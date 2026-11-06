//! Read-only, necessary kernel evidence for the configured TUN auto_route path.
//! This is not a packet-delivery test or a reconstruction of Android netd policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

#[path = "diagnostics_tun_routes.rs"]
mod routes;

const SNAPSHOT_LIMIT: usize = 256 * 1024;

pub(crate) fn auto_route_check(inbound: &Value) -> (Option<bool>, String) {
    let deadline = Instant::now() + crate::SHORT_TIMEOUT;
    auto_route_check_with(inbound, cfg!(target_os = "android"), |args| {
        let mut command = Command::new("ip");
        command.args(args);
        read_snapshot(
            command,
            deadline.saturating_duration_since(Instant::now()),
            SNAPSHOT_LIMIT,
        )
    })
}

fn read_snapshot(
    command: Command,
    timeout: Duration,
    limit: usize,
) -> Result<String, &'static str> {
    if timeout.is_zero() {
        return Err("deadline");
    }
    let output = crate::utils::run_bounded_command(command, timeout, limit)
        .map_err(|_| "command-unavailable")?;
    if output.timed_out {
        return Err("deadline");
    }
    if output.truncated {
        return Err("output-truncated");
    }
    if !output.status.is_some_and(|status| status.success()) {
        return Err("command-failed");
    }
    if !output.stderr.is_empty() {
        return Err("command-warning");
    }
    String::from_utf8(output.stdout).map_err(|_| "output-invalid")
}

pub(crate) fn auto_route_check_with(
    inbound: &Value,
    android: bool,
    mut snapshot: impl FnMut(&[&str]) -> Result<String, &'static str>,
) -> (Option<bool>, String) {
    let expected = match RouteExpectation::from_inbound(inbound, android) {
        Ok(Some(expected)) => expected,
        Ok(None) => {
            return (
                Some(true),
                "auto_route=disabled rpdb=not_required fib=not_required".into(),
            )
        }
        Err(reason) => {
            return (
                None,
                format!("auto_route=unknown rpdb=unknown fib=unknown reason={reason}"),
            )
        }
    };
    let mut ready = Some(true);
    let table = expected.table.to_string();
    let mut detail = format!("auto_route=enabled table={table} scope=kernel-routes");
    for (family, prefixes) in &expected.families {
        // Numeric table IDs avoid aliases in rt_tables. A missing/unsupported ip
        // command is unknown, never an empty rule set that can prove health.
        let rules = observe(snapshot(&[family.arg(), "-N", "rule", "show"]), |text| {
            expected.rules_present(text, *family, prefixes)
        });
        let routes = match routes::expected_ranges(inbound, *family) {
            Ok(required) if required.is_empty() => (Some(true), "not_required".into()),
            Ok(required) => observe(
                snapshot(&[family.arg(), "route", "show", "table", &table]),
                |text| routes::routes_cover(text, *family, &required),
            ),
            Err(reason) => (None, format!("unknown:{reason}")),
        };
        for observed in [rules.0, routes.0] {
            ready = if ready == Some(false) || observed == Some(false) {
                Some(false)
            } else {
                ready.zip(observed).map(|(left, right)| left && right)
            };
        }
        detail.push_str(&format!(
            " {}_rpdb={} {}_fib={}",
            family.label(),
            rules.1,
            family.label(),
            routes.1
        ));
    }
    (ready, detail)
}

fn observe(
    snapshot: Result<String, &'static str>,
    check: impl FnOnce(&str) -> Result<bool, &'static str>,
) -> (Option<bool>, String) {
    match snapshot.and_then(|text| check(&text)) {
        Ok(true) => (Some(true), "present".into()),
        Ok(false) => (Some(false), "missing".into()),
        Err(reason) => (None, format!("unknown:{reason}")),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn arg(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }

    fn of(address: IpAddr) -> Self {
        if address.is_ipv4() {
            Self::V4
        } else {
            Self::V6
        }
    }
}

struct RouteExpectation {
    table: u32,
    rule_start: u32,
    families: Vec<(Family, Vec<String>)>,
    redirect: Option<RedirectMarks>,
}

struct RedirectMarks {
    input: u32,
    output: u32,
    mask: u32,
    fallback: u32,
}

impl RouteExpectation {
    fn from_inbound(inbound: &Value, android: bool) -> Result<Option<Self>, &'static str> {
        if !config_bool(inbound, "auto_route")? {
            return Ok(None);
        }
        if inbound
            .get("netns")
            .is_some_and(|value| value.as_str() != Some(""))
        {
            return Err("network-namespace-unobserved");
        }
        let addresses = match inbound.get("address") {
            Some(Value::String(value)) => vec![value.as_str()],
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| value.as_str().ok_or("address-invalid"))
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("address-family-unavailable"),
        };
        let mut families: Vec<(Family, Vec<String>)> = Vec::new();
        for address in addresses {
            if !address.contains('/') {
                return Err("address-invalid");
            }
            let (network, bits) = prefix(address).ok_or("address-invalid")?;
            let family = Family::of(network);
            let normalized = format!("{network}/{bits}");
            if let Some((_, prefixes)) = families.iter_mut().find(|entry| entry.0 == family) {
                prefixes.push(normalized);
            } else {
                families.push((family, vec![normalized]));
            }
        }
        if families.is_empty() {
            return Err("address-family-unavailable");
        }
        for (_, prefixes) in &mut families {
            prefixes.sort_unstable();
            prefixes.dedup();
        }
        // Defaults and rule shapes match the bundled sing-tun dependency's
        // NativeTun.rules(), not the ownership ledger or an assumed UID 2000.
        let table = config_index(inbound, "iproute2_table_index", 2022)?;
        let rule_start = config_index(inbound, "iproute2_rule_index", 9000)?;
        rule_start.checked_add(10).ok_or("rule-index-invalid")?;
        let redirect = if config_bool(inbound, "auto_redirect")? {
            let input = effective_mark(
                inbound,
                "auto_redirect_input_mark",
                0x2023,
                0x400000,
                android,
            )?;
            let output = effective_mark(
                inbound,
                "auto_redirect_output_mark",
                0x2024,
                0x200000,
                android,
            )?;
            let reset = effective_mark(
                inbound,
                "auto_redirect_reset_mark",
                0x2025,
                0x600000,
                android,
            )?;
            let tproxy = effective_mark(
                inbound,
                "auto_redirect_tproxy_mark",
                0x2026,
                0x800000,
                android,
            )?;
            Some(RedirectMarks {
                input,
                output,
                mask: input | output | reset | tproxy,
                fallback: config_index(
                    inbound,
                    "auto_redirect_iproute2_fallback_rule_index",
                    32768,
                )?,
            })
        } else {
            None
        };
        Ok(Some(Self {
            table,
            rule_start,
            families,
            redirect,
        }))
    }

    fn rules_present(
        &self,
        text: &str,
        family: Family,
        prefixes: &[String],
    ) -> Result<bool, &'static str> {
        let rules = parse_rules(text)?;
        let table = self.table;
        let start = self.rule_start;
        if let Some(marks) = &self.redirect {
            let end = start + 2;
            // The fallback and hotspot iif lookups cannot replace the input-mark
            // rule. Require the small core-generated mark group in full.
            return Ok(has_rule(
                &rules,
                start,
                &format!(
                    "from all fwmark {:#x}/{:#x} goto {end}",
                    marks.output, marks.mask
                ),
            ) && has_rule(
                &rules,
                start + 1,
                &format!(
                    "from all fwmark {:#x}/{:#x} lookup {table}",
                    marks.input, marks.mask
                ),
            ) && has_rule(&rules, end, "from all nop")
                && has_rule(
                    &rules,
                    marks.fallback,
                    &format!(
                        "not from all fwmark {:#x}/{:#x} lookup {table}",
                        marks.output, marks.mask
                    ),
                ));
        }
        let end = start + 10;
        if !has_rule(&rules, end, "from all nop") {
            return Ok(false);
        }
        // UID and interface exclusions change the group's starting position.
        // Match the core's local-application rules within its configured window,
        // without assuming any particular UID is supposed to enter the TUN.
        Ok((start + 1..end).any(|priority| {
            has_rule(
                &rules,
                priority - 1,
                &format!("from all iif magicnet0 goto {end}"),
            ) && prefixes.iter().all(|source| {
                has_rule(
                    &rules,
                    priority,
                    &format!("from {source} iif lo lookup {table}"),
                )
            }) && match family {
                Family::V4 => {
                    has_rule(
                        &rules,
                        priority,
                        &format!("from 0.0.0.0/32 iif lo lookup {table}"),
                    ) && has_rule(
                        &rules,
                        priority,
                        &format!("not from all iif lo lookup {table}"),
                    )
                }
                Family::V6 => {
                    priority < end - 2
                        && has_rule(
                            &rules,
                            priority + 1,
                            &format!("from ::/1 iif lo goto {end}"),
                        )
                        && has_rule(
                            &rules,
                            priority + 1,
                            &format!("from 8000::/1 iif lo goto {end}"),
                        )
                        && has_rule(&rules, priority + 2, &format!("from all lookup {table}"))
                }
            }
        }))
    }
}

fn config_bool(inbound: &Value, key: &str) -> Result<bool, &'static str> {
    match inbound.get(key) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err("auto-route-config-invalid"),
    }
}

fn config_index(inbound: &Value, key: &str, default: u32) -> Result<u32, &'static str> {
    match inbound.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(|value| if value == 0 { default } else { value })
            .ok_or("route-index-invalid"),
    }
}

fn effective_mark(
    inbound: &Value,
    key: &str,
    linux_default: u32,
    android_default: u32,
    android: bool,
) -> Result<u32, &'static str> {
    let value = match inbound.get(key) {
        None => 0,
        Some(Value::String(value)) => number(value).ok_or("mark-config-unrecognized")?,
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or("mark-config-invalid")?,
    };
    // sing-tun effectiveMark(): Android reserves netd and vendor/connmark bits.
    if android {
        Ok(if value != 0 && value & 0xE31FFFFF == 0 {
            value
        } else {
            android_default
        })
    } else {
        Ok(if value == 0 { linux_default } else { value })
    }
}

fn number(value: &str) -> Option<u32> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else if let Some(octal) = value.strip_prefix('0') {
        if octal.is_empty() {
            Some(0)
        } else {
            u32::from_str_radix(octal, 8).ok()
        }
    } else {
        value.parse().ok()
    }
}

fn mark(value: &str) -> Option<(u32, u32)> {
    match value.split_once('/') {
        Some((value, mask)) => Some((number(value)?, number(mask)?)),
        None => Some((number(value)?, u32::MAX)),
    }
}

fn prefix(value: &str) -> Option<(IpAddr, u8)> {
    let (address, bits) = match value.split_once('/') {
        Some((address, bits)) => (address.parse::<IpAddr>().ok()?, bits.parse::<u8>().ok()?),
        None => {
            let address = value.parse::<IpAddr>().ok()?;
            (address, if address.is_ipv4() { 32 } else { 128 })
        }
    };
    match address {
        IpAddr::V4(address) if bits <= 32 => Some((
            IpAddr::V4(Ipv4Addr::from(
                u32::from(address) & u32::MAX.checked_shl(u32::from(32 - bits)).unwrap_or(0),
            )),
            bits,
        )),
        IpAddr::V6(address) if bits <= 128 => Some((
            IpAddr::V6(Ipv6Addr::from(
                u128::from(address) & u128::MAX.checked_shl(u32::from(128 - bits)).unwrap_or(0),
            )),
            bits,
        )),
        _ => None,
    }
}

struct Rule<'a> {
    priority: u32,
    fields: Vec<&'a str>,
}

fn parse_rules(text: &str) -> Result<Vec<Rule<'_>>, &'static str> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (priority, fields) = line.split_once(':').ok_or("rule-output-invalid")?;
            let priority = priority.trim().parse().map_err(|_| "rule-output-invalid")?;
            let mut fields: Vec<_> = fields.split_whitespace().collect();
            // Rule protocol is provenance metadata, not a packet selector.
            if fields.len() >= 2 && matches!(fields[fields.len() - 2], "protocol" | "proto") {
                fields.truncate(fields.len() - 2);
            }
            if !(fields.starts_with(&["from"]) || fields.starts_with(&["not", "from"]))
                || fields.len() < 3
            {
                return Err("rule-output-invalid");
            }
            Ok(Rule { priority, fields })
        })
        .collect()
}

fn has_rule(rules: &[Rule<'_>], priority: u32, body: &str) -> bool {
    let expected: Vec<_> = body.split_whitespace().collect();
    rules.iter().any(|rule| {
        rule.priority == priority
            && rule.fields.len() == expected.len()
            && rule.fields.iter().zip(&expected).enumerate().all(
                |(index, (actual, expected_field))| {
                    if actual == expected_field {
                        return true;
                    }
                    match index.checked_sub(1).map(|previous| expected[previous]) {
                        Some("from") => prefix(actual)
                            .zip(prefix(expected_field))
                            .is_some_and(|(actual, expected)| actual == expected),
                        Some("fwmark") => mark(actual)
                            .zip(mark(expected_field))
                            .is_some_and(|(actual, expected)| actual == expected),
                        _ => false,
                    }
                },
            )
    })
}

#[cfg(test)]
#[path = "../tests/internal/diagnostics_tun.rs"]
mod tests;
