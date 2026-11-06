use std::net::IpAddr;

use serde_json::Value;

use super::{config_bool, prefix, Family};

const MAX_CONFIG_PREFIXES: usize = 1024;

#[derive(Clone, Copy)]
pub(super) struct AddressRange {
    first: u128,
    last: u128,
}

impl AddressRange {
    fn whole(family: Family) -> Self {
        Self {
            first: 0,
            last: if family == Family::V4 {
                u128::from(u32::MAX)
            } else {
                u128::MAX
            },
        }
    }

    fn parse(value: &str, family: Family) -> Option<Self> {
        let (address, bits) = prefix(value)?;
        if Family::of(address) != family {
            return None;
        }
        let first = match address {
            IpAddr::V4(value) => u128::from(u32::from(value)),
            IpAddr::V6(value) => u128::from(value),
        };
        Some(Self {
            first,
            last: first
                | Self::whole(family)
                    .last
                    .checked_shr(u32::from(bits))
                    .unwrap_or(0),
        })
    }
}

pub(super) fn expected_ranges(
    inbound: &Value,
    family: Family,
) -> Result<Vec<AddressRange>, &'static str> {
    // NativeTun.routes() calls BuildAutoRouteRanges(false): on Android/Linux,
    // each configured family defaults to /0, minus its static exclusions.
    // sing-box only appends rule-set ranges to tunOptions when autoRedirect is
    // absent; native auto_redirect keeps those sets in its netfilter plane.
    if !config_bool(inbound, "auto_redirect")? {
        for key in ["route_address_set", "route_exclude_address_set"] {
            if inbound
                .get(key)
                .is_some_and(|value| !value.as_array().is_some_and(Vec::is_empty))
            {
                return Err("dynamic-route-ranges-unobserved");
            }
        }
    }
    let mut included = config_ranges(inbound, "route_address", family)?;
    if included.is_empty() {
        included.push(AddressRange::whole(family));
    }
    let excluded = config_ranges(inbound, "route_exclude_address", family)?;
    let mut required = merge_ranges(included);
    // Both config inputs are bounded. Subtracting disjoint intervals avoids
    // expanding IPv6 ranges into addresses or probing any destination.
    for excluded in merge_ranges(excluded) {
        let mut remaining = Vec::new();
        for range in required {
            if excluded.last < range.first || excluded.first > range.last {
                remaining.push(range);
                continue;
            }
            if range.first < excluded.first {
                remaining.push(AddressRange {
                    first: range.first,
                    last: excluded.first - 1,
                });
            }
            if range.last > excluded.last {
                remaining.push(AddressRange {
                    first: excluded.last + 1,
                    last: range.last,
                });
            }
        }
        required = remaining;
    }
    Ok(required)
}

fn config_ranges(
    inbound: &Value,
    key: &str,
    family: Family,
) -> Result<Vec<AddressRange>, &'static str> {
    let values: Vec<&str> = match inbound.get(key) {
        None => return Ok(Vec::new()),
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) if values.len() <= MAX_CONFIG_PREFIXES => values
            .iter()
            .map(|value| value.as_str().ok_or("route-address-invalid"))
            .collect::<Result<_, _>>()?,
        Some(Value::Array(_)) => return Err("route-address-limit"),
        _ => return Err("route-address-invalid"),
    };
    let mut ranges = Vec::new();
    for value in values {
        if !value.contains('/') || prefix(value).is_none() {
            return Err("route-address-invalid");
        }
        if let Some(range) = AddressRange::parse(value, family) {
            ranges.push(range);
        }
    }
    Ok(ranges)
}

fn merge_ranges(mut ranges: Vec<AddressRange>) -> Vec<AddressRange> {
    ranges.sort_unstable_by_key(|range| (range.first, range.last));
    let mut merged: Vec<AddressRange> = Vec::new();
    for range in ranges {
        if let Some(last) = merged
            .last_mut()
            .filter(|last| range.first <= last.last.saturating_add(1))
        {
            last.last = last.last.max(range.last);
            continue;
        }
        merged.push(range);
    }
    merged
}

pub(super) fn routes_cover(
    text: &str,
    family: Family,
    required: &[AddressRange],
) -> Result<bool, &'static str> {
    let mut observed = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let (destination, unicast) = match fields[0] {
            "unicast" => (1, true),
            "local" | "broadcast" | "multicast" | "throw" | "unreachable" | "prohibit"
            | "blackhole" => (1, false),
            _ => (0, true),
        };
        let address = fields.get(destination).ok_or("route-output-invalid")?;
        let range = if *address == "default" {
            AddressRange::whole(family)
        } else {
            AddressRange::parse(address, family).ok_or("route-output-invalid")?
        };
        if unicast
            && !fields.contains(&"linkdown")
            && fields.windows(2).any(|pair| pair == ["dev", "magicnet0"])
        {
            if fields.contains(&"from") || fields.contains(&"nexthop") {
                return Err("route-selectors-unobserved");
            }
            observed.push(range);
        }
    }
    let observed = merge_ranges(observed);
    let mut index = 0;
    for required in required {
        while index < observed.len() && observed[index].last < required.first {
            index += 1;
        }
        if !observed
            .get(index)
            .is_some_and(|route| route.first <= required.first && route.last >= required.last)
        {
            return Ok(false);
        }
    }
    Ok(true)
}
