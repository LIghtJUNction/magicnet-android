//! Probe the selected proxy itself; domain routing may use another test group.
use super::{
    cancelled, live, log_event, mixed_proxy, probe, requests, tun, Clock, Observation, State,
    SECONDARY_TARGET, TARGET,
};
use crate::webui_api::{change_selector_locked, rollback_selector_locked, SelectorChange};
use crate::App;
use serde_json::Value;
use std::time::{Duration, Instant};

const MAX_CANDIDATES: usize = 3;
const MAX_SELECTORS: usize = 16;
const PROBE_TIMEOUT_MS: u64 = 4000;

pub(super) fn strict_probe(app: &App, outbound: &str, url: &str) -> Observation {
    let path = format!(
        "/proxies/{}/delay?url={}&timeout={PROBE_TIMEOUT_MS}&expected_status=204",
        crate::node_delay::encode_path_segment(outbound),
        crate::node_delay::encode_path_segment(url),
    );
    match crate::webui_api::api_response(app, "GET", &path, "", 6, 4096) {
        Ok(bytes) => parse_strict_probe(&bytes),
        Err(_) => Observation::failed("probe_unavailable"),
    }
}

fn parse_strict_probe(bytes: &[u8]) -> Observation {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Observation::failed("probe_invalid");
    };
    // Old cores ignore unknown query parameters and return a delay even for
    // an HTTP error. A capability marker is required on failures as well.
    if value["strict_probe"] != true || value["expected_status"] != 204 {
        return Observation::failed("probe_unsupported");
    }
    match value["ok"].as_bool() {
        Some(true) => {
            let Some(delay) = value["delay"]
                .as_u64()
                .filter(|delay| *delay <= PROBE_TIMEOUT_MS)
            else {
                return Observation::failed("probe_invalid");
            };
            if value["http_status"] != 204 {
                return Observation::failed("probe_invalid");
            }
            Observation {
                ok: true,
                reason: "ok",
                http: Some(204),
                millis: Some(delay),
            }
        }
        Some(false) => {
            let reason = match value["reason"].as_str() {
                Some("timeout") => "timeout",
                Some("dns_failure") => "dns_failure",
                Some("tls_failure") => "tls_failure",
                Some("http_status") => "http_error",
                Some("transport_failure") => "transport_failure",
                Some("cancelled") => "probe_unavailable",
                _ => return Observation::failed("probe_invalid"),
            };
            let http = value["http_status"]
                .as_u64()
                .filter(|status| (100..=599).contains(status))
                .map(|status| status as u16);
            if (!value["http_status"].is_null() && http.is_none())
                || (reason == "http_error" && (http.is_none() || http == Some(204)))
            {
                return Observation::failed("probe_invalid");
            }
            Observation {
                ok: false,
                reason,
                http,
                millis: None,
            }
        }
        None => Observation::failed("probe_invalid"),
    }
}

pub(super) fn automatic_mode(app: &App) -> bool {
    crate::webui_api::curl_get_json(app, "/configs")
        .ok()
        .and_then(|value| value["mode"].as_str().map(str::to_ascii_lowercase))
        .is_some_and(|mode| matches!(mode.as_str(), "rule" | "global"))
}

#[derive(Clone)]
struct Snapshot {
    config: Value,
    proxies: Value,
}

fn snapshot(app: &App) -> Result<Snapshot, String> {
    let config = crate::utils::read_json_file_bounded(
        &app.moddir.join(".config/sing-box/config.json"),
        4 * 1024 * 1024,
    )
    .ok_or("connectivity.config_unavailable")?;
    let proxies = crate::webui_api::curl_get_json(app, "/proxies")
        .map_err(|_| "connectivity.selectors_unavailable")?;
    Ok(Snapshot { config, proxies })
}

/// In-memory identity only; never publish node tags or configuration values.
pub(super) fn identity(app: &App) -> Option<Value> {
    identity_of(&snapshot(app).ok()?)
}

fn identity_of(snapshot: &Snapshot) -> Option<Value> {
    selector(snapshot, "proxy")?;
    let mut tag = "proxy".to_string();
    let mut path = Vec::<String>::new();
    for _ in 0..16 {
        if path.contains(&tag) {
            return None;
        }
        path.push(tag.clone());
        let node = snapshot.proxies["proxies"].get(&tag)?;
        match node["now"].as_str() {
            Some(next) if !next.is_empty() => tag = next.to_string(),
            _ => return Some(serde_json::json!({"config":&snapshot.config, "path":path})),
        }
    }
    None
}

fn config_outbound<'a>(config: &'a Value, tag: &str) -> Option<&'a Value> {
    let mut matches = config["outbounds"]
        .as_array()?
        .iter()
        .filter(|node| node["tag"] == tag);
    let node = matches.next()?;
    matches.next().is_none().then_some(node)
}

fn concrete_proxy(node: &Value) -> bool {
    // An explicit allow-list avoids adopting endpoints, future control types,
    // or a generated chain member as a transparent replacement.
    matches!(
        node["type"].as_str(),
        Some(
            "shadowsocks"
                | "shadowsocksr"
                | "vmess"
                | "vless"
                | "trojan"
                | "hysteria"
                | "hysteria2"
                | "tuic"
                | "anytls"
                | "naive"
                | "socks"
                | "http"
                | "ssh"
        )
    ) && node["detour"].as_str().is_none_or(str::is_empty)
        && node["tag"]
            .as_str()
            .is_some_and(|tag| !tag.is_empty() && !tag.starts_with("magicnet-chain-"))
}

fn contains_member(value: &Value, key: &str, member: &str) -> bool {
    value[key]
        .as_array()
        .is_some_and(|members| members.iter().any(|item| item == member))
}

fn eligible_leaf(snapshot: &Snapshot, tag: &str) -> bool {
    config_outbound(&snapshot.config, tag).is_some_and(concrete_proxy)
        && snapshot.proxies["proxies"][tag]["type"]
            .as_str()
            .is_some_and(|kind| {
                matches!(
                    kind.to_ascii_lowercase().as_str(),
                    "shadowsocks"
                        | "shadowsocksr"
                        | "vmess"
                        | "vless"
                        | "trojan"
                        | "hysteria"
                        | "hysteria2"
                        | "tuic"
                        | "anytls"
                        | "naive"
                        | "socks"
                        | "socks5"
                        | "http"
                        | "ssh"
                )
            })
}

fn selector<'a>(snapshot: &'a Snapshot, group: &str) -> Option<(&'a Value, &'a Value)> {
    let configured = config_outbound(&snapshot.config, group)?;
    let observed = snapshot.proxies["proxies"].as_object()?.get(group)?;
    (configured["type"] == "selector"
        && observed["type"]
            .as_str()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("selector"))
        && configured["outbounds"].is_array()
        && observed["all"].is_array())
    .then_some((configured, observed))
}

fn candidates(snapshot: &Snapshot) -> Option<(String, Vec<String>)> {
    let (configured, observed) = selector(snapshot, "proxy")?;
    let current = observed["now"].as_str()?;
    if !eligible_leaf(snapshot, current)
        || !contains_member(configured, "outbounds", current)
        || !contains_member(observed, "all", current)
    {
        return None;
    }
    let mut candidates = Vec::new();
    for member in configured["outbounds"].as_array()? {
        let Some(tag) = member.as_str() else { continue };
        if tag != current
            && contains_member(observed, "all", tag)
            && eligible_leaf(snapshot, tag)
            && !candidates.iter().any(|item| item == tag)
        {
            candidates.push(tag.to_string());
            if candidates.len() == MAX_CANDIDATES {
                break;
            }
        }
    }
    (!candidates.is_empty()).then(|| (current.to_string(), candidates))
}

fn affected_selectors(snapshot: &Snapshot, previous: &str, selected: &str) -> Option<Vec<String>> {
    let mut groups = Vec::new();
    for configured in snapshot.config["outbounds"].as_array()? {
        let Some(tag) = configured["tag"].as_str() else {
            continue;
        };
        if tag == "hotspot"
            || tag == "chain"
            || tag.starts_with("chain-")
            || tag.starts_with("magicnet-chain-")
        {
            continue;
        }
        let Some((configured, observed)) = selector(snapshot, tag) else {
            continue;
        };
        if observed["now"] == previous
            && contains_member(configured, "outbounds", previous)
            && contains_member(observed, "all", previous)
            && contains_member(configured, "outbounds", selected)
            && contains_member(observed, "all", selected)
        {
            if groups.iter().any(|group| group == tag) {
                return None;
            }
            groups.push(tag.to_string());
            if groups.len() > MAX_SELECTORS {
                return None;
            }
        }
    }
    if !groups.iter().any(|tag| tag == "proxy") {
        return None;
    }
    groups.sort_by_key(|tag| (tag != "proxy", tag.clone()));
    Some(groups)
}

fn rollback(
    app: &App,
    guard: &crate::service::ConfigApplyGuard,
    changes: &[SelectorChange],
) -> Result<(), String> {
    let mut failed = false;
    for change in changes.iter().rev() {
        failed |= rollback_selector_locked(app, guard, change).is_err();
    }
    if failed {
        Err("connectivity.failover_rollback_failed".into())
    } else {
        Ok(())
    }
}

/// Returns true if a bounded failover attempt consumed this action window.
/// Candidate probes run before the lifecycle lock. Every observed premise is
/// checked again after acquiring it; user/dashboard changes win over recovery.
pub(super) fn attempt(
    app: &App,
    state: &mut State,
    clock: &Clock,
    expected_identity: Option<&Value>,
) -> Result<bool, String> {
    if !same_request(app, state, clock) {
        state.phase = "pending";
        state.reason = "selection_changed";
        state.next_uptime = clock.uptime.saturating_add(requests::MIN_INTERVAL);
        state.publish(app)?;
        return Ok(true);
    }
    let original = match snapshot(app) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    if expected_identity.is_none() || identity_of(&original).as_ref() != expected_identity {
        state.phase = "pending";
        state.reason = "selection_changed";
        state.next_uptime = clock.uptime.saturating_add(requests::MIN_INTERVAL);
        state.publish(app)?;
        return Ok(true);
    }
    let Some((previous, candidates)) = candidates(&original) else {
        return Ok(false);
    };
    if !automatic_mode(app) {
        return Ok(true);
    }
    state.reserve_action(clock, "failover");
    state.publish(app)?;
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut selected = None;
    for candidate in candidates {
        if cancelled() || Instant::now() >= deadline || !same_request(app, state, clock) {
            break;
        }
        let primary = strict_probe(app, &candidate, TARGET);
        if cancelled() || Instant::now() >= deadline {
            break;
        }
        let secondary = strict_probe(app, &candidate, SECONDARY_TARGET);
        if primary.ok && secondary.ok {
            selected = Some(candidate);
            break;
        }
    }
    let Some(selected) = selected else {
        state.action_status = if same_request(app, state, clock) {
            "failed"
        } else {
            "conflict"
        };
        state.publish(app)?;
        log_event(app, state);
        return Ok(true);
    };
    let Some(guard) = crate::service::try_config_apply_lock(app)? else {
        state.action_status = "busy";
        state.publish(app)?;
        return Ok(true);
    };
    let now = Clock::now()?;
    let routes = tun::observe(app, &now);
    let current = match snapshot(app) {
        Ok(current) => current,
        Err(_) => {
            state.action_status = "conflict";
            state.publish(app)?;
            return Ok(true);
        }
    };
    if cancelled()
        || live(app) != Ok(true)
        || !automatic_mode(app)
        || !same_request(app, state, &now)
        || !matches!(routes.status, "present" | "not_required")
        || current.config != original.config
        || selector(&current, "proxy").and_then(|(_, group)| group["now"].as_str())
            != Some(previous.as_str())
    {
        state.action_status = "conflict";
        state.publish(app)?;
        return Ok(true);
    }
    let Some(groups) = affected_selectors(&current, &previous, &selected) else {
        state.action_status = "conflict";
        state.publish(app)?;
        return Ok(true);
    };
    let mut changes = Vec::new();
    let mut apply_failed = false;
    let mut inner_rollback_failed = false;
    for group in groups {
        if cancelled() || !same_request(app, state, &now) {
            apply_failed = true;
            break;
        }
        match change_selector_locked(app, &guard, &group, &selected, Some(&previous)) {
            Ok(change) => changes.push(change),
            Err(error) => {
                inner_rollback_failed = error.starts_with("selector.rollback_failed;");
                apply_failed = true;
                break;
            }
        }
    }
    let primary = if apply_failed || cancelled() {
        Observation::failed("selection_changed")
    } else {
        strict_probe(app, "proxy", TARGET)
    };
    let secondary = if primary.ok && !cancelled() {
        strict_probe(app, "proxy", SECONDARY_TARGET)
    } else {
        Observation::failed("selection_changed")
    };
    let mixed = if primary.ok && secondary.ok && !cancelled() {
        mixed_proxy(app).map_or_else(
            || Observation::failed("proxy_unavailable"),
            |proxy| probe(app, TARGET, Some(&proxy), true),
        )
    } else {
        Observation::failed("selection_changed")
    };
    // Validate that the successful requests still belong to our committed
    // selector choices. Foreign writes are never rolled back over newer intent.
    let still_selected = snapshot(app).ok().is_some_and(|snapshot| {
        snapshot.config == current.config
            && changes.iter().all(|change| {
                selector(&snapshot, &change.group)
                    .is_some_and(|(_, group)| group["now"] == selected)
            })
    });
    if !apply_failed
        && !cancelled()
        && live(app) == Ok(true)
        && same_request(app, state, &now)
        && primary.ok
        && secondary.ok
        && mixed.ok
        && still_selected
    {
        let now = Clock::now()?;
        state.record(&now, &primary, Some(&secondary), None);
        state.record_mixed(Some(&mixed));
        state.action_status = "ok";
    } else {
        let restored = rollback(app, &guard, &changes);
        state.action_status = if restored.is_ok() && !inner_rollback_failed {
            "failed"
        } else {
            "rollback_failed"
        };
        state.publish(app)?;
        log_event(app, state);
        restored?;
        if inner_rollback_failed {
            return Err("connectivity.failover_rollback_failed".into());
        }
    }
    state.publish(app)?;
    log_event(app, state);
    let _ = crate::state::reconcile(app);
    Ok(true)
}

pub(super) fn same_request(app: &App, state: &State, clock: &Clock) -> bool {
    requests::generation(app, clock).is_ok_and(|generation| generation == state.request_generation)
}

pub(super) fn same_identity(app: &App, expected: Option<&Value>) -> bool {
    expected.is_some() && identity(app).as_ref() == expected
}

#[cfg(test)]
#[path = "../tests/internal/connectivity_selected.rs"]
mod tests;
