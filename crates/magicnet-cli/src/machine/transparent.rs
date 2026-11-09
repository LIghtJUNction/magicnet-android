use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use crate::{
    ebpf_runtime::{inspect_ebpf_attachments, read_ebpf_active_report, EbpfAttachmentEvidence},
    App,
};

const CONFIG: &str = ".config/sing-box/config.json";
const CAPABILITY: &str = ".state/transparent-ebpf/capability";
const SHARED_PENDING: &str = ".state/transparent-ebpf/shared.pending";
const RECENT_ERROR: &str = ".state/transparent-recent-error";

pub(super) struct Status {
    pub(super) configured_mode: String,
    pub(super) effective_type: String,
    pub(super) effective_mode: String,
    pub(super) capability: String,
    pub(super) local_cgroup: &'static str,
    pub(super) shared_tc: &'static str,
    pub(super) shared_interface_count: usize,
    pub(super) transition: String,
    pub(super) has_recent_error: bool,
    pub(super) dataplane_ready: Option<bool>,
    pub(super) local_ready: Option<bool>,
    pub(super) shared_ready: Option<bool>,
}

impl Status {
    pub(super) fn as_value(&self) -> Value {
        json!({
            // Keep `mode` as the compatibility alias introduced by schema 1.
            "mode": self.configured_mode,
            "configured_mode": self.configured_mode,
            "effective_type": self.effective_type,
            "effective_mode": self.effective_mode,
            "capability": self.capability,
            "local_cgroup": self.local_cgroup,
            "shared_tc": self.shared_tc,
            "shared_interface_count": self.shared_interface_count,
            "transition": self.transition,
            "has_recent_error": self.has_recent_error,
            "dataplane_ready": self.dataplane_ready,
            "local_ready": self.local_ready,
            "shared_ready": self.shared_ready,
        })
    }
}

pub(super) fn snapshot(app: &App, process_state: &str, configured_mode: &str) -> Status {
    snapshot_with_probe(app, process_state, configured_mode, tun_dataplane_ready)
}

fn snapshot_with_probe(
    app: &App,
    process_state: &str,
    configured_mode: &str,
    tun_probe: impl FnOnce(Option<&Value>) -> Option<bool>,
) -> Status {
    let config = crate::utils::read_json_file_bounded(&app.moddir.join(CONFIG), 4 * 1024 * 1024);
    let inbound = crate::service::transparent_inbound(config.as_ref());
    let (effective_type, effective_mode) = crate::service::transparent_effective_modes(inbound);
    let effective_type = effective_type.to_string();
    let effective_mode = effective_mode.to_string();
    let transition = crate::state::transparent_phase(app);
    let has_recent_error = regular_file_nonempty(&app.moddir.join(RECENT_ERROR));

    if effective_type != "ebpf" || effective_mode == "unknown" {
        let ready = match process_state {
            "running" if effective_type == "tun" => tun_probe(inbound),
            "stopped" => Some(false),
            _ => None,
        };
        let capability = if effective_type == "tun" {
            "not_required"
        } else {
            "unknown"
        }
        .to_string();
        let attachment = if effective_type == "tun" {
            "inactive"
        } else {
            "unknown"
        };
        return Status {
            configured_mode: configured_mode.to_string(),
            effective_type,
            effective_mode,
            capability,
            local_cgroup: attachment,
            shared_tc: attachment,
            shared_interface_count: 0,
            transition,
            has_recent_error,
            dataplane_ready: ready,
            local_ready: None,
            shared_ready: None,
        };
    }

    let shared_interfaces = shared_interfaces(inbound);
    let local_expected = matches!(effective_mode.as_str(), "local" | "hybrid");
    let shared_expected = matches!(effective_mode.as_str(), "shared" | "hybrid");
    let capability = read_regular_text(&app.moddir.join(CAPABILITY), 64)
        .map(|value| value.trim().to_string())
        .filter(|value| matches!(value.as_str(), "ok" | "failed"))
        .unwrap_or_else(|| "unknown".to_string());
    let attachments = if process_state == "running" {
        read_ebpf_active_report(app).ok().map(|report| {
            let cgroup_path = inbound
                .and_then(|value| value.get("local"))
                .and_then(|value| value.get("cgroup_path"))
                .and_then(Value::as_str)
                .filter(|path| Path::new(path).is_absolute())
                .unwrap_or("/sys/fs/cgroup");
            inspect_ebpf_attachments(
                app,
                &report,
                local_expected,
                cgroup_path,
                &network_values(inbound),
                &shared_interfaces,
            )
        })
    } else {
        None
    };
    let local_cgroup = if !local_expected {
        "inactive"
    } else if process_state == "stopped" {
        "configured"
    } else if process_state != "running" {
        "unknown"
    } else if attachments
        .as_ref()
        .is_some_and(|evidence| evidence.local_attached)
    {
        "attached"
    } else if attachments.is_some() {
        "missing"
    } else {
        "unknown"
    };
    let shared_tc = if !shared_expected {
        if regular_file_nonempty(&app.moddir.join(SHARED_PENDING)) {
            "pending"
        } else {
            "inactive"
        }
    } else if shared_interfaces.is_empty() {
        "pending"
    } else if process_state == "stopped" {
        "configured"
    } else if process_state != "running" {
        "unknown"
    } else if attachments
        .as_ref()
        .is_some_and(|evidence| evidence.shared_attached)
    {
        "attached"
    } else if attachments.is_some() {
        "missing"
    } else {
        "unknown"
    };
    let readiness = match process_state {
        "stopped" => Some(PlaneReadiness {
            local: false,
            shared: false,
            dataplane: false,
        }),
        "running" => attachments.as_ref().map(|evidence| {
            ebpf_readiness(
                &effective_mode,
                &capability,
                shared_interfaces.len(),
                evidence,
            )
        }),
        _ => None,
    };

    Status {
        configured_mode: configured_mode.to_string(),
        effective_type,
        effective_mode,
        capability,
        local_cgroup,
        shared_tc,
        shared_interface_count: shared_interfaces.len(),
        transition,
        has_recent_error,
        dataplane_ready: readiness.as_ref().map(|ready| ready.dataplane),
        local_ready: if local_expected {
            readiness.as_ref().map(|ready| ready.local)
        } else {
            None
        },
        shared_ready: if shared_expected {
            readiness.as_ref().map(|ready| ready.shared)
        } else {
            None
        },
    }
}

struct PlaneReadiness {
    local: bool,
    shared: bool,
    dataplane: bool,
}

fn ebpf_readiness(
    mode: &str,
    capability: &str,
    shared_count: usize,
    evidence: &EbpfAttachmentEvidence,
) -> PlaneReadiness {
    let local_expected = matches!(mode, "local" | "hybrid");
    let shared_expected = matches!(mode, "shared" | "hybrid");
    let local = capability == "ok" && local_expected && evidence.local_attached;
    let shared =
        capability == "ok" && shared_expected && shared_count > 0 && evidence.shared_attached;
    PlaneReadiness {
        local,
        shared,
        dataplane: capability == "ok"
            && (!local_expected || local)
            && (!shared_expected || (mode == "hybrid" && shared_count == 0) || shared),
    }
}

fn tun_dataplane_ready(inbound: Option<&Value>) -> Option<bool> {
    tun_dataplane_ready_with_probe(
        inbound,
        || Path::new("/sys/class/net/magicnet0").try_exists().ok(),
        |inbound| crate::diagnostics::tun::auto_route_check(inbound).0,
    )
}

fn tun_dataplane_ready_with_probe(
    inbound: Option<&Value>,
    interface_probe: impl FnOnce() -> Option<bool>,
    route_probe: impl FnOnce(&Value) -> Option<bool>,
) -> Option<bool> {
    let inbound = inbound?;
    if inbound.get("type").and_then(Value::as_str) != Some("tun") {
        return None;
    }
    let interface = inbound.get("interface_name").and_then(Value::as_str)?;
    if interface != "magicnet0" {
        return Some(false);
    }
    match interface_probe() {
        Some(true) => route_probe(inbound),
        ready => ready,
    }
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn shared_interfaces(inbound: Option<&Value>) -> Vec<String> {
    inbound
        .and_then(|value| value.get("shared"))
        .and_then(|value| value.get("interface"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| valid_interface_name(value))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn network_values(inbound: Option<&Value>) -> Vec<String> {
    let values = match inbound.and_then(|value| value.get("network")) {
        Some(Value::String(value)) if matches!(value.as_str(), "tcp" | "udp") => {
            vec![value.clone()]
        }
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| matches!(*value, "tcp" | "udp"))
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    };
    if values.is_empty() {
        vec!["tcp".to_string(), "udp".to_string()]
    } else {
        values
    }
}

fn read_regular_text(path: &Path, max_bytes: u64) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn regular_file_nonempty(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.len() > 0)
}

#[cfg(test)]
mod tests {
    use super::{network_values, valid_interface_name};
    use serde_json::json;

    #[test]
    fn tun_never_reports_ebpf_plane_readiness() {
        let fixture = crate::test_support::temp_app();
        let app = crate::App::for_test(fixture.moddir.clone());
        std::fs::create_dir_all(app.moddir.join(".config/sing-box")).unwrap();
        std::fs::write(
            app.moddir.join(".config/sing-box/config.json"),
            r#"{"inbounds":[{"tag":"tun-in","type":"tun","interface_name":"lo"}]}"#,
        )
        .unwrap();
        for state in ["running", "stopped", "unknown"] {
            let status = super::snapshot_with_probe(&app, state, "tun", |inbound| {
                assert_eq!(inbound.unwrap()["interface_name"], "lo");
                Some(true)
            });
            assert_eq!(status.local_ready, None, "{state}");
            assert_eq!(status.shared_ready, None, "{state}");
            assert_eq!(
                status.dataplane_ready,
                match state {
                    "running" => Some(true),
                    "stopped" => Some(false),
                    _ => None,
                }
            );
        }
    }

    #[test]
    fn tun_readiness_requires_interface_evidence_only_for_a_running_core() {
        let fixture = crate::test_support::temp_app();
        let app = crate::App::for_test(fixture.moddir.clone());
        std::fs::create_dir_all(app.moddir.join(".config/sing-box")).unwrap();
        std::fs::write(
            app.moddir.join(".config/sing-box/config.json"),
            r#"{"inbounds":[{"tag":"tun-in","type":"tun","interface_name":"magicnet0"}]}"#,
        )
        .unwrap();
        let status = super::snapshot_with_probe(&app, "running", "tun", |_| Some(false));
        assert_eq!(status.dataplane_ready, Some(false));
        for (state, ready) in [("stopped", Some(false)), ("unknown", None)] {
            let status = super::snapshot_with_probe(&app, state, "tun", |_| {
                panic!("must not probe the interface without a running core")
            });
            assert_eq!(status.dataplane_ready, ready);
        }
    }

    #[test]
    fn unknown_effective_config_never_probes_or_claims_a_ready_dataplane() {
        let fixture = crate::test_support::temp_app();
        let app = crate::App::for_test(fixture.moddir.clone());
        for (state, ready) in [
            ("running", None),
            ("stopped", Some(false)),
            ("unknown", None),
        ] {
            let status = super::snapshot_with_probe(&app, state, "ebpf", |_| {
                panic!("configured intent cannot authorize a dataplane probe")
            });
            assert_eq!(status.effective_type, "unknown");
            assert_eq!(status.effective_mode, "unknown");
            assert_eq!(status.capability, "unknown");
            assert_eq!(status.local_cgroup, "unknown");
            assert_eq!(status.shared_tc, "unknown");
            assert_eq!(status.dataplane_ready, ready);
        }
    }

    #[test]
    fn tun_machine_readiness_uses_the_same_live_routing_evidence_as_health() {
        let app = crate::test_support::temp_app();
        std::fs::create_dir_all(app.moddir.join(".config/sing-box")).unwrap();
        std::fs::write(
            app.moddir.join(".config/sing-box/config.json"),
            json!({"inbounds": [{
                "tag": "tun-in", "type": "tun", "interface_name": "magicnet0",
                "address": ["172.19.0.1/30"], "auto_route": true, "auto_redirect": true
            }]})
            .to_string(),
        )
        .unwrap();
        let rules = "0: from all lookup 255\n9000: from all fwmark 0x200000/0xe00000 goto 9002\n9001: from all fwmark 0x400000/0xe00000 lookup 2022\n9002: from all nop\n32768: not from all fwmark 0x200000/0xe00000 lookup 2022\n";
        for (rules, routes, expected) in [
            (Ok(rules), "default dev magicnet0\n", Some(true)),
            (
                Ok("0: from all lookup 255\n"),
                "default dev magicnet0\n",
                Some(false),
            ),
            (
                Ok("8999: from all iif wlan2 lookup 2022\n"),
                "default dev magicnet0\n",
                Some(false),
            ),
            (
                Ok(rules),
                "172.19.0.0/30 dev magicnet0 proto kernel scope link src 172.19.0.1\n",
                Some(false),
            ),
            (Err("command-failed"), "default dev magicnet0\n", None),
            (Err("output-truncated"), "default dev magicnet0\n", None),
        ] {
            let status = super::snapshot_with_probe(&app, "running", "tun", |inbound| {
                super::tun_dataplane_ready_with_probe(
                    inbound,
                    || Some(true),
                    |inbound| {
                        crate::diagnostics::tun::auto_route_check_with(inbound, true, |args| {
                            if args.contains(&"rule") {
                                rules.map(|rules| {
                                    if args.contains(&"table") {
                                        rules
                                            .lines()
                                            .filter(|line| line.ends_with("lookup 2022"))
                                            .collect::<Vec<_>>()
                                            .join("\n")
                                    } else {
                                        rules.into()
                                    }
                                })
                            } else {
                                Ok(routes.into())
                            }
                        })
                        .0
                    },
                )
            });
            assert_eq!(status.dataplane_ready, expected);
            assert_eq!(status.as_value()["dataplane_ready"], json!(expected));
            assert_eq!(status.local_ready, None);
            assert_eq!(status.shared_ready, None);
        }
    }

    #[test]
    fn tun_unknown_config_or_interface_cannot_be_promoted_to_ready() {
        let inbound = json!({"type": "tun", "interface_name": "magicnet0"});
        for interface_ready in [Some(false), None] {
            assert_eq!(
                super::tun_dataplane_ready_with_probe(
                    Some(&inbound),
                    || interface_ready,
                    |_| panic!("interface not ready")
                ),
                interface_ready
            );
        }
        assert_eq!(
            super::tun_dataplane_ready_with_probe(
                None,
                || panic!("config unknown"),
                |_| panic!("config unknown")
            ),
            None
        );
        let wrong_interface = json!({"type": "tun", "interface_name": "lo"});
        assert_eq!(
            super::tun_dataplane_ready_with_probe(
                Some(&wrong_interface),
                || panic!("noncanonical interface"),
                |_| panic!("noncanonical interface")
            ),
            Some(false)
        );
    }

    #[test]
    fn hybrid_without_downstream_keeps_local_ready_and_shared_pending() {
        let evidence = crate::ebpf_runtime::EbpfAttachmentEvidence {
            local_attached: true,
            shared_attached: false,
            shared_interfaces: Vec::new(),
            detail: String::new(),
        };
        let ready = super::ebpf_readiness("hybrid", "ok", 0, &evidence);
        assert!(ready.local);
        assert!(!ready.shared);
        assert!(
            ready.dataplane,
            "an absent optional downstream must not block the local service"
        );
    }

    #[test]
    fn optional_shared_plane_does_not_hide_required_attachment_failures() {
        for (mode, count, capability, local_attached, shared_attached, expected) in [
            ("hybrid", 0, "ok", false, false, false),
            ("hybrid", 0, "failed", true, false, false),
            ("hybrid", 0, "unknown", true, false, false),
            ("hybrid", 1, "ok", true, false, false),
            ("hybrid", 1, "ok", true, true, true),
            ("shared", 0, "ok", false, false, false),
            ("shared", 1, "ok", false, true, true),
            ("local", 0, "ok", true, false, true),
        ] {
            let evidence = crate::ebpf_runtime::EbpfAttachmentEvidence {
                local_attached,
                shared_attached,
                shared_interfaces: Vec::new(),
                detail: String::new(),
            };
            let ready = super::ebpf_readiness(mode, capability, count, &evidence);
            assert_eq!(
                ready.dataplane, expected,
                "mode={mode}, count={count}, capability={capability}, evidence={evidence:?}"
            );
        }
    }

    #[test]
    fn interface_names_cannot_escape_sysfs_or_expose_paths() {
        assert!(valid_interface_name("magicnet0"));
        assert!(valid_interface_name("wlan0"));
        assert!(!valid_interface_name("../proc/self"));
        assert!(!valid_interface_name("rmnet/data0"));
    }

    #[test]
    fn network_values_are_bounded_to_supported_protocols() {
        let inbound = json!({"network": ["tcp", "icmp", "udp"]});
        assert_eq!(network_values(Some(&inbound)), vec!["tcp", "udp"]);
        assert_eq!(network_values(None), vec!["tcp", "udp"]);
    }
}
