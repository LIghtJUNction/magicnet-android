use std::fs;

use serde_json::Value;

use crate::App;

pub(super) fn dns_leak_check(app: &App, singbox: &str, mode: &str) -> (bool, String) {
    let transparent_dns = true;
    let cfg = singbox_dns_config(app, mode, transparent_dns);
    let core = if singbox != "stopped" {
        "sing-box"
    } else {
        "stopped"
    };
    (
        cfg.ok(),
        format!(
            "core={core}, mode={mode}, valid_json={}, fakeip={}, hijack_dns={}, remote_dns_detour={}, store_fakeip={}, sniff_inbound={}, strategy={}, ipv6_guard={}",
            yes_no(cfg.valid_json),
            disabled_enabled(cfg.fake_ip_disabled),
            yes_no(cfg.hijack),
            yes_no(cfg.remote_dns),
            disabled_enabled(cfg.store_fake_ip_disabled),
            yes_no(cfg.sniff_inbound),
            cfg.strategy,
            cfg.ipv6_guard.as_str(),
        ),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ipv6GuardStatus {
    Ok,
    Missing,
    NotRequired,
    Unexpected,
}

impl Ipv6GuardStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::NotRequired => "not_required",
            Self::Unexpected => "unexpected",
        }
    }

    fn ok(self) -> bool {
        !matches!(self, Self::Missing | Self::Unexpected)
    }
}

#[derive(Clone, Copy)]
struct SingboxDnsConfig {
    valid_json: bool,
    fake_ip_disabled: bool,
    hijack: bool,
    remote_dns: bool,
    store_fake_ip_disabled: bool,
    sniff_inbound: bool,
    strategy: &'static str,
    ipv6_guard: Ipv6GuardStatus,
    transparent_dns: bool,
}

impl SingboxDnsConfig {
    fn ok(self) -> bool {
        self.valid_json
            && self.fake_ip_disabled
            && self.hijack
            && self.remote_dns
            && self.store_fake_ip_disabled
            && self.sniff_inbound
            && self.ipv6_guard.ok()
            && self.transparent_dns
    }
}

fn singbox_dns_config(app: &App, mode: &str, transparent_dns: bool) -> SingboxDnsConfig {
    let text =
        fs::read_to_string(app.moddir.join(".config/sing-box/config.json")).unwrap_or_default();
    singbox_dns_config_from_text(&text, mode, transparent_dns)
}

fn singbox_dns_config_from_text(
    text: &str,
    _mode: &str,
    transparent_dns: bool,
) -> SingboxDnsConfig {
    let parsed = serde_json::from_str::<Value>(text).ok();
    let strategy = singbox_dns_strategy(parsed.as_ref());
    let ipv6_guard = ipv6_guard_status(strategy, parsed.as_ref());
    let sniff_inbound = parsed.as_ref().is_some_and(|config| {
        sniff_rule_has(config, "mixed-in") && sniff_rule_has(config, "tun-in")
    });
    SingboxDnsConfig {
        valid_json: parsed.is_some(),
        fake_ip_disabled: parsed.as_ref().is_some_and(|config| !has_fake_ip(config)),
        hijack: parsed.as_ref().is_some_and(has_dns_hijack_rule),
        remote_dns: parsed.as_ref().is_some_and(has_remote_dns_detour),
        store_fake_ip_disabled: parsed
            .as_ref()
            .is_some_and(|config| !stores_fake_ip(config)),
        sniff_inbound,
        strategy,
        ipv6_guard,
        transparent_dns,
    }
}

fn has_fake_ip(config: &Value) -> bool {
    let has_server = config
        .pointer("/dns/servers")
        .and_then(Value::as_array)
        .is_some_and(|servers| {
            servers.iter().any(|server| {
                server.get("type").and_then(Value::as_str) == Some("fakeip")
                    || server.get("tag").and_then(Value::as_str) == Some("fakeip")
            })
        });
    let has_rule = config
        .pointer("/dns/rules")
        .and_then(Value::as_array)
        .is_some_and(|rules| {
            rules
                .iter()
                .any(|rule| rule.get("server").and_then(Value::as_str) == Some("fakeip"))
        });
    has_server || has_rule
}

fn stores_fake_ip(config: &Value) -> bool {
    config
        .pointer("/experimental/cache_file/store_fakeip")
        .and_then(Value::as_bool)
        == Some(true)
}

fn has_dns_hijack_rule(config: &Value) -> bool {
    config
        .get("route")
        .and_then(|route| route.get("rules"))
        .and_then(Value::as_array)
        .is_some_and(|rules| {
            rules.iter().any(|rule| {
                rule.as_object().is_some_and(|rule| {
                    value_contains_string(rule.get("action"), "hijack-dns")
                        && (value_contains_string(rule.get("protocol"), "dns")
                            || value_contains_string(rule.get("inbound"), "magicnet-dns-in"))
                })
            })
        })
}

fn value_contains_string(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn ipv6_guard_status(strategy: &str, config: Option<&Value>) -> Ipv6GuardStatus {
    let has_guard = config.is_some_and(has_ipv6_reject_guard);
    match (strategy, has_guard) {
        ("ipv4_only", true) => Ipv6GuardStatus::Ok,
        ("ipv4_only", false) => Ipv6GuardStatus::Missing,
        (_, true) => Ipv6GuardStatus::Unexpected,
        (_, false) => Ipv6GuardStatus::NotRequired,
    }
}

fn has_ipv6_reject_guard(config: &Value) -> bool {
    config
        .get("route")
        .and_then(|route| route.get("rules"))
        .and_then(Value::as_array)
        .is_some_and(|rules| {
            rules.iter().any(|rule| {
                rule.as_object().is_some_and(|rule| {
                    let canonical_fields = rule.len() == 3 && !rule.contains_key("method")
                        || rule.len() == 4
                            && rule.get("method").and_then(Value::as_str) == Some("default");
                    canonical_fields
                        && rule.get("ip_version").and_then(Value::as_u64) == Some(6)
                        && rule.get("action").and_then(Value::as_str) == Some("reject")
                        && rule.get("no_drop").and_then(Value::as_bool) == Some(true)
                })
            })
        })
}

fn sniff_rule_has(config: &Value, tag: &str) -> bool {
    config
        .pointer("/route/rules")
        .and_then(Value::as_array)
        .is_some_and(|rules| {
            rules.iter().any(|rule| {
                rule.get("action").and_then(Value::as_str) == Some("sniff")
                    && value_contains_string(rule.get("inbound"), tag)
            })
        })
}

fn singbox_dns_strategy(config: Option<&Value>) -> &'static str {
    match config
        .and_then(|config| config.get("dns"))
        .and_then(|dns| dns.get("strategy"))
        .and_then(Value::as_str)
    {
        Some("ipv4_only") => "ipv4_only",
        Some("prefer_ipv4") => "prefer_ipv4",
        Some("prefer_ipv6") => "prefer_ipv6",
        Some("ipv6_only") => "ipv6_only",
        _ => "unset",
    }
}

fn has_remote_dns_detour(config: &Value) -> bool {
    if !crate::diagnostics_routing::outbound_is_proxy_or_block(config, "proxy") {
        return false;
    }
    let Some(servers) = config.pointer("/dns/servers").and_then(Value::as_array) else {
        return false;
    };
    let final_tag = match config.pointer("/dns/final") {
        None | Some(Value::Null) => servers.first().and_then(|server| server["tag"].as_str()),
        Some(Value::String(tag)) if tag.is_empty() => {
            servers.first().and_then(|server| server["tag"].as_str())
        }
        Some(Value::String(tag)) => Some(tag.as_str()),
        _ => None,
    };
    let uses_proxy = |tag: Option<&str>| {
        let Some(tag) = tag.filter(|tag| !tag.is_empty()) else {
            return false;
        };
        let mut matches = servers
            .iter()
            .filter(|server| server["tag"].as_str() == Some(tag));
        matches.next().is_some_and(|server| {
            server["detour"].as_str() == Some("proxy")
                && matches!(
                    server["type"].as_str(),
                    Some("udp" | "tcp" | "tls" | "https" | "quic" | "h3")
                )
                && server["server"]
                    .as_str()
                    .is_some_and(|host| !host.is_empty())
        }) && matches.next().is_none()
    };
    if !uses_proxy(final_tag) {
        return false;
    }
    // A remote server elsewhere in the list cannot protect a direct default
    // or an unconditional evaluate/route rule ahead of it. Explicit domain,
    // mode and LAN rules retain their configured resolver choices.
    config
        .pointer("/dns/rules")
        .and_then(Value::as_array)
        .is_none_or(|rules| {
            rules.iter().all(|rule| {
                let default_type = rule
                    .get("type")
                    .filter(|kind| !kind.is_null())
                    .is_none_or(|kind| matches!(kind.as_str(), Some("" | "default")));
                // The core treats an empty default matcher as unconditional,
                // including explicit type metadata and either invert value.
                let unconditional = default_type
                    && rule.as_object().is_some_and(|object| {
                        object.iter().all(|(key, value)| {
                            matches!(
                                key.as_str(),
                                "type"
                                    | "invert"
                                    | "action"
                                    | "server"
                                    | "tag"
                                    | "strategy"
                                    | "disable_cache"
                                    | "disable_optimistic_cache"
                                    | "rewrite_ttl"
                                    | "timeout"
                                    | "client_subnet"
                                    | "remove_client_subnet"
                                    | "speculative"
                                    | "race"
                                    | "rule_set_ip_cidr_match_source"
                                    | "rule_set_ipcidr_match_source"
                                    | "rule_set_ip_cidr_accept_empty"
                            ) || value.is_null()
                                || value.as_array().is_some_and(Vec::is_empty)
                                || value.as_object().is_some_and(|map| map.is_empty())
                                || value.as_bool() == Some(false)
                                || key == "clash_mode" && value.as_str() == Some("")
                                || key == "ip_version" && value.as_u64() == Some(0)
                        })
                    });
                !unconditional
                    || !matches!(
                        rule.get("action").and_then(Value::as_str),
                        None | Some("route" | "evaluate")
                    )
                    || uses_proxy(rule.get("server").and_then(Value::as_str))
            })
        })
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "ok"
    } else {
        "missing"
    }
}

fn disabled_enabled(disabled: bool) -> &'static str {
    if disabled {
        "disabled"
    } else {
        "enabled"
    }
}

#[cfg(test)]
mod tests {
    use super::{
        has_remote_dns_detour, ipv6_guard_status, singbox_dns_config_from_text,
        singbox_dns_strategy, Ipv6GuardStatus, SingboxDnsConfig,
    };
    use serde_json::Value;

    fn parsed(json: &str) -> Value {
        serde_json::from_str(json).expect("test JSON must be valid")
    }

    fn with_proxy_outbound(mut config: Value) -> Value {
        config["outbounds"] = serde_json::json!([
            {"tag":"proxy","type":"http","server":"proxy.invalid","server_port":8080}
        ]);
        config
    }

    fn healthy_config(strategy: &'static str, ipv6_guard: Ipv6GuardStatus) -> SingboxDnsConfig {
        SingboxDnsConfig {
            valid_json: true,
            fake_ip_disabled: true,
            hijack: true,
            remote_dns: true,
            store_fake_ip_disabled: true,
            sniff_inbound: true,
            strategy,
            ipv6_guard,
            transparent_dns: true,
        }
    }

    #[test]
    fn dns_hijack_accepts_dedicated_inbound_array_rule() {
        let config = singbox_dns_config_from_text(
            r#"{"route":{"rules":[{"inbound":["magicnet-dns-in"],"action":"hijack-dns"}]}}"#,
            "tun",
            true,
        );

        assert!(config.hijack);
    }

    #[test]
    fn dns_hijack_accepts_protocol_string_rule() {
        let config = singbox_dns_config_from_text(
            r#"{"route":{"rules":[{"protocol":"dns","action":"hijack-dns"}]}}"#,
            "tun",
            true,
        );

        assert!(config.hijack);
    }

    #[test]
    fn dns_hijack_rejects_action_and_matcher_in_different_rules() {
        let config = singbox_dns_config_from_text(
            r#"{"route":{"rules":[{"protocol":"dns"},{"action":"hijack-dns"}]}}"#,
            "tun",
            true,
        );

        assert!(!config.hijack);
    }

    #[test]
    fn dns_hijack_rejects_unrelated_inbound_rule() {
        let config = singbox_dns_config_from_text(
            r#"{"route":{"rules":[{"inbound":["mixed-in"],"action":"hijack-dns"}]}}"#,
            "tun",
            true,
        );

        assert!(!config.hijack);
    }

    #[test]
    fn dns_hijack_rejects_malformed_json_with_matching_tokens() {
        let config = singbox_dns_config_from_text(
            r#"{"route":{"rules":[{"protocol":"dns","action":"hijack-dns"}]}} trailing"#,
            "tun",
            true,
        );

        assert!(!config.hijack);
    }

    #[test]
    fn remote_dns_detour_accepts_tls_server_name() {
        let config = r#"
        {
          "dns": {
            "servers": [
              {
                "type": "https",
                "tag": "doh-google",
                "detour": "proxy",
                "server": "8.8.8.8",
                "server_port": 443,
                "tls": {
                  "server_name": "dns.google"
                }
              }
            ]
          }
        }
        "#;

        assert!(has_remote_dns_detour(&with_proxy_outbound(parsed(config))));
    }

    #[test]
    fn remote_dns_detour_requires_proxy_detour() {
        let config = r#"
        {
          "dns": {
            "servers": [
              {
                "type": "https",
                "tag": "doh-google",
                "server": "dns.google"
              }
            ]
          }
        }
        "#;

        assert!(!has_remote_dns_detour(&with_proxy_outbound(parsed(config))));
    }

    #[test]
    fn remote_dns_detour_rejects_fields_split_across_servers() {
        let config = with_proxy_outbound(parsed(
            r#"{"dns":{"servers":[{"detour":"proxy","server":"other.invalid"},{"server":"dns.google"}]}}"#,
        ));
        assert!(!has_remote_dns_detour(&config));
    }

    #[test]
    fn remote_dns_detour_checks_the_selected_default_not_an_unused_server() {
        let mut config = with_proxy_outbound(serde_json::json!({"dns": {
            "servers": [
                {"type":"https","tag":"local","server":"223.6.6.6"},
                {"type":"https","tag":"remote","server":"9.9.9.9","detour":"proxy"}
            ], "final":"local"
        }}));
        assert!(!has_remote_dns_detour(&config));
        config["dns"]["final"] = "remote".into();
        assert!(has_remote_dns_detour(&config));
        for tag in ["missing", ""] {
            config["dns"]["final"] = tag.into();
            assert!(!has_remote_dns_detour(&config));
        }
    }

    #[test]
    fn remote_dns_detour_accepts_proxy_udp_and_arbitrary_resolver_hosts() {
        for kind in ["https", "tls", "udp", "tcp", "quic", "h3"] {
            for host in [
                "1.1.1.1",
                "2606:4700:4700::1111",
                "resolver.example.invalid",
            ] {
                let config = with_proxy_outbound(serde_json::json!({"dns":{"servers":[
                    {"type":kind,"tag":"remote","server":host,"detour":"proxy"}
                ]}}));
                assert!(has_remote_dns_detour(&config), "{kind} {host}");
            }
        }
    }

    #[test]
    fn remote_dns_detour_rejects_stale_evaluation_and_duplicate_tags() {
        let mut config = with_proxy_outbound(serde_json::json!({"dns": {
            "servers": [
                {"type":"https","tag":"local","server":"223.6.6.6"},
                {"type":"https","tag":"remote","server":"1.1.1.1","detour":"proxy"}
            ], "final":"remote"
        }}));
        for action in ["route", "evaluate"] {
            config["dns"]["rules"] = serde_json::json!([
                {"action":action,"server":"local","tag":"magicnet-final-dns"}
            ]);
            assert!(!has_remote_dns_detour(&config));
        }
        config["dns"]["rules"] = serde_json::json!([
            {"domain_suffix":["cn"],"server":"local"},
            {"clash_mode":"Direct","server":"local"},
            {"action":"evaluate","server":"remote","tag":"magicnet-final-dns"},
            {"match_response":"magicnet-final-dns","action":"respond"}
        ]);
        assert!(has_remote_dns_detour(&config));
        config["dns"]["servers"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"type":"https","tag":"remote","server":"223.6.6.6"}));
        assert!(!has_remote_dns_detour(&config));
    }

    #[test]
    fn remote_dns_detour_handles_explicit_default_rule_metadata() {
        let mut config = with_proxy_outbound(serde_json::json!({"dns": {
            "servers": [
                {"type":"https","tag":"local","server":"223.6.6.6"},
                {"type":"https","tag":"remote","server":"1.1.1.1","detour":"proxy"}
            ], "final":"remote"
        }}));
        for action in ["route", "evaluate"] {
            for metadata in [
                serde_json::json!({}),
                serde_json::json!({"type":""}),
                serde_json::json!({"type":"default"}),
                serde_json::json!({"type":"default","invert":false}),
                serde_json::json!({"invert":true}),
                serde_json::json!({"type":null,"domain":[]}),
                serde_json::json!({"domain_suffix":[],"rule_set":[],"ip_version":0}),
                serde_json::json!({"network":null,"match_response":false,"clash_mode":""}),
                serde_json::json!({"interface_address":{},"network_is_expensive":false}),
            ] {
                let mut rule = metadata;
                rule["action"] = action.into();
                rule["server"] = "local".into();
                config["dns"]["rules"] = serde_json::json!([rule]);
                assert!(!has_remote_dns_detour(&config), "{config}");
                config["dns"]["rules"][0]["server"] = "remote".into();
                assert!(has_remote_dns_detour(&config), "{config}");
            }
        }
        config["dns"]["rules"] = serde_json::json!([
            {"type":"default","domain_suffix":["cn"],"server":"local"},
            {"type":"default","invert":false,"clash_mode":"Direct","server":"local"}
        ]);
        assert!(has_remote_dns_detour(&config));
    }

    #[test]
    fn remote_dns_detour_resolves_the_proxy_outbound() {
        let mut config = serde_json::json!({"dns": {
            "servers":[{"type":"https","tag":"remote","server":"1.1.1.1","detour":"proxy"}],
            "final":"remote"
        }});
        for outbounds in [
            serde_json::json!([]),
            serde_json::json!([{"tag":"proxy","type":"direct"}]),
            serde_json::json!([
                {"tag":"proxy","type":"selector","outbounds":["direct"],"default":"direct"},
                {"tag":"direct","type":"direct"}
            ]),
            serde_json::json!([
                {"tag":"proxy","type":"urltest","outbounds":["direct","remote-node"]},
                {"tag":"direct","type":"direct"},
                {"tag":"remote-node","type":"http","server":"proxy.invalid","server_port":8080}
            ]),
            serde_json::json!([{"tag":"proxy","type":"selector","outbounds":["missing"]}]),
            serde_json::json!([{"tag":"proxy","type":"selector","outbounds":["proxy"]}]),
            serde_json::json!([
                {"tag":"proxy","type":"http","server":"proxy.invalid","server_port":8080},
                {"tag":"proxy","type":"direct"}
            ]),
        ] {
            config["outbounds"] = outbounds;
            assert!(!has_remote_dns_detour(&config), "{config}");
        }
        for outbounds in [
            serde_json::json!([{"tag":"proxy","type":"http","server":"proxy.invalid","server_port":8080}]),
            serde_json::json!([
                {"tag":"proxy","type":"selector","outbounds":["auto"]},
                {"tag":"auto","type":"urltest","outbounds":["node"]},
                {"tag":"node","type":"http","server":"proxy.invalid","server_port":8080}
            ]),
            serde_json::json!([
                {"tag":"proxy","type":"selector","outbounds":["block"]},
                {"tag":"block","type":"block"}
            ]),
        ] {
            config["outbounds"] = outbounds;
            assert!(has_remote_dns_detour(&config), "{config}");
        }
    }

    #[test]
    fn sniff_inbound_rejects_action_and_inbound_split_across_rules() {
        let config = singbox_dns_config_from_text(
            r#"{"route":{"rules":[{"action":"sniff"},{"inbound":["mixed-in","tun-in"]}]}}"#,
            "tun",
            true,
        );
        assert!(!config.sniff_inbound);
    }

    #[test]
    fn ipv4_only_with_ipv6_reject_guard_passes() {
        let config = parsed(
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","method":"default","no_drop":true}]}}"#,
        );
        let guard = ipv6_guard_status("ipv4_only", Some(&config));

        assert!(healthy_config("ipv4_only", guard).ok());
    }

    #[test]
    fn ipv4_only_with_implicit_default_ipv6_reject_guard_passes() {
        let config =
            parsed(r#"{"route":{"rules":[{"ip_version":6,"action":"reject","no_drop":true}]}}"#);
        let guard = ipv6_guard_status("ipv4_only", Some(&config));

        assert!(healthy_config("ipv4_only", guard).ok());
    }

    #[test]
    fn ipv4_only_without_ipv6_reject_guard_fails() {
        let config = parsed(r#"{"route":{"rules":[]}}"#);
        let guard = ipv6_guard_status("ipv4_only", Some(&config));

        assert!(!healthy_config("ipv4_only", guard).ok());
    }

    #[test]
    fn ipv4_only_with_malformed_config_fails() {
        let guard = ipv6_guard_status("ipv4_only", None);

        assert!(!healthy_config("ipv4_only", guard).ok());
    }

    #[test]
    fn malformed_json_with_all_health_tokens_is_unhealthy() {
        let malformed = r#"
        {
          "dns": {
            "servers": [
              {"type": "fakeip", "tag": "fakeip"},
              {"server": "dns.google", "detour": "proxy"}
            ]
          },
          "experimental": {"cache_file": {"store_fakeip": true}},
          "route": {
            "rules": [
              {"protocol": "dns", "action": "hijack-dns"},
              {"action": "sniff", "inbound": ["mixed-in", "tun-in"]}
            ]
          }
        }
        trailing-invalid-json
        "#;

        let config = singbox_dns_config_from_text(malformed, "tun", true);

        assert_eq!(
            (
                config.fake_ip_disabled,
                config.hijack,
                config.remote_dns,
                config.store_fake_ip_disabled,
                config.sniff_inbound,
                config.valid_json,
                config.ok(),
            ),
            (false, false, false, false, false, false, false)
        );
    }

    #[test]
    fn unused_fake_ip_server_is_unhealthy() {
        let config = singbox_dns_config_from_text(
            r#"{
              "outbounds":[{"tag":"proxy","type":"http","server":"proxy.invalid","server_port":8080}],
              "dns": {
                "servers": [
                  {"type":"fakeip","tag":"fakeip"},
                  {"type":"https","tag":"remote","server":"dns.google","detour":"proxy"}
                ]
              },
              "route": {"rules": [
                {"protocol":"dns","action":"hijack-dns"},
                {"action":"sniff","inbound":["mixed-in","tun-in"]}
              ]}
            }"#,
            "tun",
            true,
        );

        assert!(!config.ok());
    }

    #[test]
    fn real_address_dns_without_fake_ip_is_healthy() {
        let config = singbox_dns_config_from_text(
            r#"{
              "outbounds":[{"tag":"proxy","type":"http","server":"proxy.invalid","server_port":8080}],
              "dns": {"servers": [
                {"type":"https","tag":"remote","server":"dns.google","detour":"proxy"}
              ], "strategy":"prefer_ipv4"},
              "route": {"rules": [
                {"protocol":"dns","action":"hijack-dns"},
                {"action":"sniff","inbound":["mixed-in","tun-in"]}
              ]},
              "experimental":{"cache_file":{"enabled":true}}
            }"#,
            "tun",
            true,
        );

        assert!(config.ok());
    }

    #[test]
    fn prefer_ipv4_without_ipv6_reject_guard_does_not_fail() {
        let config = parsed(r#"{"route":{"rules":[]}}"#);
        let guard = ipv6_guard_status("prefer_ipv4", Some(&config));

        assert!(healthy_config("prefer_ipv4", guard).ok());
    }

    #[test]
    fn prefer_ipv4_with_stale_ipv6_reject_guard_fails() {
        let config = parsed(
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","method":"default","no_drop":true}]}}"#,
        );
        let guard = ipv6_guard_status("prefer_ipv4", Some(&config));

        assert_eq!(guard, Ipv6GuardStatus::Unexpected);
        assert!(!healthy_config("prefer_ipv4", guard).ok());
    }

    #[test]
    fn ipv6_reject_guard_rejects_legacy_lookalikes_and_wrong_values() {
        let invalid = [
            r#"{"route":{"rules":[{"ip_version":6,"outbound":"block"}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","method":"default"}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","no_drop":false}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","method":"default","no_drop":false}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","method":"drop","no_drop":true}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","method":"default","no_drop":true,"network":"tcp"}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","no_drop":true,"network":"tcp"}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","method":"default","no_drop":true,"domain_suffix":["example.com"]}]}}"#,
            r#"{"route":{"rules":[{"ip_version":"6","action":"reject","method":"default","no_drop":true}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6.0,"action":"reject","method":"default","no_drop":true}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"Reject","method":"default","no_drop":true}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","method":"DEFAULT","no_drop":true}]}}"#,
            r#"{"route":{"rules":[{"ip_version":6,"action":"reject","method":"default","no_drop":"true"}]}}"#,
        ];

        assert!(invalid.iter().all(|json| {
            ipv6_guard_status("ipv4_only", Some(&parsed(json))) == Ipv6GuardStatus::Missing
        }));
    }

    #[test]
    fn ipv6_reject_guard_is_independent_of_field_order() {
        let config = parsed(
            r#"{"route":{"rules":[{"no_drop":true,"method":"default","action":"reject","ip_version":6}]}}"#,
        );

        assert_eq!(
            ipv6_guard_status("ipv4_only", Some(&config)),
            Ipv6GuardStatus::Ok
        );
    }

    #[test]
    fn dns_strategy_ignores_out_of_scope_strategy_strings() {
        let config = parsed(
            r#"{"dns":{"strategy":"prefer_ipv4","servers":[{"strategy":"ipv4_only"}]},"route":{"strategy":"ipv6_only"}}"#,
        );

        assert_eq!(singbox_dns_strategy(Some(&config)), "prefer_ipv4");
    }

    #[test]
    fn dns_strategy_rejects_missing_wrong_type_and_malformed_values() {
        let missing = parsed(r#"{"dns":{}}"#);
        let wrong_type = parsed(r#"{"dns":{"strategy":["ipv4_only"]}}"#);
        let unknown = parsed(r#"{"dns":{"strategy":"IPv4_only"}}"#);

        assert_eq!(
            [
                singbox_dns_strategy(Some(&missing)),
                singbox_dns_strategy(Some(&wrong_type)),
                singbox_dns_strategy(Some(&unknown)),
                singbox_dns_strategy(None),
            ],
            ["unset"; 4]
        );
    }
}
