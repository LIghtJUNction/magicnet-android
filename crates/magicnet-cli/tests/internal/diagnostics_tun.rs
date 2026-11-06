use super::{auto_route_check_with, read_snapshot, Family, RouteExpectation, SNAPSHOT_LIMIT};
use crate::diagnostics::{tun_dataplane_check_with_probe, TransparentModeSource};
use crate::test_support::temp_app;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{Duration, Instant};

const SYSTEM_RULES: &str = "0: from all lookup 255\n10000: from all fwmark 0xc0000/0xd0000 lookup 99\n18000: from all iif lo oif wlan0 lookup 1031\n32000: from all unreachable\n";
const ROUTES4: &str = "0.0.0.0/1 dev magicnet0 scope link\n128.0.0.0/1 dev magicnet0 scope link\n";
const ROUTES6: &str = "default dev magicnet0 metric 1024 pref medium\n";

fn inbound() -> Value {
    json!({
        "type": "tun", "tag": "tun-in", "interface_name": "magicnet0",
        "address": ["172.19.0.1/30"], "auto_route": true,
        "exclude_uid": [0, 2000, 10123]
    })
}

fn normal_rules(table: u32, start: u32, family: Family) -> String {
    let end = start + 10;
    let bypass = start + 1;
    let local = start + 2;
    let mut rules = format!("{SYSTEM_RULES}{start}: from all uidrange 0-0 goto {end}\n{start}: from all uidrange 2000-2000 goto {end}\n{bypass}: from all iif magicnet0 goto {end}\n");
    match family {
        Family::V4 => rules.push_str(&format!("{local}: not from all iif lo lookup {table}\n{local}: from 0.0.0.0 iif lo lookup {table}\n{local}: from 172.19.0.0/30 iif lo lookup {table}\n")),
        Family::V6 => rules.push_str(&format!("{local}: from fdfe:dcba:9876::/126 iif lo lookup {table}\n{}: from ::/1 iif lo goto {end}\n{}: from 8000::/1 iif lo goto {end}\n{}: from all lookup {table}\n", local + 1, local + 1, local + 2)),
    }
    rules.push_str(&format!("{end}: from all nop\n"));
    rules
}

fn redirect_rules(
    table: u32,
    start: u32,
    fallback: u32,
    input: u32,
    output: u32,
    mask: u32,
) -> String {
    format!("{SYSTEM_RULES}{start}: from all fwmark {output:#x}/{mask:#x} goto {}\n{}: from all fwmark {input:#x}/{mask:#x} lookup {table}\n{}: from all nop\n{fallback}: not from all fwmark {output:#x}/{mask:#x} lookup {table}\n", start + 2, start + 1, start + 2)
}

fn rule_snapshot(args: &[&str], rules: &str) -> String {
    if args.contains(&"table") {
        let lookup = format!("lookup {}", args.last().unwrap().trim());
        rules
            .lines()
            .filter(|line| line.ends_with(&lookup))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        rules.into()
    }
}

fn check(inbound: &Value, android: bool, rules: &str, routes: &str) -> (bool, String) {
    let (ready, detail) = auto_route_check_with(inbound, android, |args| {
        Ok(if args.contains(&"rule") {
            rule_snapshot(args, rules)
        } else {
            routes.into()
        })
    });
    (ready == Some(true), detail)
}

#[test]
fn android_ip_compatibility_reads_both_families_without_numeric_option() {
    let app = temp_app();
    for (family, rules, routes) in [
        ("4", normal_rules(2022, 9000, Family::V4), ROUTES4),
        ("6", normal_rules(2022, 9000, Family::V6), ROUTES6),
    ] {
        fs::write(app.moddir.join(format!("rules{family}")), rules).unwrap();
        fs::write(app.moddir.join(format!("routes{family}")), routes).unwrap();
    }
    let ip = app.moddir.join("android-ip-fixture");
    // AOSP android-15.0.0_r1 ip/ip.c disables numeric output support and
    // rejects -N before opening netlink. Supply safe, known kernel snapshots
    // after that argument check instead of requiring a privileged test host.
    fs::write(
        &ip,
        r#"#!/bin/sh
case "$*" in
'-4 -N rule show'|'-6 -N rule show')
    printf '%s\n' 'Option "-N" is unknown, try "ip -help".' >&2
    exit 255;;
'-4 rule show') cat "$TUN_HEALTH_FIXTURE/rules4";;
'-6 rule show') cat "$TUN_HEALTH_FIXTURE/rules6";;
'-4 rule show table  2022') sed -n '/lookup 2022$/p' "$TUN_HEALTH_FIXTURE/rules4";;
'-6 rule show table  2022') sed -n '/lookup 2022$/p' "$TUN_HEALTH_FIXTURE/rules6";;
'-4 route show table  2022') cat "$TUN_HEALTH_FIXTURE/routes4";;
'-6 route show table  2022') cat "$TUN_HEALTH_FIXTURE/routes6";;
*) exit 64;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&ip, fs::Permissions::from_mode(0o700)).unwrap();
    let run = |args: &[&str]| {
        let mut command = Command::new(&ip);
        command.args(args).env("TUN_HEALTH_FIXTURE", &app.moddir);
        read_snapshot(command, Duration::from_secs(1), SNAPSHOT_LIMIT)
    };
    for family in ["-4", "-6"] {
        assert_eq!(run(&[family, "-N", "rule", "show"]), Err("command-failed"));
    }
    let mut config = inbound();
    config["address"] = json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"]);
    let (ready, detail) = auto_route_check_with(&config, true, run);
    assert_eq!(ready, Some(true), "{detail}");
    assert!(detail.contains("ipv4_rpdb=present"));
    assert!(detail.contains("ipv6_rpdb=present"));
}

#[test]
fn interface_and_stale_active_ledger_do_not_hide_lost_live_rules() {
    let app = temp_app();
    fs::create_dir_all(app.moddir.join(".config/sing-box")).unwrap();
    fs::create_dir_all(app.moddir.join(".state/network")).unwrap();
    fs::write(
        app.moddir.join(".config/sing-box/config.json"),
        json!({"inbounds": [inbound()]}).to_string(),
    )
    .unwrap();
    let ledger = app.moddir.join(".state/network/kernel-route-table.state");
    let ledger_text = "schema=1\nphase=active\ntable=2022\ninterface=magicnet0\n";
    fs::write(&ledger, ledger_text).unwrap();
    fs::write(
        app.moddir.join("rules"),
        normal_rules(2022, 9000, Family::V4),
    )
    .unwrap();
    fs::write(app.moddir.join("routes"), ROUTES4).unwrap();
    let ip = app.moddir.join("ip-fixture");
    fs::write(&ip, "#!/bin/sh\ncase \"$*\" in\n'-4 rule show') cat \"$TUN_HEALTH_FIXTURE/rules\";;\n'-4 rule show table  2022') sed -n '/lookup 2022$/p' \"$TUN_HEALTH_FIXTURE/rules\";;\n'-4 route show table  2022') cat \"$TUN_HEALTH_FIXTURE/routes\";;\n*) exit 64;;\nesac\n").unwrap();
    fs::set_permissions(&ip, fs::Permissions::from_mode(0o700)).unwrap();
    let run = || {
        tun_dataplane_check_with_probe(&app, TransparentModeSource::Default, true, |inbound| {
            let (ready, detail) = auto_route_check_with(inbound, true, |args| {
                let mut command = Command::new(&ip);
                command.args(args).env("TUN_HEALTH_FIXTURE", &app.moddir);
                read_snapshot(command, Duration::from_secs(1), SNAPSHOT_LIMIT)
            });
            (ready == Some(true), detail)
        })
    };
    assert!(run().0);
    // Reproduce #436's distinguishing evidence: the interface, ledger and FIB
    // remain, while the actual RPDB group disappears between observations.
    fs::write(app.moddir.join("rules"), SYSTEM_RULES).unwrap();
    let (ok, detail) = run();
    assert!(!ok, "{detail}");
    assert!(detail.contains("probe=present"), "{detail}");
    assert!(detail.contains("ipv4_rpdb=missing"), "{detail}");
    assert!(detail.contains("ipv4_fib=present"), "{detail}");
    assert_eq!(fs::read_to_string(&ledger).unwrap(), ledger_text);
    assert_eq!(
        fs::read_to_string(app.moddir.join("routes")).unwrap(),
        ROUTES4
    );
    fs::write(
        app.moddir.join("rules"),
        normal_rules(2022, 9000, Family::V4),
    )
    .unwrap();
    assert!(run().0);
}

#[test]
fn hotspot_and_conditional_lookups_are_not_application_rules() {
    for residual in [
        "9002: from all iif wlan2 lookup 2022\n",
        "9002: from all uidrange 0-0 lookup 2022\n",
        "9002: from all fwmark 0x1 lookup 2022\n",
        "9002: from all ipproto udp dport 53 lookup 2022\n",
        "9002: not from all iif lo lookup 2022\n",
        "9002: from 172.19.0.0/30 iif lo lookup 2022\n",
    ] {
        let rules = format!(
            "{SYSTEM_RULES}9001: from all iif magicnet0 goto 9010\n{residual}9010: from all nop\n"
        );
        assert!(
            !check(&inbound(), true, &rules, ROUTES4).0,
            "accepted {residual}"
        );
    }
}

#[test]
fn normal_local_group_requires_its_local_source_rules() {
    let mut config = inbound();
    config["address"] = json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"]);
    for family in [Family::V4, Family::V6] {
        let expected = RouteExpectation::from_inbound(&config, true)
            .unwrap()
            .unwrap();
        let prefixes = &expected
            .families
            .iter()
            .find(|entry| entry.0 == family)
            .unwrap()
            .1;
        let healthy = normal_rules(2022, 9000, family);
        assert!(expected.rules_present(&healthy, family, prefixes).unwrap());
        let damaged = healthy
            .lines()
            .filter(|line| !line.contains("iif lo lookup"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!expected.rules_present(&damaged, family, prefixes).unwrap());
    }
}

#[test]
fn custom_table_priority_uid_exclusions_and_android_network_tables_are_supported() {
    let mut config = inbound();
    config["iproute2_table_index"] = json!(4242);
    config["iproute2_rule_index"] = json!(12340);
    let rules = normal_rules(4242, 12340, Family::V4);
    let mut calls = Vec::new();
    let result = auto_route_check_with(&config, true, |args| {
        calls.push(args.join(" "));
        Ok(if args.contains(&"rule") {
            rule_snapshot(args, &rules)
        } else {
            ROUTES4.into()
        })
    });
    assert_eq!(result.0, Some(true), "{}", result.1);
    assert_eq!(
        calls,
        [
            "-4 rule show",
            "-4 rule show table  4242",
            "-4 route show table  4242"
        ]
    );
    assert!(!result.1.contains("2000"));
    // No main-table default, route-get UID, or public destination is required.
}

#[test]
fn android_named_tables_require_the_same_rules_in_the_numeric_table_dump() {
    let mut config = inbound();
    config["address"] = json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"]);
    config["iproute2_table_index"] = json!(4242);
    config["iproute2_rule_index"] = json!(12340);
    for redirect in [false, true] {
        config["auto_redirect"] = json!(redirect);
        let mut calls = Vec::new();
        let result = auto_route_check_with(&config, true, |args| {
            calls.push(args.join(" "));
            let family = if args[0] == "-4" {
                Family::V4
            } else {
                Family::V6
            };
            let rules = if redirect {
                redirect_rules(4242, 12340, 32768, 0x400000, 0x200000, 0xe00000)
            } else {
                normal_rules(4242, 12340, family)
            }
            .replace("lookup 4242", "lookup PRIVATE-TABLE-CANARY")
            .replace("lookup 255", "lookup local")
            .replace("lookup 1031", "lookup PRIVATE-NETWORK-CANARY");
            Ok(match &args[1..] {
                ["rule", "show"] => rules,
                ["rule", "show", "table", " 4242"] => rules
                    .lines()
                    .filter(|line| line.contains("lookup PRIVATE-TABLE-CANARY"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                ["route", "show", "table", " 4242"] => if family == Family::V4 {
                    ROUTES4
                } else {
                    ROUTES6
                }
                .into(),
                _ => panic!("unexpected command"),
            })
        });
        assert_eq!(result.0, Some(true), "{}", result.1);
        assert!(!result.1.contains("CANARY"));
        assert_eq!(
            calls,
            [
                "-4 rule show",
                "-4 rule show table  4242",
                "-4 route show table  4242",
                "-6 rule show",
                "-6 rule show table  4242",
                "-6 route show table  4242",
            ]
        );
    }
}

#[test]
fn numeric_table_alias_cannot_substitute_rules_or_routes_on_either_platform() {
    // AOSP rt_names.c accepts `4242 2022`: both broad output and the unpadded
    // argument "2022" then name table 4242. A single argv " 2022" reaches
    // strtoul without matching any whitespace-free rt_tables name.
    let rules = normal_rules(2022, 9000, Family::V4);
    let filtered = rules
        .lines()
        .filter(|line| line.ends_with("lookup 2022"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut outcomes = Vec::new();
    for (actual_rules, actual_routes) in [("", ROUTES4), (filtered.as_str(), "")] {
        let result = auto_route_check_with(&inbound(), true, |args| {
            Ok(match &args[1..] {
                ["rule", "show"] => rules.clone(),
                ["rule", "show", "table", "2022"] => filtered.clone(),
                ["route", "show", "table", "2022"] => ROUTES4.into(),
                ["rule", "show", "table", " 2022"] => actual_rules.into(),
                ["route", "show", "table", " 2022"] => actual_routes.into(),
                _ => panic!("unexpected command"),
            })
        });
        outcomes.push(result.0);
    }
    assert_eq!(outcomes, [None, Some(false)]);
    // Linux -N makes rule output numeric but does not change table argument
    // parsing. Its FIB lookup needs the same unambiguous numeric argv.
    for actual_routes in ["", ROUTES4] {
        let result = auto_route_check_with(&inbound(), false, |args| {
            Ok(match &args[1..] {
                ["-N", "rule", "show"] => rules.clone(),
                ["route", "show", "table", "2022"] => ROUTES4.into(),
                ["route", "show", "table", " 2022"] => actual_routes.into(),
                _ => panic!("unexpected command"),
            })
        });
        assert_eq!(result.0, Some(!actual_routes.is_empty()), "{}", result.1);
    }
}

#[test]
fn unverified_named_tables_stay_unknown_and_verified_residuals_stay_missing() {
    let rules =
        normal_rules(2022, 9000, Family::V4).replace("lookup 2022", "lookup PRIVATE-TABLE-CANARY");
    let filtered = rules
        .lines()
        .filter(|line| line.contains("lookup PRIVATE-TABLE-CANARY"))
        .collect::<Vec<_>>()
        .join("\n");
    for (table_rules, reason) in [
        (Err("deadline"), "deadline"),
        (Ok(String::new()), "rule-table-unverified"),
        (
            Ok(filtered.replace("9002:", "9003:")),
            "rule-table-unverified",
        ),
        (
            Ok(filtered.replace("iif lo", "iif wlan2")),
            "rule-table-unverified",
        ),
        (
            Ok(format!("{filtered}\n9002: from all lookup 4242\n")),
            "rule-table-filter-unverified",
        ),
        (Ok(rules.clone()), "rule-table-filter-unverified"),
    ] {
        let result = auto_route_check_with(&inbound(), true, |args| match &args[1..] {
            ["rule", "show"] => Ok(rules.clone()),
            ["rule", "show", "table", " 2022"] => table_rules.clone(),
            ["route", "show", "table", " 2022"] => Ok(ROUTES4.into()),
            _ => panic!("unexpected command"),
        });
        assert_eq!(result.0, None, "{}", result.1);
        assert!(result.1.contains(&format!("ipv4_rpdb=unknown:{reason}")));
        assert!(!result.1.contains("CANARY"));
    }
    for residual in [
        "9002: from all iif wlan2 lookup PRIVATE-TABLE-CANARY",
        "9002: from all uidrange 0-0 lookup PRIVATE-TABLE-CANARY",
        "9002: not from all iif lo lookup PRIVATE-TABLE-CANARY",
    ] {
        let result = auto_route_check_with(&inbound(), true, |args| {
            Ok(match &args[1..] {
                ["rule", "show"] => format!("{SYSTEM_RULES}9001: from all iif magicnet0 goto 9010\n{residual}\n9010: from all nop\n"),
                ["rule", "show", "table", " 2022"] => residual.into(),
                ["route", "show", "table", " 2022"] => ROUTES4.into(),
                _ => panic!("unexpected command"),
            })
        });
        assert_eq!(result.0, Some(false), "{}", result.1);
        assert!(result.1.contains("ipv4_rpdb=missing"));
        assert!(!result.1.contains("CANARY"));
    }
}

#[test]
fn disabled_auto_route_and_invalid_interface_do_not_run_route_commands() {
    let mut config = inbound();
    for auto_route in [None, Some(json!(false))] {
        config.as_object_mut().unwrap().remove("auto_route");
        if let Some(auto_route) = auto_route {
            config["auto_route"] = auto_route;
        }
        let result = auto_route_check_with(&config, true, |_| panic!("auto_route disabled"));
        assert_eq!(result.0, Some(true));
        assert!(result.1.contains("rpdb=not_required"));
    }
    let app = temp_app();
    fs::create_dir_all(app.moddir.join(".config/sing-box")).unwrap();
    fs::write(
        app.moddir.join(".config/sing-box/config.json"),
        json!({"inbounds": [inbound()]}).to_string(),
    )
    .unwrap();
    assert!(
        !tun_dataplane_check_with_probe(&app, TransparentModeSource::Default, false, |_| panic!(
            "missing interface"
        ))
        .0
    );
}

#[test]
fn configured_ipv6_requires_its_own_rule_group_and_fib() {
    let mut config = inbound();
    config["address"] = json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"]);
    for missing6 in [false, true] {
        let result = auto_route_check_with(&config, true, |args| {
            Ok(match (args[0], args[1]) {
                ("-4", "rule") => rule_snapshot(args, &normal_rules(2022, 9000, Family::V4)),
                ("-4", "route") => ROUTES4.into(),
                ("-6", "rule") if !missing6 => {
                    rule_snapshot(args, &normal_rules(2022, 9000, Family::V6))
                }
                ("-6", "rule") => SYSTEM_RULES.into(),
                ("-6", "route") => ROUTES6.into(),
                _ => panic!("unexpected command"),
            })
        });
        assert_eq!(result.0, Some(!missing6), "{}", result.1);
    }
    let result = auto_route_check_with(&config, true, |args| {
        Ok(match (args[0], args[1]) {
            ("-4", "rule") => rule_snapshot(args, &normal_rules(2022, 9000, Family::V4)),
            ("-4", "route") => ROUTES4.into(),
            ("-6", "rule") => rule_snapshot(args, &normal_rules(2022, 9000, Family::V6)),
            ("-6", "route") => String::new(),
            _ => panic!("unexpected command"),
        })
    });
    assert_eq!(result.0, Some(false));
    assert!(result.1.contains("ipv6_fib=missing"));
}

#[test]
fn redirect_uses_the_platform_mark_group_not_the_fallback_or_hotspot_alone() {
    let mut config = inbound();
    config["auto_redirect"] = json!(true);
    for (android, input, output, mask) in [
        (true, 0x400000, 0x200000, 0xe00000),
        (false, 0x2023, 0x2024, 0x2027),
    ] {
        let rules = redirect_rules(2022, 9000, 32768, input, output, mask);
        assert!(check(&config, android, &rules, ROUTES4).0);
        for removed in ["9000:", "9001:", "9002:", "32768:"] {
            let damaged = rules
                .lines()
                .filter(|line| !line.starts_with(removed))
                .collect::<Vec<_>>()
                .join("\n");
            let damaged = format!("{damaged}\n9001: from all iif wlan2 lookup 2022\n");
            assert!(
                !check(&config, android, &damaged, ROUTES4).0,
                "accepted missing {removed}"
            );
        }
    }
}

#[test]
fn custom_and_reserved_android_marks_follow_the_bundled_core() {
    let mut config = inbound();
    config["auto_redirect"] = json!(true);
    config["iproute2_table_index"] = json!(4242);
    config["iproute2_rule_index"] = json!(12000);
    config["auto_redirect_iproute2_fallback_rule_index"] = json!(40000);
    config["auto_redirect_input_mark"] = json!("0x4000000");
    config["auto_redirect_output_mark"] = json!(0x8000000u32);
    config["auto_redirect_reset_mark"] = json!("0xc000000");
    config["auto_redirect_tproxy_mark"] = json!("0x10000000");
    let rules = redirect_rules(4242, 12000, 40000, 0x4000000, 0x8000000, 0x1c000000);
    assert!(check(&config, true, &rules, ROUTES4).0);
    for (key, value) in [
        ("input", 0x2023),
        ("output", 0x2024),
        ("reset", 0x2025),
        ("tproxy", 0x2026),
    ] {
        config[format!("auto_redirect_{key}_mark")] = json!(value);
    }
    let defaults = redirect_rules(4242, 12000, 40000, 0x400000, 0x200000, 0xe00000);
    assert!(check(&config, true, &defaults, ROUTES4).0);
    assert!(!check(&config, true, &rules, ROUTES4).0);
}

#[test]
fn failed_or_uninterpretable_observations_are_unknown_not_green() {
    for reason in [
        "deadline",
        "command-failed",
        "output-truncated",
        "command-unavailable",
        "output-invalid",
    ] {
        let result = auto_route_check_with(&inbound(), true, |_| Err(reason));
        assert_eq!(result.0, None);
        assert!(result.1.contains(&format!("rpdb=unknown:{reason}")));
        assert!(!result.1.contains("=missing"));
    }
    let rules = normal_rules(2022, 9000, Family::V4);
    for (bad_rules, bad_routes, reason) in [
        ("permission denied", ROUTES4, "rule-output-invalid"),
        (
            rules.as_str(),
            "not a routing table",
            "route-output-invalid",
        ),
    ] {
        let result = check(&inbound(), true, bad_rules, bad_routes);
        assert!(!result.0);
        assert!(
            result.1.contains(&format!("unknown:{reason}")),
            "{}",
            result.1
        );
    }
    for config in [
        json!({"auto_route": true, "address": []}),
        json!({"auto_route": "true"}),
        json!({"auto_route": true, "address": ["172.19.0.1/99"]}),
        json!({"auto_route": true, "address": ["172.19.0.1/30"], "netns": "private-canary"}),
    ] {
        let result =
            auto_route_check_with(&config, true, |_| panic!("uninterpretable configuration"));
        assert_eq!(result.0, None);
        assert!(result.1.contains("unknown"));
        assert!(!result.1.contains("private-canary"));
    }
}

#[test]
fn fib_evidence_requires_a_live_unicast_route_on_the_exact_tun_device() {
    let rules = normal_rules(2022, 9000, Family::V4);
    for routes in [
        "",
        "172.19.0.0/30 dev magicnet0 proto kernel scope link src 172.19.0.1\n",
        "default dev wlan0\n",
        "default dev magicnet00\n",
        "default dev magicnet0 linkdown\n",
        "local 172.19.0.1 dev magicnet0\n",
        "unreachable default dev magicnet0\n",
    ] {
        let result = check(&inbound(), true, &rules, routes);
        assert!(!result.0, "accepted {routes}");
        assert!(result.1.contains("ipv4_fib=missing"));
    }
}

#[test]
fn default_exclusions_accept_fragmented_fib_and_detect_missing_coverage() {
    // Independent oracle: these fixtures were generated with Python ipaddress
    // address_exclude from the pinned MagicSingBox template, not this parser.
    let template: Value = serde_json::from_str(include_str!(
        "../../../../src/MagicNet/.config/sing-box/config.json"
    ))
    .unwrap();
    let config = template["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|inbound| inbound["tag"] == "tun-in")
        .unwrap();
    let routes4 = include_str!("../fixtures/tun_default_routes_ipv4.txt");
    let routes6 = include_str!("../fixtures/tun_default_routes_ipv6.txt");
    let missing4 = routes4.lines().skip(1).collect::<Vec<_>>().join("\n");
    let missing6 = routes6.lines().skip(1).collect::<Vec<_>>().join("\n");
    let connected4 = "172.19.0.0/30 dev magicnet0 proto kernel scope link src 172.19.0.1\n";
    for (routes4, routes6, expected) in [
        (routes4, routes6, Some(true)),
        (missing4.as_str(), routes6, Some(false)),
        (routes4, missing6.as_str(), Some(false)),
        (connected4, routes6, Some(false)),
    ] {
        let result = auto_route_check_with(config, true, |args| {
            Ok(if args.contains(&"rule") {
                rule_snapshot(
                    args,
                    &redirect_rules(2022, 9000, 32768, 0x400000, 0x200000, 0xe00000),
                )
            } else if args[0] == "-4" {
                routes4.into()
            } else {
                routes6.into()
            })
        });
        assert_eq!(result.0, expected, "{}", result.1);
        assert!(!result.1.contains("unknown"), "{}", result.1);
    }
}

#[test]
fn explicit_route_ranges_and_exclusions_determine_required_fib_coverage() {
    let mut config = inbound();
    config["route_address"] = json!(["203.0.113.0/24", "2001:db8::/32"]);
    config["route_exclude_address"] = json!("203.0.113.0/25");
    let rules = normal_rules(2022, 9000, Family::V4);
    assert!(
        check(
            &config,
            true,
            &rules,
            "203.0.113.128/26 dev magicnet0\n203.0.113.192/26 dev magicnet0\n"
        )
        .0
    );
    assert!(!check(&config, true, &rules, "203.0.113.128/26 dev magicnet0\n").0);
    assert!(!check(&config, true, &rules, "172.19.0.0/30 dev magicnet0\n").0);
    config["route_exclude_address"] = json!(["203.0.113.0/24"]);
    let result = auto_route_check_with(&config, true, |args| {
        assert!(
            args.contains(&"rule"),
            "fully excluded policy needs no FIB route"
        );
        Ok(rule_snapshot(args, &rules))
    });
    assert_eq!(result.0, Some(true));
    assert!(result.1.contains("ipv4_fib=not_required"));
}

#[test]
fn dynamic_ranges_are_unknown_only_when_they_determine_tun_fib() {
    let mut config = inbound();
    config["route_address_set"] = json!(["PRIVATE-ROUTE-SET-CANARY"]);
    for redirect in [false, true] {
        config["auto_redirect"] = json!(redirect);
        let result = auto_route_check_with(&config, true, |args| {
            Ok(if args.contains(&"rule") {
                if redirect {
                    rule_snapshot(
                        args,
                        &redirect_rules(2022, 9000, 32768, 0x400000, 0x200000, 0xe00000),
                    )
                } else {
                    rule_snapshot(args, &normal_rules(2022, 9000, Family::V4))
                }
            } else {
                ROUTES4.into()
            })
        });
        assert_eq!(result.0, if redirect { Some(true) } else { None });
        assert!(!result.1.contains("PRIVATE-ROUTE-SET-CANARY"));
        if !redirect {
            assert!(result
                .1
                .contains("ipv4_fib=unknown:dynamic-route-ranges-unobserved"));
        }
    }
}

#[test]
fn unbounded_or_invalid_static_route_policy_stays_unknown() {
    for addresses in [
        json!(["203.0.113.0/99"]),
        json!(vec!["203.0.113.0/24"; 1025]),
    ] {
        let mut config = inbound();
        config["route_address"] = addresses;
        let result = auto_route_check_with(&config, true, |args| {
            assert!(args.contains(&"rule"));
            Ok(rule_snapshot(args, &normal_rules(2022, 9000, Family::V4)))
        });
        assert_eq!(result.0, None);
        assert!(result.1.contains("ipv4_fib=unknown:route-address-"));
    }
}

#[test]
fn bounded_snapshot_rejects_failed_truncated_and_timed_out_commands() {
    for (script, timeout, limit, reason) in [
        (
            "printf '0: from all lookup 255\\n'; exit 1",
            Duration::from_secs(1),
            1024,
            "command-failed",
        ),
        (
            "printf '01234567890123456789'",
            Duration::from_secs(1),
            8,
            "output-truncated",
        ),
        (
            "printf '0: from all lookup 255\\n'; sleep 2",
            Duration::from_millis(80),
            1024,
            "deadline",
        ),
        (
            "printf 'warning-canary' >&2",
            Duration::from_secs(1),
            1024,
            "command-warning",
        ),
    ] {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        let start = Instant::now();
        let result = read_snapshot(command, timeout, limit);
        assert_eq!(result, Err(reason));
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
