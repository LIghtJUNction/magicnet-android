use super::*;
use serde_json::json;

fn inventory() -> Snapshot {
    Snapshot {
        config: json!({"outbounds":[
            {"type":"selector","tag":"proxy","outbounds":["node-a","node-b"]},
            {"type":"selector","tag":"ai-proxy","outbounds":["node-a","node-b"]},
            {"type":"selector","tag":"restricted-ai","outbounds":["node-a"]},
            {"type":"selector","tag":"already-other","outbounds":["node-a","node-b"]},
            {"type":"selector","tag":"indirect","outbounds":["proxy","node-b"]},
            {"type":"vmess","tag":"node-a"},
            {"type":"vmess","tag":"node-b"}
        ]}),
        proxies: json!({"proxies":{
            "proxy":{"type":"Selector","now":"node-a","all":["node-a","node-b"]},
            "ai-proxy":{"type":"Selector","now":"node-a","all":["node-a","node-b"]},
            "restricted-ai":{"type":"Selector","now":"node-a","all":["node-a"]},
            "already-other":{"type":"Selector","now":"node-b","all":["node-a","node-b"]},
            "indirect":{"type":"Selector","now":"proxy","all":["proxy","node-b"]},
            "node-a":{"type":"VMess"},"node-b":{"type":"VMess"}
        }}),
    }
}

#[test]
fn strict_capability_and_get_status_are_required_even_for_a_zero_millisecond_probe() {
    let success = parse_strict_probe(
        br#"{"strict_probe":true,"expected_status":204,"ok":true,"http_status":204,"delay":0}"#,
    );
    assert!(success.ok);
    assert_eq!(success.millis, Some(0));
    for bytes in [br#"{"delay":12}"#.as_slice(), br#"{"message":"Timeout"}"#] {
        let observation = parse_strict_probe(bytes);
        assert_eq!(observation.reason, "probe_unsupported");
        assert!(!observation.conclusive());
    }
    for value in [
        json!({"strict_probe":true,"expected_status":204,"ok":true,"http_status":200,"delay":1}),
        json!({"strict_probe":true,"expected_status":204,"ok":true,"http_status":204}),
        json!({"strict_probe":true,"expected_status":204,"ok":true,"http_status":204,"delay":4001}),
        json!({"strict_probe":true,"expected_status":204,"ok":false,"reason":"unknown","http_status":null}),
        json!({"strict_probe":true,"expected_status":204,"ok":false,"reason":"http_status","http_status":204}),
        json!({"strict_probe":true,"expected_status":204,"ok":false,"reason":"http_status","http_status":null}),
    ] {
        let observation = parse_strict_probe(&serde_json::to_vec(&value).unwrap());
        assert_eq!(observation.reason, "probe_invalid", "{value}");
        assert!(!observation.conclusive());
    }
}

#[test]
fn strict_failures_are_conclusive_only_when_the_core_returned_a_supported_result() {
    for (reason, expected, conclusive, status) in [
        ("timeout", "timeout", true, None),
        ("transport_failure", "transport_failure", true, None),
        ("http_status", "http_error", true, Some(403)),
        ("cancelled", "probe_unavailable", false, None),
    ] {
        let value = json!({"strict_probe":true,"expected_status":204,"ok":false,"reason":reason,"http_status":status});
        let observation = parse_strict_probe(&serde_json::to_vec(&value).unwrap());
        assert!(!observation.ok);
        assert_eq!(observation.reason, expected);
        assert_eq!(observation.conclusive(), conclusive);
        assert_eq!(observation.http, status);
    }
}

#[test]
fn failover_candidates_are_real_members_of_both_configured_and_live_groups() {
    let mut snapshot = inventory();
    assert_eq!(
        candidates(&snapshot),
        Some(("node-a".into(), vec!["node-b".into()]))
    );
    snapshot.proxies["proxies"]["proxy"]["all"] = json!(["node-a"]);
    assert!(candidates(&snapshot).is_none());
    snapshot = inventory();
    snapshot.config["outbounds"][0]["outbounds"] = json!(["node-a"]);
    assert!(candidates(&snapshot).is_none());
    snapshot = inventory();
    snapshot.proxies["proxies"]["node-b"]["type"] = json!("Selector");
    assert!(candidates(&snapshot).is_none());
    snapshot = inventory();
    snapshot.config["outbounds"][6]["detour"] = json!("node-a");
    assert!(candidates(&snapshot).is_none());
}

#[test]
fn direct_block_automatic_groups_and_chain_members_are_never_failover_candidates() {
    for kind in [
        "direct",
        "block",
        "selector",
        "urltest",
        "wireguard",
        "unknown",
    ] {
        let mut snapshot = inventory();
        snapshot.config["outbounds"][6]["type"] = json!(kind);
        assert!(candidates(&snapshot).is_none(), "{kind}");
    }
    let mut snapshot = inventory();
    snapshot.config["outbounds"][6]["tag"] = json!("magicnet-chain-node-b");
    snapshot.config["outbounds"][0]["outbounds"] = json!(["node-a", "magicnet-chain-node-b"]);
    snapshot.proxies["proxies"]["proxy"]["all"] = json!(["node-a", "magicnet-chain-node-b"]);
    snapshot.proxies["proxies"]["magicnet-chain-node-b"] = json!({"type":"VMess"});
    assert!(candidates(&snapshot).is_none());
    let mut snapshot = inventory();
    snapshot.proxies["proxies"]["proxy"]["now"] = json!("ai-proxy");
    assert!(
        candidates(&snapshot).is_none(),
        "nested selection must not cross group boundaries"
    );
}

#[test]
fn candidate_limit_and_related_selectors_preserve_individual_group_policy() {
    let mut snapshot = inventory();
    for tag in ["node-c", "node-d", "node-e", "node-f"] {
        snapshot.config["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"vmess","tag":tag}));
        snapshot.config["outbounds"][0]["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!(tag));
        snapshot.proxies["proxies"]["proxy"]["all"]
            .as_array_mut()
            .unwrap()
            .push(json!(tag));
        snapshot.proxies["proxies"][tag] = json!({"type":"VMess"});
    }
    assert_eq!(
        candidates(&snapshot).unwrap().1,
        ["node-b", "node-c", "node-d"]
    );
    assert_eq!(
        affected_selectors(&snapshot, "node-a", "node-b").unwrap(),
        ["proxy", "ai-proxy"]
    );
    snapshot.proxies["proxies"]["ai-proxy"]["all"] = json!(["node-a"]);
    assert_eq!(
        affected_selectors(&snapshot, "node-a", "node-b").unwrap(),
        ["proxy"]
    );
}

#[test]
fn ambiguous_configuration_and_oversized_selector_batches_are_rejected() {
    let mut snapshot = inventory();
    let duplicate = snapshot.config["outbounds"][0].clone();
    snapshot.config["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(candidates(&snapshot).is_none());
    let mut snapshot = inventory();
    for index in 0..MAX_SELECTORS {
        let tag = format!("extra-{index}");
        snapshot.config["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"selector","tag":tag,"outbounds":["node-a","node-b"]}));
        snapshot.proxies["proxies"][&tag] =
            json!({"type":"Selector","now":"node-a","all":["node-a","node-b"]});
    }
    assert!(affected_selectors(&snapshot, "node-a", "node-b").is_none());
}
