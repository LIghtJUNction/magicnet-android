use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::Path;

use crate::node_delay::node_delay;
use crate::webui_api::select_proxy;
use crate::App;
use serde_json::Value;

pub(crate) fn node_cmd(app: &App, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str).unwrap_or("list") {
        "list" => {
            node_list(app);
            Ok(())
        }
        "current" => node_current(app),
        "use" => {
            let name = args[1..].join(" ");
            node_use(app, &name)
        }
        "test" => {
            let name = args[1..].join(" ");
            node_test(app, &name)
        }
        "test-all" => node_test_all(app, &args[1..]),
        _ => Err("Usage: cli node {list|current|use|test <name>|test-all [name ...]}".to_string()),
    }
}

fn node_list(app: &App) {
    let limit = env::var("MAGICNET_NODE_LIST_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.min(500))
        .unwrap_or(48);
    let cache = app.moddir.join(".cache/magicnet-node-list.cache");
    let cache_enabled = env::var("MAGICNET_NODE_CACHE").unwrap_or_else(|_| "1".to_string()) != "0";
    let names = resolve_node_names(app, limit, cache_enabled, &cache);
    if !names.is_empty() {
        let text = format!("{}\n", names.join("\n"));
        print!("{text}");
    }
}

fn node_current(app: &App) -> Result<(), String> {
    let proxy = read_proxy_selector(app)?;
    let current = proxy
        .get("now")
        .and_then(Value::as_str)
        .or_else(|| proxy.get("selected").and_then(Value::as_str))
        .unwrap_or("");
    if current.is_empty() {
        return Err("current node is not reported by sing-box API".to_string());
    }
    println!("{current}");
    Ok(())
}

fn node_use(app: &App, name: &str) -> Result<(), String> {
    let clean = name.trim();
    if clean.is_empty() {
        return Err("Usage: cli node use <name>".to_string());
    }
    select_proxy(app, "proxy", clean)
}

fn node_test(app: &App, name: &str) -> Result<(), String> {
    let clean = name.trim();
    if clean.is_empty() {
        return Err("Usage: cli node test <name>".to_string());
    }
    let delay = node_delay(app, clean).map_err(|err| format!("test node failed: {err}"))?;
    println!("{clean}={delay}ms");
    Ok(())
}

fn node_test_all(app: &App, args: &[String]) -> Result<(), String> {
    let nodes = test_all_targets(app, args);
    if nodes.is_empty() {
        return Err("Usage: cli node test-all [name ...]".to_string());
    }
    let total = nodes.len();
    let mut failed = 0usize;
    for node in nodes {
        match node_delay(app, &node) {
            Ok(delay) => println!("{node}={delay}ms"),
            Err(err) => {
                failed += 1;
                println!("{node}=error: {err}");
            }
        }
    }
    node_test_all_status(total.saturating_sub(failed), failed)
}

fn node_test_all_status(successful: usize, failed: usize) -> Result<(), String> {
    if successful == 0 && failed > 0 {
        Err(format!("{failed} node tests failed"))
    } else {
        if failed > 0 {
            eprintln!("[warning] {failed} node tests failed; {successful} node tests succeeded");
        }
        Ok(())
    }
}

fn test_all_targets(app: &App, args: &[String]) -> Vec<String> {
    if !args.is_empty() {
        return args
            .iter()
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    let cache = app.moddir.join(".cache/magicnet-node-list.cache");
    resolve_node_names(app, 16, true, &cache)
}

fn read_proxy_selector(app: &App) -> Result<Value, String> {
    let bytes =
        crate::webui_api::api_response(app, "GET", "/proxies/proxy", "", 5, 8 * 1024 * 1024)
            .map_err(|error| format!("read proxy selector failed: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse proxy selector: {error}"))
}

fn resolve_node_names(app: &App, limit: usize, cache_enabled: bool, cache: &Path) -> Vec<String> {
    if let Some(names) = scan_node_names(app, limit) {
        refresh_node_cache(cache, &names);
        return names;
    }
    if cache_enabled {
        return read_node_cache(cache, limit).unwrap_or_default();
    }
    Vec::new()
}

fn scan_node_names(app: &App, limit: usize) -> Option<Vec<String>> {
    // Only the active configuration defines the current candidates. Legacy work
    // tags and staged configurations can describe nodes removed by exclusions.
    let config = app.moddir.join(".config/sing-box/config.json");
    let text = fs::read_to_string(config).ok()?;
    let json = serde_json::from_str::<Value>(&text).ok()?;
    let outbounds = match json.as_object()?.get("outbounds") {
        None | Some(Value::Null) => return Some(Vec::new()),
        Some(value) => value.as_array()?,
    };
    let proxy_members = proxy_member_tags(outbounds);
    let mut names = Vec::new();
    for outbound in outbounds {
        let Some(name) = outbound.get("tag").and_then(Value::as_str) else {
            continue;
        };
        if is_real_outbound(outbound)
            && proxy_members
                .as_ref()
                .is_none_or(|members| members.contains(name))
        {
            push_node(name, limit, &mut names);
            if names.len() >= limit {
                break;
            }
        }
    }
    // An observed empty configuration is authoritative, not a cache miss.
    Some(names)
}

fn push_node(name: &str, limit: usize, names: &mut Vec<String>) {
    if name.is_empty() || is_builtin_node(name) || is_reserved_group(name) {
        return;
    }
    if !names.iter().any(|item| item == name) {
        names.push(name.to_string());
        if names.len() >= limit {
            names.truncate(limit);
        }
    }
}

fn read_node_cache(cache: &Path, limit: usize) -> Option<Vec<String>> {
    let text = fs::read_to_string(cache).ok()?;
    let mut names = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        push_node(line, limit, &mut names);
        if names.len() >= limit {
            break;
        }
    }
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

fn refresh_node_cache(cache: &Path, names: &[String]) {
    if let Some(parent) = cache.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let text = format!("{}\n", names.join("\n"));
    let _ = fs::write(cache, text);
}

fn proxy_member_tags(outbounds: &[Value]) -> Option<HashSet<&str>> {
    let proxy = outbounds.iter().find(|item| item["tag"] == "proxy")?;
    // A present selector with no members is an authoritative empty list.
    Some(
        proxy["outbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect(),
    )
}

fn is_real_outbound(outbound: &Value) -> bool {
    let Some(outbound_type) = outbound.get("type").and_then(Value::as_str) else {
        return false;
    };
    !matches!(
        outbound_type,
        "" | "selector" | "urltest" | "direct" | "block" | "dns"
    )
}

fn is_builtin_node(name: &str) -> bool {
    matches!(
        name,
        "" | "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "COMPATIBLE" | "direct" | "block"
    )
}

fn is_reserved_group(name: &str) -> bool {
    matches!(
        name,
        "GLOBAL"
            | "Global"
            | "global"
            | "proxy"
            | "chain"
            | "chain-hop1"
            | "chain-exit"
            | "chain-auto"
            | "select"
            | "lan"
            | "ad-block"
            | "cn-direct"
            | "apple-cn"
            | "microsoft-cn"
            | "google-cn"
            | "icloud"
            | "bing"
            | "network-test"
            | "ai-proxy"
            | "proxy-rule"
            | "dev-proxy"
            | "social-proxy"
            | "download-direct"
            | "media-proxy"
            | "game-proxy"
            | "telegram-proxy"
            | "google-proxy"
            | "youtube-proxy"
            | "github-proxy"
            | "discord-proxy"
            | "netflix-proxy"
            | "spotify-proxy"
            | "twitter-proxy"
            | "whatsapp-proxy"
            | "final"
    ) || name.starts_with("magicnet-chain-")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::test_support::temp_app;

    fn write_file(path: impl AsRef<Path>, text: &str) {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, text).unwrap();
    }

    fn resolve_config_nodes(config: &str) -> Vec<String> {
        let app = temp_app();
        write_file(app.moddir.join(".config/sing-box/config.json"), config);
        resolve_node_names(
            &app,
            48,
            false,
            &app.moddir.join(".cache/magicnet-node-list.cache"),
        )
    }

    #[test]
    fn compact_config_json_skips_selector_groups_and_keeps_real_nodes() {
        let names = resolve_config_nodes(
            r#"{"outbounds":[{"tag":"dns-guard","type":"selector","outbounds":["alpha"]},{"tag":"alpha","type":"shadowsocks"},{"tag":"beta","type":"vless"}]}"#,
        );

        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn proxy_selector_members_control_included_nodes() {
        let names = resolve_config_nodes(
            r#"{"outbounds":[{"tag":"dns-guard","type":"selector","outbounds":["alpha"]},{"tag":"proxy","type":"selector","outbounds":["alpha","beta"]},{"tag":"alpha","type":"shadowsocks"},{"tag":"beta","type":"vless"},{"tag":"gamma","type":"trojan"}]}"#,
        );

        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn node_labels_survive_scan_cache_and_default_tests() {
        let app = temp_app();
        let active = app.moddir.join(".config/sing-box/config.json");
        let cache = app.moddir.join(".cache/magicnet-node-list.cache");
        let expected = [
            "[HK] 香港-选择",
            "策略优化",
            "US-fallback-01",
            "Selector-node",
            "URLTest-node",
        ];
        let mut outbounds: Vec<Value> = expected
            .iter()
            .map(|tag| serde_json::json!({"tag": tag, "type": "trojan"}))
            .collect();
        outbounds.extend([
            serde_json::json!({"tag": "ordinary-group", "type": "selector", "outbounds": expected}),
            serde_json::json!({"tag": "fast-group", "type": "urltest", "outbounds": expected}),
            serde_json::json!({"tag": "plain-direct", "type": "direct"}),
            serde_json::json!({"tag": "plain-block", "type": "block"}),
            serde_json::json!({"tag": "plain-dns", "type": "dns"}),
            serde_json::json!({"tag": "magicnet-chain-exit::US-fallback-01", "type": "trojan"}),
        ]);
        write_file(
            &active,
            &serde_json::json!({"outbounds": outbounds}).to_string(),
        );

        assert_eq!(resolve_node_names(&app, 48, true, &cache), expected);
        assert_eq!(test_all_targets(&app, &[]), expected);
        fs::remove_file(active).unwrap();
        assert_eq!(resolve_node_names(&app, 48, true, &cache), expected);
        assert_eq!(resolve_node_names(&app, 1, true, &cache), &expected[..1]);
        assert!(resolve_node_names(&app, 0, true, &cache).is_empty());
    }

    #[test]
    fn explicit_empty_proxy_members_do_not_expose_unselected_nodes() {
        let app = temp_app();
        let active = app.moddir.join(".config/sing-box/config.json");
        let cache = app.moddir.join(".cache/magicnet-node-list.cache");
        for proxy in [
            serde_json::json!({"tag": "proxy", "type": "selector", "outbounds": []}),
            serde_json::json!({"tag": "proxy", "type": "selector", "outbounds": null}),
            serde_json::json!({"tag": "proxy", "type": "selector"}),
            serde_json::json!({"tag": "proxy", "type": "urltest", "outbounds": []}),
        ] {
            write_file(
                &active,
                &serde_json::json!({"outbounds": [
                    proxy, {"tag": "unselected", "type": "trojan"}
                ]})
                .to_string(),
            );
            write_file(&cache, "retired\n");

            assert!(resolve_node_names(&app, 48, true, &cache).is_empty());
            assert!(test_all_targets(&app, &[]).is_empty());
            assert_eq!(fs::read_to_string(&cache).unwrap(), "\n");
        }
    }

    #[test]
    fn proxy_members_include_labels_but_exclude_internal_nodes_and_group_leaves() {
        let names = resolve_config_nodes(
            r#"{"outbounds":[
            {"tag":"proxy","type":"selector","outbounds":["US-fallback-01","ordinary-group","magicnet-chain-exit::US-fallback-01","missing"]},
            {"tag":"US-fallback-01","type":"trojan"},
            {"tag":"ordinary-group","type":"urltest","outbounds":["nested-leaf"]},
            {"tag":"nested-leaf","type":"vless"},
            {"tag":"magicnet-chain-exit::US-fallback-01","type":"trojan"}
        ]}"#,
        );
        assert_eq!(names, ["US-fallback-01"]);
    }

    #[test]
    fn active_config_nodes_ignore_retired_work_tags_at_every_list_limit() {
        let app = temp_app();
        let cache = app.moddir.join(".cache/magicnet-node-list.cache");
        let retired = (0..48)
            .map(|index| format!("HK-retired-{index:02}\n"))
            .collect::<String>();
        write_file(
            app.moddir
                .join(".state/sing-box/subscription-work/tags.txt"),
            &retired,
        );
        write_file(&cache, &retired);
        write_file(
            app.moddir.join(".config/sing-box/config.json"),
            r#"{"outbounds":[{"tag":"proxy","type":"selector","outbounds":["JP-test","US-test"]},{"tag":"JP-test","type":"trojan"},{"tag":"JP-test","type":"trojan"},{"tag":"US-test","type":"trojan"},{"tag":"HK-hidden","type":"trojan"}]}"#,
        );
        write_file(
            app.moddir
                .join(".config/sing-box/config.json.candidate-test"),
            r#"{"outbounds":[{"tag":"HK-staged","type":"trojan"}]}"#,
        );
        for limit in [48, 1, 2, 0, 500] {
            let expected: Vec<_> = ["JP-test", "US-test"]
                .into_iter()
                .take(limit)
                .map(str::to_owned)
                .collect();
            let names = resolve_node_names(&app, limit, true, &cache);
            assert_eq!(
                names, expected,
                "retired work tags displaced the active configuration at limit {limit}"
            );
            assert_eq!(
                fs::read_to_string(&cache).unwrap(),
                format!("{}\n", expected.join("\n"))
            );
        }
    }

    #[test]
    fn valid_empty_config_does_not_revive_cached_or_staged_nodes() {
        let app = temp_app();
        let cache = app.moddir.join(".cache/magicnet-node-list.cache");
        write_file(
            app.moddir
                .join(".state/sing-box/subscription-work/tags.txt"),
            "HK-retired\n",
        );
        write_file(
            app.moddir
                .join(".config/sing-box/config.json.candidate-test"),
            r#"{"outbounds":[{"tag":"HK-staged","type":"trojan"}]}"#,
        );
        for config in [
            r#"{}"#,
            r#"{"outbounds":null}"#,
            r#"{"outbounds":[]}"#,
            r#"{"outbounds":[{"tag":"direct","type":"direct"}]}"#,
            r#"{"outbounds":[{"tag":"proxy","type":"selector","outbounds":["block"]},{"tag":"block","type":"block"}]}"#,
        ] {
            write_file(app.moddir.join(".config/sing-box/config.json"), config);
            write_file(&cache, "HK-cached\n");
            assert!(resolve_node_names(&app, 48, true, &cache).is_empty());
            assert_eq!(fs::read_to_string(&cache).unwrap(), "\n");
        }
    }

    #[test]
    fn stale_cache_does_not_override_current_scan() {
        let app = temp_app();
        write_file(
            app.moddir.join(".cache/magicnet-node-list.cache"),
            "stale\n",
        );
        write_file(
            app.moddir.join(".config/sing-box/config.json"),
            r#"{"outbounds":[{"tag":"current","type":"shadowsocks"}]}"#,
        );

        let cache = app.moddir.join(".cache/magicnet-node-list.cache");
        let names = resolve_node_names(&app, 48, true, &cache);

        assert_eq!(names, vec!["current".to_string()]);
        assert_eq!(fs::read_to_string(cache).unwrap(), "current\n");
    }

    #[test]
    fn cache_fallback_is_used_only_when_active_config_is_unavailable() {
        let app = temp_app();
        let cache = app.moddir.join(".cache/magicnet-node-list.cache");
        let active = app.moddir.join(".config/sing-box/config.json");
        write_file(&cache, "cached\n");
        write_file(
            app.moddir
                .join(".state/sing-box/subscription-work/tags.txt"),
            "HK-retired\n",
        );
        write_file(
            app.moddir
                .join(".config/sing-box/config.json.candidate-test"),
            r#"{"outbounds":[{"tag":"HK-staged","type":"trojan"}]}"#,
        );
        for config in [
            None,
            Some("invalid-json"),
            Some(r#"{"outbounds":"invalid"}"#),
            Some("[]"),
            Some("null"),
        ] {
            if let Some(config) = config {
                write_file(&active, config);
            }
            assert_eq!(
                resolve_node_names(&app, 48, true, &cache),
                vec!["cached".to_string()]
            );
            assert!(resolve_node_names(&app, 48, false, &cache).is_empty());
        }
    }

    #[test]
    fn test_all_uses_explicit_targets_when_present() {
        let app = temp_app();
        let names = test_all_targets(&app, &["alpha".to_string(), " beta ".to_string()]);
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn partial_node_batch_is_not_reported_as_total_failure() {
        assert!(node_test_all_status(3, 1).is_ok());
    }

    #[test]
    fn all_failed_node_batch_still_reports_failure() {
        assert!(node_test_all_status(0, 4).is_err());
    }
}
