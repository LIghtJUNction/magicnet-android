use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use crate::selector_store;
use crate::service::apply_config;
use crate::webui_api::{curl_get_json, select_proxy};
use crate::{write_text_file, App};

const POLICY_PATH: &str = ".config/magicnet/proxy-chain.json";
const CHAIN_PREFIX: &str = "magicnet-chain-";

/// A policy edit owns both the desired value and its exact rollback bytes.
struct Policy {
    value: Value,
    previous: Option<Vec<u8>>,
}

impl Policy {
    fn load(app: &App) -> Result<Self, String> {
        let previous = match fs::read(app.moddir.join(POLICY_PATH)) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("read proxy chain policy: {error}")),
        };
        let value = match previous.as_deref() {
            Some(bytes) => serde_json::from_slice(bytes)
                .map_err(|error| format!("parse proxy chain policy: {error}"))?,
            None => default_policy(),
        };
        if !value.is_object() {
            return Err("proxy chain policy must be a JSON object".into());
        }
        Ok(Self { value, previous })
    }

    fn enabled(&self) -> bool {
        self.value["enabled"].as_bool().unwrap_or(false)
    }

    fn commit(&self, app: &App, apply: bool) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&self.value)
            .map_err(|error| format!("encode proxy chain policy: {error}"))?;
        write_text_file(app, Path::new(POLICY_PATH), &format!("{text}\n"))?;
        if apply {
            if let Err(error) = apply_config(app) {
                let restore = match &self.previous {
                    Some(bytes) => write_text_file(
                        app,
                        Path::new(POLICY_PATH),
                        &String::from_utf8_lossy(bytes),
                    ),
                    None => match fs::remove_file(app.moddir.join(POLICY_PATH)) {
                        Ok(()) => Ok(()),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(error) => Err(format!("remove new proxy chain policy: {error}")),
                    },
                };
                let detail = restore
                    .err()
                    .map(|error| format!("; policy restore failed: {error}"))
                    .unwrap_or_default();
                return Err(format!("apply proxy chain policy failed: {error}{detail}"));
            }
        }
        Ok(())
    }
}

pub(crate) fn chain_cmd(app: &App, args: &[String]) -> Result<(), String> {
    let command = args.first().map_or("status", String::as_str);
    match command {
        "status" => chain_status(app),
        "enable" | "disable" => {
            let enabled = command == "enable";
            let mut policy = Policy::load(app)?;
            if enabled
                && ["upstream", "exit"]
                    .iter()
                    .any(|role| role_tags(&policy.value, role).is_empty())
            {
                return Err("set upstream and exit nodes before enabling the proxy chain".into());
            }
            policy.value["enabled"] = json!(enabled);
            policy.commit(app, true)?;
            let member = if enabled {
                "chain".into()
            } else {
                proxy_default_member(app)?
            };
            select_runtime_member(app, "proxy", &member)?;
            println!(
                "[info] proxy chain {}",
                if enabled { "enabled" } else { "disabled" }
            );
            Ok(())
        }
        "set-upstream" | "set-exit" => {
            let role = command.strip_prefix("set-").unwrap();
            let tag = clean_tag(&args[1..].join(" "))?;
            if !base_node_exists(app, &tag)? {
                return Err(format!("proxy node is not available: {tag}"));
            }
            let mut policy = Policy::load(app)?;
            policy.value[role] = json!([tag]);
            policy.commit(app, policy.enabled())?;
            println!("[info] proxy chain {role} node set to {tag}");
            Ok(())
        }
        "clear-upstream" | "clear-exit" => {
            let role = command.strip_prefix("clear-").unwrap();
            let mut policy = Policy::load(app)?;
            if policy.enabled() {
                return Err("disable the proxy chain before clearing a chain role".into());
            }
            policy.value[role] = json!([]);
            policy.commit(app, false)?;
            println!("[info] proxy chain {role} node cleared");
            Ok(())
        }
        "mode" => {
            let mode = args.get(1).map_or("", String::as_str).trim();
            if !matches!(mode, "manual" | "auto") {
                return Err("proxy chain mode must be manual or auto".into());
            }
            let mut policy = Policy::load(app)?;
            policy.value["mode"] = json!(mode);
            policy.commit(app, policy.enabled())?;
            println!("[info] proxy chain mode set to {mode}");
            Ok(())
        }
        "select-upstream" => {
            let tag = clean_tag(&args[1..].join(" "))?;
            let policy = Policy::load(app)?;
            if !role_tags(&policy.value, "upstream").contains(&tag.as_str()) {
                return Err("upstream tag is not in the configured chain role".into());
            }
            select_runtime_member(app, "chain-hop1", &tag)
        }
        "select-exit" => select_exit(app, &args[1..].join(" ")),
        _ => Err(chain_usage()),
    }
}

fn chain_usage() -> String {
    "Usage: cli chain {status|enable|disable|set-upstream <tag>|set-exit <tag>|clear-upstream|clear-exit|mode <manual|auto>|select-upstream <tag>|select-exit <tag>}".into()
}

fn default_policy() -> Value {
    json!({"enabled": false, "mode": "manual", "upstream": [], "exit": []})
}

fn policy_mode(policy: &Value) -> &str {
    policy["mode"]
        .as_str()
        .filter(|mode| matches!(*mode, "manual" | "auto"))
        .unwrap_or("manual")
}

fn role_tags<'a>(policy: &'a Value, role: &str) -> Vec<&'a str> {
    policy[role]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn clean_tag(tag: &str) -> Result<String, String> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Err(chain_usage());
    }
    if tag.chars().any(char::is_control) {
        return Err("proxy node tag contains a control character".into());
    }
    if tag.starts_with(CHAIN_PREFIX) {
        return Err("generated proxy chain tags cannot be used as base nodes".into());
    }
    Ok(tag.into())
}

fn load_singbox_config(app: &App) -> Result<Value, String> {
    let config = fs::read_to_string(app.moddir.join(".config/sing-box/config.json"))
        .map_err(|error| format!("read sing-box config: {error}"))?;
    serde_json::from_str(&config).map_err(|error| format!("parse sing-box config: {error}"))
}

fn outbounds(config: &Value) -> impl Iterator<Item = &Value> {
    config["outbounds"].as_array().into_iter().flatten()
}

fn base_node_exists(app: &App, tag: &str) -> Result<bool, String> {
    let config = load_singbox_config(app)?;
    Ok(!tag.starts_with(CHAIN_PREFIX)
        && outbounds(&config).any(|item| {
            item["tag"].as_str() == Some(tag)
                && matches!(
                    item["type"].as_str(),
                    Some(
                        "shadowsocks"
                            | "vmess"
                            | "vless"
                            | "trojan"
                            | "hysteria2"
                            | "anytls"
                            | "tuic"
                            | "socks"
                    )
                )
        }))
}

fn proxy_default_member(app: &App) -> Result<String, String> {
    let config = load_singbox_config(app)?;
    let member = outbounds(&config)
        .find(|item| item["tag"] == "proxy" && item["type"] == "selector")
        .and_then(|item| item["default"].as_str())
        .filter(|member| {
            !member.is_empty() && *member != "chain" && !member.starts_with(CHAIN_PREFIX)
        })
        .unwrap_or("block")
        .to_string();
    Ok(member)
}

fn select_exit(app: &App, tag: &str) -> Result<(), String> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Err(chain_usage());
    }
    let generated = tag.starts_with("magicnet-chain-exit::");
    let member = if generated {
        tag.into()
    } else {
        format!("magicnet-chain-exit::{}", clean_tag(tag)?)
    };
    if (generated && tag.chars().any(char::is_control)) || !generated_exit_exists(app, &member)? {
        return Err(if generated {
            "generated chain exit is not available".into()
        } else {
            format!("generated chain exit is not available: {tag}")
        });
    }
    select_runtime_member(app, "chain-exit", &member)
}

fn generated_exit_exists(app: &App, tag: &str) -> Result<bool, String> {
    let config = load_singbox_config(app)?;
    let exists = outbounds(&config)
        .any(|item| item["tag"].as_str() == Some(tag) && item["detour"] == "chain-hop1");
    Ok(exists)
}

fn select_runtime_member(app: &App, group: &str, member: &str) -> Result<(), String> {
    if curl_get_json(app, "/proxies").is_ok() {
        select_proxy(app, group, member)
    } else {
        selector_store::save(app, group, member)
            .map_err(|error| format!("persist proxy chain selector: {error}"))
    }
}

fn chain_status(app: &App) -> Result<(), String> {
    let policy = Policy::load(app)?;
    println!("enabled={}", policy.enabled());
    println!("mode={}", policy_mode(&policy.value));
    for role in ["upstream", "exit"] {
        let tags = role_tags(&policy.value, role);
        println!(
            "{role}={}",
            if tags.is_empty() {
                "none".into()
            } else {
                tags.join(",")
            }
        );
    }
    match curl_get_json(app, "/proxies") {
        Ok(runtime) => {
            println!("runtime=available");
            for group in ["proxy", "chain", "chain-hop1", "chain-exit"] {
                if let Some(now) = runtime["proxies"][group]["now"].as_str() {
                    println!("runtime.{group}={now}");
                }
            }
        }
        Err(_) => println!("runtime=unavailable"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{clean_tag, default_policy, policy_mode};

    #[test]
    fn default_policy_starts_disabled_and_manual() {
        let policy = default_policy();
        assert!(!policy["enabled"].as_bool().unwrap_or(true));
        assert_eq!(policy_mode(&policy), "manual");
    }

    #[test]
    fn clean_tag_rejects_generated_chain_tags() {
        assert!(clean_tag("magicnet-chain-exit::node-a").is_err());
    }

    #[test]
    fn clean_tag_preserves_node_names_with_spaces() {
        assert_eq!(clean_tag("  node a  ").unwrap(), "node a");
    }
}
