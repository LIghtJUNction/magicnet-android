//! Explicit local inspection, separate from the privacy-safe `sub.status` API.
use std::fs;
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    envelope, sub_status_data, App, MachineError, SUBSCRIPTION_STATUS, SUBSCRIPTION_TRANSACTION,
};
use crate::subscriptions::{observe_source_configuration, SourceConfiguration};
use crate::utils::{clean_module_lines_bounded, read_json_file_bounded};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const INSPECTION_ERROR: MachineError = MachineError {
    code: "machine.subscription_observation_failed",
    message: "unable to inspect subscription configuration",
};

pub(super) fn owner_running(owner: &str) -> Option<bool> {
    match owner {
        "active" => Some(true),
        "none" | "stale" => Some(false),
        _ => None,
    }
}

pub(super) fn cache_counts(path: &Path) -> (usize, usize) {
    let Ok(entries) = fs::read_dir(path) else {
        return (0, 0);
    };
    entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .fold((0, 0), |(sources, provenance), entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            (
                sources + usize::from(name.ends_with(".yaml")),
                provenance + usize::from(name.ends_with(".yaml.identity")),
            )
        })
}

pub(super) fn inspect(app: &App) -> Result<Value, MachineError> {
    let source = observe_sources(app)?;
    let user_agent = clean_module_lines_bounded(
        app,
        Path::new(".config/sing-box/subscription.user-agent"),
        1024,
    )
    .map_err(|_| INSPECTION_ERROR)?
    .into_iter()
    .next()
    .unwrap_or_default();
    let filters = clean_module_lines_bounded(
        app,
        Path::new(".config/sing-box/subscription-filter.list"),
        8192,
    )
    .map_err(|_| INSPECTION_ERROR)?;
    if filters.len() > 32 {
        return Err(INSPECTION_ERROR);
    }
    let transaction = app.moddir.join(SUBSCRIPTION_TRANSACTION).exists();
    let generation = crate::read_kv(app.moddir.join(SUBSCRIPTION_STATUS));
    let mut data = sub_status_data(app, &source);
    let usage = if data["source"]["mode"] == "local_file" {
        Vec::new()
    } else {
        source_usage(
            app,
            &source.urls,
            data["last"]["result"].as_str().unwrap_or("unknown"),
        )
    };
    // This is not an OS-atomic snapshot. Reject detected configuration or
    // generation changes instead of assigning another provider's quota.
    if transaction != app.moddir.join(SUBSCRIPTION_TRANSACTION).exists()
        || generation != crate::read_kv(app.moddir.join(SUBSCRIPTION_STATUS))
        || source != observe_sources(app)?
    {
        return Err(MachineError {
            code: "machine.snapshot_changed",
            message: "subscription changed during observation",
        });
    }
    data["configuration"] =
        json!({"sing_box_urls": source.urls, "user_agent": user_agent, "filters": filters});
    data["source_usage"] = json!(usage);
    Ok(envelope("sub.inspect", data))
}

pub(super) fn observe_sources(app: &App) -> Result<SourceConfiguration, MachineError> {
    observe_source_configuration(app).map_err(|_| INSPECTION_ERROR)
}

fn safe_count(value: &Value, key: &str) -> Option<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
}

fn source_usage(app: &App, urls: &[String], result: &str) -> Vec<Value> {
    let pending = app.moddir.join(SUBSCRIPTION_TRANSACTION).exists();
    let force_cached = matches!(result, "failed" | "interrupted");
    urls.iter().enumerate().map(|(index, url)| {
        let identity = crate::subscriptions::canonical_subscription_url(url)
            .unwrap_or_else(|_| url.clone());
        let id = format!("{:x}", Sha256::digest(identity.as_bytes()));
        let source = app.moddir.join(".state/sing-box/subscription-work/sources")
            .join(format!("{id}.yaml"));
        let valid_source = fs::symlink_metadata(&source)
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0);
        let usage = if !pending && valid_source {
            read_json_file_bounded(&source.with_extension("yaml.usage.json"), 2048)
        } else { None };
        let usage = usage.unwrap_or(Value::Null);
        let state = match usage["state"].as_str() {
            Some("fresh") if !force_cached => "fresh",
            Some("fresh" | "cached") => "cached",
            _ => "unknown",
        };
        let count = |key| if state == "unknown" { None } else { safe_count(&usage, key) };
        json!({
            "id": id, "index": index + 1,
            "hostname": crate::subscriptions::subscription_display_hostname(url).unwrap_or_default(),
            "state": state,
            "upload_bytes": count("upload_bytes"), "download_bytes": count("download_bytes"),
            "total_bytes": count("total_bytes"),
            "expire_epoch": count("expire_epoch").filter(|value| *value > 0 && *value <= 253_402_300_799),
            "updated_epoch": count("updated_epoch").filter(|value| *value > 0 && *value <= 253_402_300_799),
        })
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBSCRIPTION_URL: &str = ".config/sing-box/subscription.url";
    const MAX_CONFIG_BYTES: u64 = 64 * 1024;

    #[test]
    fn usage_is_bound_to_the_url_hash_not_list_position() {
        let (root, app) = super::super::tests::fixture();
        let urls = vec![
            "https://first.example/sub?token=PRIVATE".to_string(),
            "https://second.example/sub".to_string(),
        ];
        let id = format!("{:x}", Sha256::digest(urls[0].as_bytes()));
        let directory = root.join(".state/sing-box/subscription-work/sources");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(format!("{id}.yaml")), "proxies: []").unwrap();
        fs::write(directory.join(format!("{id}.yaml.usage.json")), r#"{"state":"fresh","upload_bytes":3,"download_bytes":7,"total_bytes":100,"expire_epoch":-1}"#).unwrap();
        let usage = source_usage(&app, &urls, "success");
        assert_eq!(usage[0]["total_bytes"], 100);
        assert_eq!(usage[0]["hostname"], "first.example");
        assert_eq!(usage[1]["state"], "unknown");
        assert!(usage[0]["expire_epoch"].is_null());
        assert!(!json!(usage).to_string().contains("PRIVATE"));
        let reversed = source_usage(&app, &[urls[1].clone(), urls[0].clone()], "failed");
        assert_eq!(reversed[1]["total_bytes"], 100);
        assert_eq!(reversed[1]["state"], "cached");
        fs::create_dir_all(root.join(SUBSCRIPTION_TRANSACTION)).unwrap();
        assert!(source_usage(&app, &urls, "success")
            .iter()
            .all(|row| row["total_bytes"].is_null()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspect_is_explicit_while_generic_status_stays_redacted() {
        let (root, app) = super::super::tests::fixture();
        fs::write(
            root.join(SUBSCRIPTION_URL),
            "https://provider.example/sub?token=PRIVATE\n",
        )
        .unwrap();
        fs::write(
            root.join(".config/sing-box/subscription.user-agent"),
            "client=1\n",
        )
        .unwrap();
        fs::write(
            root.join(".config/sing-box/subscription-filter.list"),
            "HK\nfree\n",
        )
        .unwrap();
        let value = inspect(&app).unwrap();
        assert_eq!(value["command"], "sub.inspect");
        assert_eq!(
            value["data"]["configuration"]["filters"],
            json!(["HK", "free"])
        );
        assert!(value.to_string().contains("PRIVATE"));
        let status = super::super::sub_status_value(&app).unwrap().to_string();
        assert!(!status.contains("PRIVATE"));
        assert!(!status.contains("provider.example"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_inspect_fails_on_symlink_or_oversized_config_without_echo() {
        let (root, app) = super::super::tests::fixture();
        let path = root.join(SUBSCRIPTION_URL);
        fs::write(&path, "s".repeat(MAX_CONFIG_BYTES as usize + 1)).unwrap();
        assert_eq!(inspect(&app).unwrap_err(), INSPECTION_ERROR);
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
        assert_eq!(inspect(&app).unwrap_err(), INSPECTION_ERROR);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn subscription_readers_reject_invalid_sources_without_leaking_or_writing() {
        for name in ["subscription.url", "subscription.local"] {
            let (root, app) = super::super::tests::fixture();
            let path = root.join(".config/sing-box").join(name);
            let limit = if name.ends_with(".url") {
                64 * 1024
            } else {
                8 * 1024 * 1024
            };
            let reject = || {
                for command in ["status", "inspect"] {
                    let error = super::super::machine_value(&app, &["sub", command])
                        .expect_err("invalid source must not look unconfigured");
                    assert_eq!(error, INSPECTION_ERROR);
                    assert!(!format!("{error:?}").contains("SOURCE-CANARY"));
                }
                assert!(!root.join(".state").exists());
            };

            for bytes in [b"SOURCE-CANARY\xff".as_slice(), b"# SOURCE-CANARY\0\n"] {
                fs::write(&path, bytes).unwrap();
                reject();
                assert_eq!(fs::read(&path).unwrap(), bytes);
            }
            fs::write(&path, "x".repeat(limit + 1)).unwrap();
            reject();
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            reject();
            fs::remove_dir(&path).unwrap();

            let outside = root.join("SOURCE-CANARY");
            fs::write(&outside, "preserved").unwrap();
            std::os::unix::fs::symlink(&outside, &path).unwrap();
            reject();
            fs::remove_file(&path).unwrap();
            fs::hard_link(&outside, &path).unwrap();
            reject();
            assert_eq!(fs::read_to_string(&outside).unwrap(), "preserved");
            fs::remove_file(&path).unwrap();

            use std::os::unix::ffi::OsStrExt;
            let fifo = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            reject();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn subscription_readers_accept_exact_bounds_and_detect_local_source_replacement() {
        let (root, app) = super::super::tests::fixture();
        let urls = root.join(SUBSCRIPTION_URL);
        fs::write(&urls, format!("#{}", "x".repeat(64 * 1024 - 1))).unwrap();
        let local = root.join(".config/sing-box/subscription.local");
        fs::write(&local, "x".repeat(8 * 1024 * 1024)).unwrap();
        for command in ["status", "inspect"] {
            let value = super::super::machine_value(&app, &["sub", command]).unwrap();
            assert_eq!(value["data"]["source"]["mode"], "local_file");
            assert_eq!(value["data"]["source"]["configured_count"], 1);
        }
        let before = observe_sources(&app).unwrap();
        fs::write(&local, "a new local subscription").unwrap();
        let after = observe_sources(&app).unwrap();
        assert_eq!(before.mode(), after.mode());
        assert_eq!(before.configured_count(), after.configured_count());
        assert!(
            before != after,
            "same mode must not conceal changed local bytes"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn service_keeps_independent_evidence_when_subscription_intent_is_unreadable() {
        let (root, app) = super::super::tests::fixture();
        fs::write(root.join(SUBSCRIPTION_URL), b"SOURCE-CANARY\xff").unwrap();
        let value = super::super::service_status_value(&app);
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"]["subscription"]["source"], "unknown");
        assert!(value["data"]["core"].is_object());
        assert!(!value.to_string().contains("SOURCE-CANARY"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incomplete_owner_evidence_is_never_reported_running() {
        assert_eq!(owner_running("active"), Some(true));
        assert_eq!(owner_running("stale"), Some(false));
        assert_eq!(owner_running("pending"), None);
        assert_eq!(owner_running("unknown"), None);
    }
}
