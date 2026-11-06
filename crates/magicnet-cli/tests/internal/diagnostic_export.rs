use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn config_projection_preserves_route_references_without_private_values() {
    let config = json!({
        "inbounds": [{"type":"tun", "tag":"tun-in", "mtu":1400, "exclude_uid":[0, 10112]}],
        "outbounds": [{"type":"vless", "tag":"PRIVATE-NODE", "server":"private.example.invalid", "password":"TOP-SECRET", "uuid":"secret-id"}],
        "route": {"final":"PRIVATE-NODE", "rules":[{"domain_suffix":["private.example.invalid"],"outbound":"PRIVATE-NODE"}]},
        "experimental": {"clash_api":{"secret":"API-SECRET", "external_controller":"127.0.0.1:9090"}},
        "UNSUPPORTED-PRIVATE-KEY":"PRIVATE-EXTENSION"
    });
    let mut privacy = Privacy::new(Some(&config));
    let result = privacy.project(&config, "", 0);
    let text = result.to_string();
    for secret in [
        "PRIVATE-NODE",
        "private.example.invalid",
        "TOP-SECRET",
        "secret-id",
        "API-SECRET",
        "PRIVATE-EXTENSION",
        "10112",
        "UNSUPPORTED-PRIVATE-KEY",
    ] {
        assert!(!text.contains(secret), "projection leaked {secret}: {text}");
    }
    assert_eq!(result["route"]["final"], result["outbounds"][0]["tag"]);
    assert_eq!(
        result["route"]["rules"][0]["outbound"],
        result["outbounds"][0]["tag"]
    );
    assert_eq!(result["inbounds"][0]["mtu"], 1400);
    assert_eq!(result["inbounds"][0]["exclude_uid"]["count"], 2);
    assert_eq!(result["outbounds"][0]["password"]["present"], true);
    assert_eq!(result["unrecognized_fields"], 1);
}

#[test]
fn logs_redact_credentials_node_labels_headers_and_uid_ranges() {
    let config = json!({"outbounds":[{"tag":"Premium Tokyo", "password":"Secret with spaces", "server":"private.example.invalid"}]});
    let privacy = Privacy::new(Some(&config));
    for line in [
        "error outbound/vless[Premium Tokyo]: failed Secret with spaces",
        "error outbound/vless[DifferentPrivateNode]: failed",
        "request Authorization: Bearer abc def PRIVATE-TOKEN",
        "request Authorization : Bearer abc def PRIVATE-TOKEN",
        "request x-magicnet-mcp-secret: VALUE with spaces",
        "1000: from all uidrange 10112-10113 lookup 2022",
        "warn dial private.example.invalid:443 failed",
        "cookie: session=SECRET cookie-two=PRIVATE",
    ] {
        let safe = privacy.line(line);
        for secret in [
            "Premium Tokyo",
            "Secret with spaces",
            "DifferentPrivateNode",
            "PRIVATE-TOKEN",
            "abc def",
            "VALUE with spaces",
            "10112-10113",
            "private.example.invalid",
            "session=SECRET",
        ] {
            assert!(!safe.contains(secret), "leaked {secret}: {safe}");
        }
    }
    assert!(privacy
        .line("1000: from all uidrange 10112-10113 lookup 2022")
        .contains("lookup 2022"));
    assert_eq!(
        privacy.line("\u{1b}[31mERROR\u{1b}[0m dns failed"),
        "ERROR dns failed"
    );
}

fn machine_capture(stdout: String) -> Capture {
    Capture {
        status: "status=ok exit_code=0 timed_out=false output_truncated=false duration_ms=1".into(),
        stdout,
        stderr: String::new(),
        complete: true,
    }
}

fn captured_json(text: &str) -> Value {
    let (_, payload) = text.split_once('\n').expect("capture status precedes JSON");
    serde_json::Deserializer::from_str(payload)
        .into_iter::<Value>()
        .next()
        .expect("one JSON value")
        .expect("valid redacted JSON")
}

#[test]
fn machine_capture_preserves_compact_and_pretty_status_despite_url_leaves() {
    let value = json!({
        "schema": 1, "ok": true, "command": "service.status", "data": {
            "core": {"selected": "sing-box", "sing_box": {
                "process_state": "running", "running": true, "pid_summary": "1234,5678", "rss_kib": 12345
            }},
            "api": {"url": "http://127.0.0.1:9090", "webui": "http://127.0.0.1:9090/ui", "ready": true},
            "lifecycle": "ready", "readiness": {"dataplane": true, "overall": true},
            "supervisors": {"fswatch": "2345", "wifi_policy": "stopped"},
            "connectivity": {
                "target": crate::connectivity::TARGET, "path": "mixed_proxy", "status": "offline",
                "reason": "upstream_unavailable", "primary_reason": "dns_failure", "warning": true,
                "http_status": null, "latency_ms": null, "checked_at": 1770000000,
                "next_check_at": 1770000060, "retry_in_seconds": 60, "backoff_seconds": 60,
                "consecutive_failures": 1, "probe_count": 1, "secondary_status": "failed",
                "direct_status": "online", "last_action": "repair", "action_status": "pending",
                "last_action_at": 1770000000, "last_refresh_at": null
            }
        }
    });
    for stdout in [
        value.to_string(),
        serde_json::to_string_pretty(&value).unwrap(),
    ] {
        let mut collector = Collector::new(Instant::now(), None);
        let capture = machine_capture(stdout);
        collector.append_machine_capture("service status", &capture, "service.status");
        let result = captured_json(
            collector
                .report
                .strip_prefix("\n[service status]\n")
                .unwrap(),
        );
        for key in ["schema", "ok", "command"] {
            assert_eq!(result[key], value[key]);
        }
        for key in [
            "core",
            "lifecycle",
            "readiness",
            "supervisors",
            "connectivity",
        ] {
            assert_eq!(result["data"][key], value["data"][key], "lost {key}");
        }
        assert_eq!(result["data"]["api"]["ready"], true);
        assert_eq!(result["data"]["api"]["url"], "<redacted-url>");
        assert_eq!(result["data"]["api"]["webui"], "<redacted-url>");
        assert!(!collector.report.contains("http://127.0.0.1"));
        assert_eq!(collector.incomplete_commands, 0);
    }
    for profile in ["cloudflare-doh", "cloudflare-dot"] {
        let value = json!({"schema": 1, "ok": true, "command": "dns.status", "data": {
            "profile": profile, "transport": if profile.ends_with("doh") { "doh" } else { "dot" },
            "primary": "https://cloudflare-dns.com/dns-query", "secondary": "tls://1.0.0.1"
        }});
        for stdout in [
            value.to_string(),
            serde_json::to_string_pretty(&value).unwrap(),
        ] {
            let mut collector = Collector::new(Instant::now(), None);
            let safe =
                captured_json(&collector.machine_text(&machine_capture(stdout), "dns.status"));
            assert_eq!(safe["command"], "dns.status");
            assert_eq!(safe["data"]["profile"], profile);
            assert_eq!(safe["data"]["transport"], value["data"]["transport"]);
            assert_eq!(safe["data"]["primary"], "<redacted-url>");
            assert_eq!(safe["data"]["secondary"], "<redacted-url>");
        }
    }
}

#[test]
fn machine_capture_preserves_all_published_transparent_transaction_phases() {
    // The transaction producer in service.rs and android-tun-proof.py use this
    // complete phase vocabulary; losing a phase hides where recovery stopped.
    for phase in [
        "idle",
        "prepared",
        "target-written",
        "preflight",
        "candidate-prepared",
        "stopping-old",
        "old-stopped",
        "candidate-starting",
        "verified",
        "rolling-back",
        "old-restored",
    ] {
        let transparent = json!({
            "mode": "ebpf", "configured_mode": "ebpf", "effective_type": "ebpf",
            "effective_mode": "hybrid", "capability": "ok", "local_cgroup": "attached",
            "shared_tc": "pending", "shared_interface_count": 2, "transition": phase,
            "has_recent_error": false, "dataplane_ready": null, "local_ready": true,
            "shared_ready": false
        });
        for (command, data) in [
            ("transparent.status", transparent.clone()),
            ("service.status", json!({"transparent": transparent})),
        ] {
            let expected = json!({"schema": 1, "ok": true, "command": command, "data": data});
            let mut collector = Collector::new(Instant::now(), None);
            let text = collector.machine_text(&machine_capture(expected.to_string()), command);
            assert_eq!(
                captured_json(&text),
                expected,
                "lost {command} phase {phase}"
            );
        }
    }
    let value = json!({"schema": 1, "ok": true, "command": "transparent.status",
        "data": {"transition": "UNTRUSTED-PHASE-CANARY"}});
    let mut collector = Collector::new(Instant::now(), None);
    let text = collector.machine_text(&machine_capture(value.to_string()), "transparent.status");
    assert!(!text.contains("UNTRUSTED-PHASE-CANARY"));
    assert!(captured_json(&text)["data"].get("transition").is_some());
}

#[test]
fn machine_capture_redacts_private_keys_identifiers_headers_and_unknown_strings() {
    let config = json!({"outbounds": [{"tag": "PRIVATE-NODE-CANARY"}, {"tag": "unknown"}]});
    let mut collector = Collector::new(Instant::now(), Some(&config));
    let config_alias = collector.privacy.project(&config, "", 0)["outbounds"][0]["tag"].clone();
    let value = json!({"schema": 1, "ok": true, "command": "service.status", "data": {
        "status": "unknown", "phase": "offline", "reason": "dns_failure",
        "rss_kib": 8192, "warning": false, "latency_ms": null,
        "selected": "PRIVATE-NODE-CANARY",
        "target": "https://www.google.com/generate_204?token=URL-TOKEN-CANARY",
        "headers": {"Authorization": "Bearer MULTI WORD HEADER-CANARY", "Cookie": "SESSION-CANARY"},
        "UID": [10112, 10113], "bootId": "BOOT-ID-CANARY", "device_id": 987654321,
        "devID": "DEVICE-CANARY", "authKey": "AUTH-KEY-CANARY", "api_key": "API-KEY-CANARY",
        "privateKey": "PRIVATE-KEY-CANARY", "password": "PASSWORD-CANARY", "token": "TOKEN-CANARY",
        "PRIVATE-OBJECT-KEY-CANARY": {"NESTED-PRIVATE-KEY-CANARY": "UNKNOWN-STRING-CANARY"},
        "unknown_field": "UNCONFIGURED-NODE-CANARY"
    }});
    let mut capture = machine_capture(value.to_string());
    capture.stderr =
        "ERROR DNS unavailable\nAuthorization: Bearer STDERR MULTI WORD CANARY\n".into();
    let text = collector.machine_text(&capture, "service.status");
    let safe = captured_json(&text);
    assert_eq!(
        safe["data"]["status"], "unknown",
        "a private label must not mask a canonical status"
    );
    assert_eq!(safe["data"]["phase"], "offline");
    assert_eq!(safe["data"]["reason"], "dns_failure");
    assert_eq!(safe["data"]["rss_kib"], 8192);
    assert_eq!(safe["data"]["warning"], false);
    assert_eq!(safe["data"]["latency_ms"], Value::Null);
    assert_eq!(safe["data"]["selected"], config_alias);
    assert_eq!(safe["data"]["target"], "<redacted-url>");
    assert_eq!(
        safe["data"].as_object().unwrap().len(),
        value["data"].as_object().unwrap().len()
    );
    assert!(text.contains("ERROR DNS unavailable"));
    for private in [
        "CANARY",
        "MULTI WORD",
        "10112",
        "10113",
        "987654321",
        "https://",
        "unknown_field",
    ] {
        assert!(!text.contains(private), "leaked {private}: {text}");
    }
}

#[test]
fn machine_capture_invalid_truncated_or_unexpected_output_fails_closed() {
    let valid = json!({"schema": 1, "ok": true, "command": "service.status", "data": {
        "message": "UNTRACKED-SECRET-CANARY"
    }})
    .to_string();
    let too_deep = format!(
        "{}\"UNTRACKED-SECRET-CANARY\"{}",
        "[".repeat(140),
        "]".repeat(140)
    );
    for (stdout, complete, command) in [
        (
            format!("{valid} trailing-SECRET-CANARY"),
            true,
            "service.status",
        ),
        (
            "{\"schema\":1,\"SECRET-CANARY\":".into(),
            true,
            "service.status",
        ),
        (valid.clone(), false, "service.status"),
        (valid.clone(), true, "dns.status"),
        (valid, true, "unsupported.status"),
        (too_deep, true, "service.status"),
        ("SECRET-CANARY".repeat(STREAM_LIMIT), true, "service.status"),
    ] {
        let mut collector = Collector::new(Instant::now(), None);
        let mut capture = machine_capture(stdout);
        capture.complete = complete;
        let text = collector.machine_text(&capture, command);
        assert_eq!(
            captured_json(&text),
            json!({"omitted": "invalid_or_incomplete_machine_json"})
        );
        assert!(!text.contains("SECRET-CANARY"));
        assert_eq!(collector.incomplete_commands, usize::from(complete));
    }
}

#[test]
fn machine_projection_limits_depth_arrays_and_serialized_output() {
    let mut nested = json!("DEPTH-SECRET-CANARY");
    for _ in 0..30 {
        nested = json!({"data": nested});
    }
    let value = json!({"schema": 1, "ok": true, "command": "service.status", "data": {
        "data": nested, "core": (0..160).collect::<Vec<_>>()
    }});
    let mut collector = Collector::new(Instant::now(), None);
    let text = collector.machine_text(&machine_capture(value.to_string()), "service.status");
    let safe = captured_json(&text);
    assert!(text.contains("depth_limit"));
    assert!(!text.contains("DEPTH-SECRET-CANARY"));
    assert_eq!(safe["data"]["core"].as_array().unwrap().len(), 129);
    assert_eq!(safe["data"]["core"][128]["omitted_entries"], 32);

    // Small unknown keys expand to aliases. Keep the original section/report
    // limits and emit a whole JSON omission instead of half a serialized object.
    let entries = (0..2500)
        .map(|index| (index.to_string(), json!("x")))
        .collect::<serde_json::Map<_, _>>();
    let value = json!({"schema": 1, "ok": true, "command": "service.status", "data": entries});
    assert!(value.to_string().len() <= STREAM_LIMIT);
    let text = collector.machine_text(&machine_capture(value.to_string()), "service.status");
    assert_eq!(
        captured_json(&text),
        json!({"omitted": "machine_json_output_limit"})
    );
    assert_eq!(collector.truncated_sections, 1);
    assert!(text.len() <= SECTION_LIMIT);

    collector.report = "x".repeat(REPORT_LIMIT - 8192 - 40);
    collector.append_machine_capture(
        "service status",
        &machine_capture(value.to_string()),
        "service.status",
    );
    let report = collector.finish();
    assert!(report.len() <= REPORT_LIMIT);
    assert!(report.ends_with("end_of_report=true\n"));
}

#[test]
fn command_timeout_keeps_partial_stderr_and_never_counts_as_success() {
    let mut collector = Collector::new(Instant::now(), None);
    let result = collector.command(
        Command::new("sh"),
        &[
            "-c",
            "printf 'early evidence'; printf 'failure detail' >&2; sleep 3",
        ],
        Duration::from_millis(30),
    );
    assert!(!result.complete);
    assert!(
        result.status.contains("timed_out=true"),
        "{}",
        result.status
    );
    assert!(result.stdout.contains("early evidence"));
    assert!(result.stderr.contains("failure detail"));
    assert_eq!(collector.incomplete_commands, 1);
}

#[test]
fn output_limit_is_reported_even_when_the_command_exits_successfully() {
    let mut collector = Collector::new(Instant::now(), None);
    let result = collector.command(Command::new("sh"), &["-c", "i=0; while [ $i -lt 3000 ]; do printf '0123456789012345678901234567890123456789\\n'; i=$((i+1)); done"], Duration::from_secs(2));
    assert!(!result.complete);
    assert!(result.status.contains("exit_code=0"), "{}", result.status);
    assert!(result.status.contains("output_truncated=true"));
    assert!(result.stdout.len() <= STREAM_LIMIT + 64);
}

#[test]
fn core_version_remains_readable_without_passing_arbitrary_command_text() {
    let capture = Capture {
        status: String::new(),
        stdout: "sing-box version 1.15.0-alpha.12\nEnvironment: go1.26.7 android/arm64\n".into(),
        stderr: String::new(),
        complete: true,
    };
    assert_eq!(version_identity(&capture), "version=1.15.0-alpha.12");
    let mut invalid = capture;
    invalid.stdout = "sing-box version PRIVATE-CANARY token=SECRET".into();
    let safe = version_identity(&invalid);
    assert!(safe.contains("version_format_unknown"));
    assert!(!safe.contains("SECRET"));
}

fn curl_build_fixture() -> Value {
    json!({
        "schema":1, "scope":"production-android-curl",
        "target":{"os":"android", "abi":"arm64-v8a", "api":21},
        "versions":{"curl":"8.22.0", "openssl":"3.5.8", "zlib":"1.3.2"},
        "ca":{"mode":"embedded", "version":"2026-09-25", "sha256":"a".repeat(64),
            "bytes":188900, "cert_count":121, "runtime_bundle":false, "system_store":false},
        "sources":{"curl":{"url":"https://private.invalid/subscription?token=SOURCE-SECRET", "sha256":"b".repeat(64)}},
        "curl_sha256":"c".repeat(64), "curl_bytes":4194304, "builder_sha256":"d".repeat(64),
        "toolchain":{"ndk_revision":"29.0.14206865", "ndk_source_properties_sha256":"e".repeat(64),
            "compiler":"PRIVATE-COMPILER-CANARY"},
        "runtime_capability":"not_tested", "PRIVATE-BUILD-KEY":"BUILD-SECRET-CANARY"
    })
}

#[test]
fn curl_version_and_build_evidence_preserve_public_versions_without_raw_private_text() {
    let app = crate::test_support::temp_app();
    let path = app.moddir.join("bin/curl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "fixture executable identity").unwrap();
    let build = app.moddir.join(CURL_BUILD_RECORD);
    fs::create_dir_all(build.parent().unwrap()).unwrap();
    let expected = curl_build_fixture();
    fs::write(&build, expected.to_string()).unwrap();
    let capture = machine_capture("curl 8.22.0 (PRIVATE-PLATFORM-CANARY) libcurl/8.22.0 OpenSSL/3.5.8 zlib/1.3.2 https://private.invalid/?secret=VERSION-SECRET\nRelease-Date: 2026-11-04\nProtocols: http https PRIVATE-PROTOCOL\nFeatures: SSL libz IPv6 PRIVATE-FEATURE\n".into());
    let privacy = Privacy::new(Some(&json!({"outbounds":[{"tag":"8.22.0"}]})));
    let evidence = curl_executor_evidence(&app, &path, &capture, &privacy);
    assert!(evidence.starts_with("selection=module_bin available=true\n"));
    let (version, build) = evidence.split_once("\n--- build provenance ---\n").unwrap();
    let version = captured_json(version.split_once("--- version ---\n").unwrap().1);
    assert_eq!(version["curl_version"], "8.22.0");
    assert_eq!(version["libcurl_version"], "8.22.0");
    assert_eq!(version["tls_backend"], "OpenSSL");
    assert_eq!(version["tls_version"], "3.5.8");
    assert_eq!(version["zlib_version"], "1.3.2");
    assert_eq!(
        version["capabilities"],
        json!({"https":true, "tls":true, "gzip":true})
    );
    let build: Value = serde_json::from_str(build).unwrap();
    for key in [
        "schema",
        "scope",
        "target",
        "versions",
        "ca",
        "curl_sha256",
        "curl_bytes",
        "runtime_capability",
    ] {
        assert_eq!(build[key], expected[key], "lost public build field {key}");
    }
    assert_eq!(build["binary_digest_verification"], "not_run");
    assert_eq!(build["applies_to_selected_path"], true);
    assert_eq!(
        curl_build_evidence(&app, false)["applies_to_selected_path"],
        false
    );
    for private in ["PRIVATE-", "SECRET", "private.invalid", "https://"] {
        assert!(!evidence.contains(private), "leaked {private}: {evidence}");
    }
    assert!(evidence.len() < 4096);
}

#[test]
fn curl_evidence_reports_missing_executor_invalid_output_and_untrusted_build_records() {
    let app = crate::test_support::temp_app();
    let absent = app.moddir.join("bin/curl");
    let mut collector = Collector::new(Instant::now(), None);
    let capture = collector.command(
        Command::new(&absent),
        &["-q", "--version"],
        Duration::from_secs(1),
    );
    let evidence = curl_executor_evidence(&app, &absent, &capture, &collector.privacy);
    assert!(evidence.starts_with("selection=missing available=false\n"));
    assert!(evidence.contains("command_spawn_failed"));
    assert!(evidence.contains("build_record_missing"));
    assert_eq!(collector.incomplete_commands, 1);

    for (stdout, complete) in [
        ("curl PRIVATE-VERSION token=SECRET-CANARY".to_owned(), true),
        ("curl 8.22.0 libcurl/8.22.0\nProtocols: http https\nFeatures: SSL libz".to_owned(), false),
        ("curl 8.22.0 libcurl/8.22.0\nProtocols: https\nProtocols: PRIVATE-CANARY\nFeatures: SSL libz".to_owned(), true),
        ("PRIVATE-CANARY".repeat(STREAM_LIMIT), true),
    ] {
        let mut capture = machine_capture(stdout);
        capture.complete = complete;
        let evidence = curl_executor_evidence(&app, &absent, &capture, &collector.privacy);
        assert!(evidence.contains("version_unavailable_or_invalid"));
        assert!(!evidence.contains("PRIVATE") && !evidence.contains("CANARY"));
    }
    let build = app.moddir.join(CURL_BUILD_RECORD);
    fs::create_dir_all(build.parent().unwrap()).unwrap();
    let mut malformed = curl_build_fixture();
    malformed["ca"]["mode"] = json!("PRIVATE-CA-CANARY");
    for text in [
        malformed.to_string(),
        "{PRIVATE-CANARY".into(),
        "x".repeat(CURL_BUILD_LIMIT as usize + 1),
    ] {
        fs::write(&build, text).unwrap();
        assert_eq!(
            curl_build_evidence(&app, true)["reason"],
            "build_record_invalid_or_oversized"
        );
    }
    fs::remove_file(&build).unwrap();
    let decoy = app.moddir.join("private-build-record");
    fs::write(&decoy, curl_build_fixture().to_string()).unwrap();
    symlink(&decoy, &build).unwrap();
    assert_eq!(curl_build_evidence(&app, true)["status"], "unavailable");
}

#[test]
fn curl_version_command_uses_the_existing_total_deadline_without_a_network_request() {
    let app = crate::test_support::temp_app();
    let path = app.moddir.join("bin/curl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "#!/bin/sh\nexit 93\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let mut collector = Collector::new(Instant::now() - BUDGET, None);
    let capture = collector.command(
        crate::trusted_curl(&app),
        &["--version"],
        Duration::from_secs(2),
    );
    assert!(capture.status.contains("collection_deadline"));
    assert!(!capture.status.contains("exit_code=93"));
    let evidence = curl_executor_evidence(&app, &path, &capture, &collector.privacy);
    collector.append_safe("curl executor", &evidence);
    let report = collector.finish();
    assert!(report.contains("available=false"));
    assert!(report.contains("network_request=not_run"));
    assert!(report.len() <= REPORT_LIMIT);
    assert!(report.ends_with("end_of_report=true\n"));
}

#[test]
fn exhausted_total_budget_does_not_spawn_more_commands() {
    let app = crate::test_support::temp_app();
    let marker = app.moddir.join("should-not-exist");
    let mut collector = Collector::new(Instant::now() - BUDGET, None);
    let result = collector.command(
        Command::new("touch"),
        &[marker.to_str().unwrap()],
        Duration::from_secs(1),
    );
    assert!(result.status.contains("collection_deadline"));
    assert!(!marker.exists());
}

#[test]
fn report_limits_are_explicit_and_keep_the_completion_marker() {
    let mut collector = Collector::new(Instant::now(), None);
    let lines = "bounded evidence\n".repeat(4000);
    for index in 0..50 {
        collector.append(&format!("section {index}"), &lines);
    }
    let result = collector.finish();
    assert!(result.len() <= REPORT_LIMIT);
    assert!(result.contains("status=truncated reason=report_output_limit"));
    assert!(result.ends_with("end_of_report=true\n"));
}

#[test]
fn export_replaces_one_private_file_without_following_a_destination_symlink() {
    let app = crate::test_support::temp_app();
    let directory = app.moddir.join("exports");
    let first = persist_bundle(&directory, "first\n").unwrap();
    assert_eq!(first.bytes, 6);
    assert_eq!(
        fs::metadata(&first.path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let target = app.moddir.join("unrelated");
    fs::write(&target, "keep me").unwrap();
    fs::remove_file(&first.path).unwrap();
    symlink(&target, &first.path).unwrap();
    let second = persist_bundle(&directory, "second complete report\n").unwrap();
    assert_eq!(first.path, second.path);
    assert_eq!(fs::read_to_string(&target).unwrap(), "keep me");
    assert_eq!(
        fs::read_to_string(&second.path).unwrap(),
        "second complete report\n"
    );
    assert!(!fs::symlink_metadata(&second.path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
}

#[test]
fn failed_publication_removes_its_temporary_and_keeps_previous_directory() {
    let app = crate::test_support::temp_app();
    let directory = app.moddir.join("exports");
    let destination = directory.join(EXPORT_NAME);
    fs::create_dir_all(&destination).unwrap();
    fs::write(destination.join("previous"), "keep me").unwrap();
    assert!(persist_bundle(&directory, "report\n").is_err());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
    assert_eq!(
        fs::read_to_string(destination.join("previous")).unwrap(),
        "keep me"
    );
}

#[test]
fn log_tail_retains_recent_failures_with_a_fixed_memory_bound() {
    let app = crate::test_support::temp_app();
    fs::create_dir_all(&app.log_dir).unwrap();
    let text = format!(
        "{}\nERROR recent failure\n",
        "INFO old line\n".repeat(20000)
    );
    fs::write(app.log_dir.join("sing-box.log"), text).unwrap();
    let tail = log_tail(&app, "sing-box");
    assert!(tail.contains("tail_only=true"));
    assert!(tail.contains("ERROR recent failure"));
    assert!(tail.lines().count() <= 121);
    assert!(tail.len() < STREAM_LIMIT + 256);

    fs::write(
        app.log_dir.join("sing-box.log"),
        "private".repeat(STREAM_LIMIT),
    )
    .unwrap();
    let tail = log_tail(&app, "sing-box");
    assert!(tail.contains("reason=oversized_unterminated_line"));
    assert!(!tail.contains("private"));
}
