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
