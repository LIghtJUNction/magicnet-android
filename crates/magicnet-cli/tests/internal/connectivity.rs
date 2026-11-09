use super::*;
use crate::test_support::temp_app;
use crate::utils::BoundedCommandOutput;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;

fn clock(uptime: u64) -> Clock {
    Clock {
        boot: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
        uptime,
        epoch: 1_700_000_000 + uptime,
    }
}

fn output(code: i32, text: &str) -> BoundedCommandOutput {
    BoundedCommandOutput {
        status: Some(std::process::ExitStatus::from_raw(code << 8)),
        stdout: text.into(),
        stderr: vec![],
        timed_out: false,
        truncated: false,
    }
}

fn online() -> Observation {
    parse_probe(&output(0, "204 0.042"), true)
}

fn failed_cycle(state: &mut State, clock: &Clock) {
    state.record(
        clock,
        &Observation::failed("timeout"),
        Some(&Observation::failed("timeout")),
        Some(&online()),
    );
}

#[test]
fn failures_back_off_and_online_resets_without_a_recovery_burst() {
    let mut state = State::new(&clock(100));
    let mut now = 100;
    for expected in [60, 120, 240, 480, 960, 1800, 1800] {
        failed_cycle(&mut state, &clock(now));
        assert_eq!(state.next_uptime - now, expected);
        assert!(!state.due(&clock(state.next_uptime - 1)));
        assert!(state.due(&clock(state.next_uptime)));
        now = state.next_uptime;
    }
    state.record(&clock(now), &online(), None, None);
    assert_eq!(state.phase, "online");
    assert_eq!(state.failures, 0);
    assert_eq!(state.next_uptime, now + 300);
    assert_eq!(state.action(&clock(now), true), None);
    assert_eq!(state.secondary, "not_run");
    assert_eq!(state.direct, "not_run");
}

#[test]
fn missing_or_invalid_executor_is_not_reported_as_an_upstream_failure() {
    for reason in ["probe_unavailable", "probe_invalid"] {
        let mut state = State::new(&clock(100));
        let failed = Observation::failed(reason);
        for now in [100, 500] {
            state.record(&clock(now), &failed, Some(&failed), Some(&failed));
            assert_eq!(state.phase, "offline");
            assert_eq!(state.reason, reason);
            assert_eq!(state.primary_reason, reason);
            assert_eq!(state.http, None);
            assert_eq!(state.millis, None);
            assert_eq!(state.action(&clock(now), true), None);
        }
        assert_eq!(state.next_uptime, 620);
        // Even if the executor changes between requests and the direct control
        // later works, a malformed primary result cannot authorize recovery.
        state.record(&clock(1000), &failed, Some(&failed), Some(&online()));
        assert_eq!(state.reason, reason);
        assert_eq!(state.action(&clock(1000), true), None);

        state.record(
            &clock(2000),
            &Observation::failed("timeout"),
            Some(&Observation::failed("timeout")),
            Some(&failed),
        );
        assert_eq!(state.reason, "timeout");
        assert_eq!(state.action(&clock(2000), true), None);
    }
}

#[test]
fn two_hour_outage_simulation_keeps_probe_and_action_budgets() {
    let mut state = State::new(&clock(100));
    let mut times = Vec::new();
    let mut actions = Vec::new();
    let mut refreshes = Vec::new();
    for now in 100..=7300 {
        if !state.due(&clock(now)) {
            continue;
        }
        times.push(now);
        failed_cycle(&mut state, &clock(now));
        if let Some(action) = state.action(&clock(now), true) {
            actions.push(now);
            if action == "refresh" {
                refreshes.push(now);
            }
            let next_probe = state.next_uptime;
            state.reserve_action(&clock(now), action);
            state.action_status = "ok";
            state.next_uptime = next_probe;
        }
    }
    assert_eq!(&times[..6], &[100, 160, 280, 520, 1000, 1960]);
    assert_eq!(
        times.len(),
        8,
        "outage retries settle at one cycle per 30 minutes"
    );
    assert!(actions.windows(2).all(|p| p[1] - p[0] >= ACTION_COOLDOWN));
    assert!(refreshes
        .windows(2)
        .all(|p| p[1] - p[0] >= REFRESH_COOLDOWN));
    assert_eq!(state.probes, 8);
}

#[test]
fn endpoint_outage_or_broken_uplink_never_triggers_disruptive_recovery() {
    let mut state = State::new(&clock(100));
    for now in [100, 500, 1000] {
        state.record(
            &clock(now),
            &Observation::failed("timeout"),
            Some(&online()),
            None,
        );
        assert_eq!(state.phase, "degraded");
        assert_eq!(state.reason, "endpoint_specific");
        assert_eq!(state.action(&clock(now), true), None);
    }
    state.record(
        &clock(2000),
        &Observation::failed("timeout"),
        Some(&Observation::failed("timeout")),
        Some(&Observation::failed("dns_failure")),
    );
    assert_eq!(state.reason, "upstream_unavailable");
    assert_eq!(state.action(&clock(2000), true), None);
    state.record(
        &clock(4000),
        &Observation::failed("no_default_route"),
        None,
        None,
    );
    assert_eq!(state.reason, "no_default_route");
    assert_eq!(state.action(&clock(4000), true), None);
}

#[test]
fn remediation_is_staged_and_subscription_refresh_has_an_independent_cooldown() {
    let mut state = State::new(&clock(100));
    failed_cycle(&mut state, &clock(100));
    assert_eq!(state.action(&clock(100), true), None);
    failed_cycle(&mut state, &clock(160));
    assert_eq!(state.action(&clock(160), true), Some("repair"));
    state.reserve_action(&clock(160), "repair");
    assert_eq!(state.action(&clock(459), true), None);
    assert_eq!(state.action(&clock(460), true), Some("refresh"));
    state.reserve_action(&clock(460), "refresh");
    assert_eq!(state.action(&clock(760), true), Some("restart"));
    state.reserve_action(&clock(760), "restart");
    assert_eq!(state.action(&clock(1060), true), Some("repair"));
    state.reserve_action(&clock(1060), "repair");
    assert_eq!(state.action(&clock(1360), true), Some("restart"));
    assert_eq!(state.action(&clock(4060), true), Some("refresh"));
    assert_eq!(state.action(&clock(4060), false), Some("restart"));
    for failures in 2..=20 {
        state.failures = failures;
        state.reserve_action(&clock(5000), "repair");
        assert!((ACTION_COOLDOWN..=MAX_BACKOFF).contains(&(state.next_uptime - 5000)));
    }
}

#[test]
fn retry_budget_survives_reexecution_and_wall_clock_changes() {
    let app = temp_app();
    let mut state = State::new(&clock(100));
    failed_cycle(&mut state, &clock(100));
    state.publish(&app).unwrap();
    let mut earlier_wall = clock(120);
    earlier_wall.epoch = 900;
    assert!(!State::read(&app, &earlier_wall).due(&earlier_wall));
    let mut later_wall = clock(140);
    later_wall.epoch = 9_000_000_000;
    assert!(!State::read(&app, &later_wall).due(&later_wall));
    assert!(State::read(&app, &clock(160)).due(&clock(160)));
    let mut reboot = clock(5);
    reboot.boot = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into();
    let fresh = State::read(&app, &reboot);
    assert_eq!(fresh.phase, "unknown");
    assert!(fresh.due(&reboot));

    // Wall time can briefly be the Unix epoch before Android time sync. The
    // action and subscription budgets still belong to monotonic uptime.
    let mut unsynced = clock(500);
    unsynced.epoch = 0;
    failed_cycle(&mut state, &unsynced);
    state.reserve_action(&unsynced, "refresh");
    assert_eq!(state.action(&clock(501), true), None);
    state.recovery_stage = 1;
    assert_eq!(state.action(&clock(800), true), Some("restart"));
    assert_eq!(state.action(&clock(4100), true), Some("refresh"));
}

#[test]
fn status_is_read_only_and_cannot_turn_a_stopped_core_into_online() {
    let app = temp_app();
    let now = Clock::now().unwrap();
    let mut state = State::new(&now);
    state.record(&now, &online(), None, None);
    state.publish(&app).unwrap();
    let original = fs::read(app.moddir.join(STATE)).unwrap();
    let response = status_with_core(&app, "stopped");
    assert_eq!(response["status"], "paused");
    assert_eq!(response["warning"], false);
    assert_eq!(response["next_check_at"], Value::Null);
    assert_eq!(response["target"], TARGET);
    assert!(!response.to_string().contains(&now.boot));
    assert_eq!(fs::read(app.moddir.join(STATE)).unwrap(), original);
    assert!(!app.moddir.join(".state/connectivity.lock").exists());
}

#[test]
fn unavailable_clock_keeps_the_complete_unknown_status_contract() {
    let app = temp_app();
    let normal = status_with_core(&app, "stopped");
    let unavailable = status_with_clock(&app, "123", Err("clock_unavailable".into()));
    assert_eq!(
        normal.as_object().unwrap().keys().collect::<Vec<_>>(),
        unavailable.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    assert_eq!(unavailable["status"], "unknown");
    assert_eq!(unavailable["warning"], true);
    assert_eq!(unavailable["checked_at"], Value::Null);
    assert_eq!(unavailable["next_check_at"], Value::Null);
    assert_eq!(unavailable["reason"], "clock_unavailable");
    assert!(!app.moddir.join(STATE).exists());
}

#[test]
fn duplicate_ticks_share_one_lock_and_sleeping_ticks_do_not_probe() {
    let app = temp_app();
    let first = lock(&app).unwrap().unwrap();
    assert!(lock(&app).unwrap().is_none());
    tick(&app).unwrap();
    drop(first);
    let clock = Clock::now().unwrap();
    let mut state = State::new(&clock);
    state.record(&clock, &online(), None, None);
    state.tun.record(&clock, "not_required");
    state.publish(&app).unwrap();
    let before = fs::read(app.moddir.join(STATE)).unwrap();
    tick(&app).unwrap();
    assert_eq!(fs::read(app.moddir.join(STATE)).unwrap(), before);
    assert!(!app.log_dir.join("connectivity.log").exists());
}

#[test]
fn invalid_http_tls_dns_and_captive_portal_results_stay_failed() {
    assert!(online().ok);
    for text in [
        "200 0.001",
        "301 0.001",
        "403 0.001",
        "500 0.001",
        "000 0.001",
        "204 NaN",
        "204 -1",
        "204 200",
        "204 0.1 unexpected",
    ] {
        assert!(!parse_probe(&output(0, text), true).ok, "{text}");
    }
    for (exit, reason) in [
        (6, "dns_failure"),
        (7, "proxy_refused"),
        (28, "timeout"),
        (60, "tls_failure"),
    ] {
        let result = parse_probe(&output(exit, "204 0.01"), true);
        assert!(!result.ok);
        assert_eq!(result.reason, reason);
    }
    let mut capped = output(0, "204 0.1");
    capped.truncated = true;
    assert_eq!(parse_probe(&capped, true).reason, "probe_invalid");
}

#[test]
fn proxy_is_read_from_managed_config_and_never_falls_back_to_direct() {
    let app = temp_app();
    fs::create_dir_all(app.moddir.join(".config/sing-box")).unwrap();
    let config = app.moddir.join(".config/sing-box/config.json");
    fs::write(
        &config,
        r#"{"inbounds":[{"type":"mixed","listen":"::","listen_port":4567}]}"#,
    )
    .unwrap();
    assert_eq!(mixed_proxy(&app).unwrap(), "http://[::1]:4567");
    for inbound in [
        r#"{"type":"mixed","listen":"192.0.2.10","listen_port":4567}"#,
        r#"{"type":"mixed","listen":"127.0.0.1","listen_port":0}"#,
        r#"{"type":"mixed","listen_port":7892,"users":[{"username":"private","password":"secret"}]}"#,
        r#"{"type":"tun"}"#,
    ] {
        fs::write(&config, format!("{{\"inbounds\":[{inbound}]}}")).unwrap();
        assert!(mixed_proxy(&app).is_none());
    }
}

#[test]
fn actual_curl_child_has_fixed_deadline_and_no_direct_fallback_or_insecure_flags() {
    let app = temp_app();
    fs::create_dir_all(app.moddir.join("bin")).unwrap();
    let path = app.moddir.join("bin/curl");
    fs::write(&path, "#!/bin/sh\nprintf '204 0.012'\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let command = probe_command(&app, TARGET, Some("http://127.0.0.1:9876"));
    let args = command
        .get_args()
        .map(|a| a.to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(args[0], "-q");
    for pair in [
        ["--proxy", "http://127.0.0.1:9876"],
        ["--noproxy", ""],
        ["--max-time", "8"],
        ["--retry", "0"],
        ["--max-redirs", "0"],
        ["--proto", "=https"],
    ] {
        assert!(args.windows(2).any(|p| p == pair));
    }
    assert!(!args
        .iter()
        .any(|a| matches!(*a, "-k" | "--insecure" | "-L" | "--location")));
    assert!(probe(&app, TARGET, Some("http://127.0.0.1:9876"), true).ok);
    fs::write(&path, "#!/bin/sh\nprintf '204 0.012'; exit 6\n").unwrap();
    assert_eq!(
        probe(&app, TARGET, Some("http://127.0.0.1:9876"), true).reason,
        "dns_failure"
    );
}

#[test]
fn a_stopped_core_cancels_a_planned_repair_under_the_lifecycle_lock() {
    let app = temp_app();
    let now = Clock::now().unwrap();
    let mut state = State::new(&now);
    failed_cycle(&mut state, &now);
    failed_cycle(&mut state, &now);
    assert_eq!(state.action(&now, true), Some("repair"));
    recover(&app, &mut state, &now, "repair").unwrap();
    assert_eq!(state.last_action, "none");
    assert!(!app.moddir.join(STATE).exists());
}
