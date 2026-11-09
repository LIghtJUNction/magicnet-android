use super::*;
use crate::test_support::temp_app;
use std::fs;

fn clock(uptime: u64) -> Clock {
    Clock {
        boot: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
        uptime,
        epoch: 1_700_000_000 + uptime,
    }
}

#[test]
fn route_budget_is_per_boot_and_both_recovery_paths_share_cooldown() {
    let app = temp_app();
    let mut state = super::super::State::new(&clock(100));
    state.tun.record(&clock(100), "missing");
    assert!(!state.tun.recovery_due(&clock(100), 0));
    state.tun.record(&clock(160), "missing");
    assert!(state.tun.recovery_due(&clock(160), 0));
    assert!(!state.tun.recovery_due(&clock(160), 100));
    for (now, delay) in [(160, 300), (460, 600), (1060, 1200)] {
        assert!(state.tun.recovery_due(&clock(now), 0));
        state.tun.reserve(&clock(now));
        assert_eq!(
            state.tun.json(Some(&clock(now)), "123", false)["recovery_status"],
            "pending"
        );
        assert_eq!(state.tun.retry_uptime, now + delay);
        assert!(!state.tun.recovery_due(&clock(now + delay - 1), 0));
        state.tun.action_status = "ok";
    }
    assert!(!state.tun.recovery_due(&clock(100_000), 0));
    state.tun.record(&clock(100_000), "present");
    assert_eq!(
        state.tun.json(Some(&clock(100_000)), "123", false)["recovery_status"],
        "ok"
    );
    state.tun.record(&clock(100_060), "unknown");
    state.tun.record(&clock(100_120), "missing");
    state.tun.record(&clock(100_180), "missing");
    state.publish(&app).unwrap();
    let mut reloaded = super::super::State::read(&app, &clock(100_180));
    assert_eq!(reloaded.tun.attempts, RECOVERY_LIMIT);
    assert!(!reloaded.tun.recovery_due(&clock(100_180), 0));
    assert_eq!(
        reloaded.tun.json(Some(&clock(100_180)), "123", false)["recovery_status"],
        "exhausted"
    );
    let mut reboot = clock(1);
    reboot.boot = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into();
    assert_eq!(super::super::State::read(&app, &reboot).tun.attempts, 0);

    reloaded.phase = "offline";
    reloaded.failures = 2;
    reloaded.secondary = "failed";
    reloaded.direct = "online";
    reloaded.primary_reason = "timeout";
    reloaded.tun.action_uptime = 100_180;
    assert_eq!(reloaded.action(&clock(100_479), true), None);
    assert_eq!(reloaded.action(&clock(100_480), true), Some("repair"));
}

#[test]
fn consecutive_missing_observations_must_belong_to_one_core_generation() {
    let app = temp_app();
    for replacement in [
        Core {
            pid: 456,
            starttime: 100,
        },
        Core {
            pid: 123,
            starttime: 200,
        },
    ] {
        let mut state = super::super::State::new(&clock(100));
        state.tun.attempts = 1;
        state.tun.action_uptime = 100;
        state.tun.retry_uptime = 400;
        let first = Observation {
            status: "missing",
            core: Some(Core {
                pid: 123,
                starttime: 100,
            }),
        };
        state.tun.record_observation(&clock(100), &first);
        state.publish(&app).unwrap();
        let mut reloaded = super::super::State::read(&app, &clock(220));
        assert_eq!(reloaded.tun.core, first.core);
        let second = Observation {
            status: "missing",
            core: Some(replacement),
        };
        reloaded.tun.record_observation(&clock(220), &second);
        assert_eq!(reloaded.tun.failures, 1);
        assert!(!reloaded.tun.recovery_due(&clock(500), 0));
        assert_eq!(reloaded.tun.attempts, 1);
        assert_eq!(reloaded.tun.action_uptime, 100);
        assert_eq!(reloaded.tun.retry_uptime, 400);
        reloaded.tun.record_observation(&clock(280), &second);
        assert_eq!(reloaded.tun.failures, 2);
        assert!(!reloaded.tun.recovery_due(&clock(399), 0));
        assert!(reloaded.tun.recovery_due(&clock(400), 0));
    }
}

#[test]
fn damaged_state_cannot_replenish_a_same_boot_recovery_budget() {
    let app = temp_app();
    let now = clock(100);
    let mut state = super::super::State::new(&now);
    state.tun.attempts = RECOVERY_LIMIT;
    state.publish(&app).unwrap();
    let path = app.moddir.join(super::super::STATE);
    let original = fs::read_to_string(&path).unwrap();
    for text in [
        original.replace("tun_attempts=3", "tun_attempts=invalid"),
        original.replace("tun_attempts=3", "tun_attempts=18446744073709551616"),
        original.replace("tun_retry_uptime=0", "tun_retry_uptime=invalid"),
        original.replace("tun_action_uptime=0", "tun_action_uptime=-1"),
        original.replace("action_uptime=0", "action_uptime=invalid"),
        format!("{original}tun_attempts=0\n"),
        original.replace("schema=1", "schema=invalid"),
        original.replace(&now.boot, "unreadable-boot"),
        "x".repeat(super::super::MAX_STATE_BYTES as usize + 1),
    ] {
        fs::write(&path, text).unwrap();
        let mut read = super::super::State::read(&app, &now);
        read.tun.record(&now, "missing");
        read.tun.record(&now, "missing");
        assert_eq!(read.tun.attempts, RECOVERY_LIMIT);
        assert!(!read.tun.recovery_due(&clock(10_000), 0));
    }
    let legacy = original
        .lines()
        .filter(|line| !line.starts_with("tun_"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&path, legacy).unwrap();
    assert_eq!(
        super::super::State::read(&app, &now).tun.attempts,
        0,
        "upgrade without prior TUN state"
    );
    fs::remove_file(path).unwrap();
    assert_eq!(
        super::super::State::read(&app, &now).tun.attempts,
        0,
        "first boot observation"
    );
}

#[test]
fn unknown_startup_and_inactive_observations_break_the_missing_streak() {
    let mut state = State::read(&BTreeMap::new(), &clock(100));
    for status in ["unknown", "pending", "not_required", "paused", "present"] {
        state.record(&clock(100), "missing");
        state.record(&clock(160), status);
        assert_eq!(state.failures, 0);
        assert!(!state.recovery_due(&clock(1000), 0));
        state.record(&clock(220), "missing");
        assert!(!state.recovery_due(&clock(1000), 0));
    }
}

#[test]
fn route_observation_does_not_rewrite_mixed_proxy_evidence() {
    let mut state = super::super::State::new(&clock(100));
    state.record(
        &clock(100),
        &super::super::Observation {
            ok: true,
            reason: "ok",
            http: Some(204),
            millis: Some(8),
        },
        None,
        None,
    );
    state.tun.record(&clock(100), "missing");
    state.tun.record(&clock(160), "missing");
    assert_eq!(state.phase, "online");
    assert_eq!(state.reason, "ok");
    assert_eq!(state.http, Some(204));
    assert_eq!(state.probes, 1);
    assert_eq!(state.failures, 0);
    assert_eq!(state.next_uptime, 400);
    assert!(state.tun.recovery_due(&clock(160), 0));
    let status = state.tun.json(Some(&clock(160)), "123", false);
    assert_eq!(status["warning"], true);
    assert_eq!(status["status"], "missing");
}

#[test]
fn only_unambiguous_managed_tun_with_explicit_auto_route_is_eligible() {
    let app = temp_app();
    fs::create_dir_all(app.moddir.join(".config/sing-box")).unwrap();
    fs::create_dir_all(app.moddir.join(".config/magicnet")).unwrap();
    let path = app.moddir.join(".config/sing-box/config.json");
    let inbound = json!({"type":"tun","tag":"tun-in","interface_name":"magicnet0","auto_route":true,"address":["172.19.0.1/30"]});
    let config = json!({"inbounds":[inbound.clone()]});
    fs::write(&path, config.to_string()).unwrap();
    assert_eq!(managed_inbound(&app), Ok(Some(inbound.clone())));
    for value in [json!(false), Value::Null] {
        let mut config = config.clone();
        if value.is_null() {
            config["inbounds"][0]
                .as_object_mut()
                .unwrap()
                .remove("auto_route");
        } else {
            config["inbounds"][0]["auto_route"] = value;
        }
        fs::write(&path, config.to_string()).unwrap();
        assert_eq!(managed_inbound(&app), Ok(None));
    }
    for invalid in [
        json!({"inbounds":[inbound.clone(),inbound.clone()]}),
        json!({"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"other","auto_route":true}]}),
        json!({"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"magicnet0","auto_route":"true"}]}),
        json!({"inbounds":[inbound.clone(),{"type":"ebpf"}]}),
        json!({}),
    ] {
        fs::write(&path, invalid.to_string()).unwrap();
        assert!(managed_inbound(&app).is_err());
    }
    fs::write(&path, config.to_string()).unwrap();
    let mode = app.moddir.join(".config/magicnet/transparent-mode.conf");
    fs::write(&mode, "MAGICNET_TRANSPARENT_MODE=ebpf\n").unwrap();
    assert_eq!(managed_inbound(&app), Ok(None));
    fs::write(&mode, "MAGICNET_TRANSPARENT_MODE=unknown\n").unwrap();
    assert!(managed_inbound(&app).is_err());
    fs::write(&mode, "MAGICNET_TRANSPARENT_MODE=tun\n").unwrap();
    for path in [
        ".state/transparent-transaction",
        ".state/sing-box/subscription-transaction",
        ".state/sing-box/subscription-update.lock",
    ] {
        let path = app.moddir.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("missing-journal", &path).unwrap();
        assert!(managed_inbound(&app).is_err());
        fs::remove_file(path).unwrap();
    }
    let staging = app.moddir.join(".cache/magicnet-app-transaction");
    fs::create_dir_all(&staging).unwrap();
    assert!(managed_inbound(&app).is_ok());
    fs::write(staging.join("unfinished-stage"), "").unwrap();
    assert!(managed_inbound(&app).is_err());
}

#[test]
fn stopped_core_and_a_busy_lifecycle_never_spend_the_route_budget() {
    let app = temp_app();
    let now = Clock::now().unwrap();
    let mut state = super::super::State::new(&now);
    state.tun.record(&now, "missing");
    state.tun.record(&now, "missing");
    let observed = Observation {
        status: "missing",
        core: Some(Core {
            pid: 123,
            starttime: 1,
        }),
    };
    let lock = crate::service::try_config_apply_lock(&app)
        .unwrap()
        .unwrap();
    recover(&app, &mut state, &now, &observed).unwrap();
    assert_eq!(state.tun.action_status, "busy");
    assert_eq!(state.tun.attempts, 0);
    drop(lock);
    recover(&app, &mut state, &now, &observed).unwrap();
    assert_eq!(state.tun.attempts, 0);
}

#[test]
fn real_route_recovery_rechecks_evidence_restarts_only_owned_core_and_respects_stop() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    const CHILD_ROOT: &str = "MAGICNET_TEST_TUN_RECOVERY_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let app = App::for_test(root.into());
        let actual = Clock::now().unwrap();
        assert_eq!(observe(&app, &actual).status, "pending", "startup grace");
        // Virtual monotonic time is confined to this unit-test process. The
        // installed CLI has no force flag or clock override.
        let mut now = actual.clone();
        now.uptime += STARTUP_GRACE + 1;
        let missing = observe(&app, &now);
        assert_eq!(missing.status, "missing");
        let old_core = missing.core.clone().unwrap();
        let mut state = super::super::State::new(&now);
        let record_missing = |state: &mut super::super::State| {
            state.tun.record(&now, "missing");
            state.tun.record(&now, "missing");
        };
        record_missing(&mut state);

        for path in ["disable", "remove"] {
            let path = app.moddir.join(path);
            fs::write(&path, "").unwrap();
            recover(&app, &mut state, &now, &missing).unwrap();
            assert_eq!(state.tun.attempts, 0);
            assert_eq!(core_identity(&app), Some(old_core.clone()));
            assert!(!app.moddir.join("actions").exists());
            fs::remove_file(path).unwrap();
        }

        for path in [
            "snapshot-unknown",
            ".state/transparent-transaction",
            ".state/sing-box/subscription-transaction",
        ] {
            let path = app.moddir.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "").unwrap();
            recover(&app, &mut state, &now, &missing).unwrap();
            assert_eq!(state.tun.attempts, 0);
            assert_eq!(state.tun.status, "unknown");
            assert_eq!(core_identity(&app), Some(old_core.clone()));
            fs::remove_file(path).unwrap();
            record_missing(&mut state);
        }
        recover(&app, &mut state, &now, &missing).unwrap();
        assert_eq!(state.tun.attempts, 1);
        assert_eq!(state.tun.action_status, "ok");
        assert_eq!(
            state.tun.status, "missing",
            "an action receipt is not route readiness"
        );
        let new_core = core_identity(&app).expect("replacement owned core");
        assert_ne!(new_core, old_core);
        assert_eq!(observe(&app, &Clock::now().unwrap()).status, "present");
        assert_eq!(
            fs::read_to_string(app.moddir.join("actions")).unwrap(),
            "restart\n"
        );
        let foreign = fs::read_to_string(app.moddir.join("foreign.pid"))
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!(crate::process::live_process_identity(foreign)
            .unwrap()
            .is_some());

        fs::write(app.moddir.join("rules"), "0: from all lookup 255\n").unwrap();
        now.uptime += 600;
        let missing_again = observe(&app, &now);
        assert_eq!(missing_again.status, "missing");
        state.tun.record(&now, "missing");
        state.tun.record(&now, "missing");
        crate::service::service_cmd(&app, &["stop".into()]).unwrap();
        assert!(crate::owned_singbox_pids(&app).unwrap().is_empty());
        recover(&app, &mut state, &now, &missing_again).unwrap();
        assert_eq!(state.tun.attempts, 1);
        assert!(crate::owned_singbox_pids(&app).unwrap().is_empty());
        assert_eq!(
            fs::read_to_string(app.moddir.join("actions")).unwrap(),
            "restart\n"
        );
        assert!(crate::process::live_process_identity(foreign)
            .unwrap()
            .is_some());
        return;
    }

    let app = temp_app();
    for dir in [
        "bin",
        "foreign",
        ".config/sing-box",
        ".state/machines",
        "lib/kamfw",
    ] {
        fs::create_dir_all(app.moddir.join(dir)).unwrap();
    }
    let script = |path: &str, body: &str| {
        let path = app.moddir.join(path);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    };
    let core_script = "trap 'exit 0' TERM INT\nprintf '%s' $$ >\"$MODDIR/${MAGICNET_TEST_TUN_PIDFILE:-core.pid}\"\nwhile :; do sleep 30 & wait; done";
    script("bin/sing-box", core_script);
    script("foreign/sing-box", core_script);
    script("bin/pidof", "test \"$1\" = sing-box || exit 1\ncat \"$MODDIR/core.pid\"; printf '\\n'; cat \"$MODDIR/foreign.pid\"");
    script(
        "bin/ip",
        r#"
test ! -f "$MODDIR/snapshot-unknown" || exit 1
case "$*" in
  '-4 -N rule show') cat "$MODDIR/rules" ;;
  '-4 route show table  2022') printf '%s\n' 'default dev magicnet0 scope link' ;;
  *) exit 64 ;;
esac
"#,
    );
    fs::write(app.moddir.join(".config/sing-box/config.json"), json!({"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"magicnet0","auto_route":true,"address":["172.19.0.1/30"]}]}).to_string()).unwrap();
    fs::write(app.moddir.join("rules"), "0: from all lookup 255\n").unwrap();
    fs::write(app.moddir.join("healthy-rules"), "0: from all lookup 255\n9001: from all iif magicnet0 goto 9010\n9002: not from all iif lo lookup 2022\n9002: from 0.0.0.0 iif lo lookup 2022\n9002: from 172.19.0.0/30 iif lo lookup 2022\n9010: from all nop\n").unwrap();
    fs::write(app.moddir.join("lib/kamfw/.kamfwrc"), "import() { :; }\n").unwrap();
    fs::write(app.moddir.join("lib/magicnet.sh"), r#"
magicnet_prepare_network_for_core_stop() { :; }
magicnet_lifecycle_after_stop() { :; }
magicnet_supervisors_start_detached() { :; }
magicnet_start_kernel() {
    cp "$MODDIR/healthy-rules" "$MODDIR/rules"
    rm -f "$MODDIR/core.pid"
    setsid "$MODDIR/bin/sing-box" run -c "$MODDIR/.config/sing-box/config.json" -D "$MODDIR/.config/sing-box" </dev/null >/dev/null 2>&1 &
    for n in 1 2 3 4 5 6 7 8 9 10; do
        test ! -f "$MODDIR/core.pid" || break
        sleep 0.02
    done
    test -f "$MODDIR/core.pid" || return 1
    printf '%s\n' restart >>"$MODDIR/actions"
}
"#).unwrap();
    let spawn_core = |path: &str, marker: &str| {
        let mut command = Command::new(app.moddir.join(path));
        command
            .args(["run", "-c"])
            .arg(app.moddir.join(".config/sing-box/config.json"))
            .arg("-D")
            .arg(app.moddir.join(".config/sing-box"))
            .env("MODDIR", &app.moddir)
            .env("MAGICNET_TEST_TUN_PIDFILE", marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        command.spawn().unwrap()
    };
    let mut owned = spawn_core("bin/sing-box", "core.pid");
    let mut foreign = spawn_core("foreign/sing-box", "foreign.pid");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !app.moddir.join("core.pid").exists() || !app.moddir.join("foreign.pid").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "connectivity::tun::tests::real_route_recovery_rechecks_evidence_restarts_only_owned_core_and_respects_stop", "--nocapture"])
        .env(CHILD_ROOT, &app.moddir).env("MODDIR", &app.moddir)
        .env("PATH", format!("{}:/usr/bin:/bin", app.moddir.join("bin").display()))
        .output().unwrap();
    for pid in [
        Some(owned.id()),
        Some(foreign.id()),
        fs::read_to_string(app.moddir.join("core.pid"))
            .ok()
            .and_then(|pid| pid.parse().ok()),
    ]
    .into_iter()
    .flatten()
    {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    let _ = owned.wait();
    let _ = foreign.wait();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
