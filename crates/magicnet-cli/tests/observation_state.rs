use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "magicnet-cli-observation-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create fixture");
        Self(root)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_magicnet-cli"))
            .env("MODDIR", &self.0)
            .env("MAGICNET_API", "http://127.0.0.1:1")
            .args(args)
            .output()
            .expect("run CLI")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn incomplete_proxy_selection_returns_usage_instead_of_panicking() {
    let fixture = Fixture::new();
    for args in [vec!["api", "select"], vec!["api", "select", "proxy"]] {
        let output = fixture.run(&args);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("Usage: cli api select"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
        assert!(!fixture
            .0
            .join(".config/magicnet/selector-selections.json")
            .exists());
    }
}

#[test]
fn unknown_service_toggle_keeps_supervisor_evidence_untouched() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let pidof = fixture.0.join("pidof");
    fs::write(&pidof, "#!/bin/sh\nexit 2\n").unwrap();
    fs::set_permissions(&pidof, fs::Permissions::from_mode(0o755)).unwrap();
    let marker = fixture.0.join(".state/watchdog/magicnet-kernel.pid");
    fs::create_dir_all(marker.parent().unwrap()).unwrap();
    fs::write(&marker, "99999999\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_magicnet-cli"))
        .env("MODDIR", &fixture.0)
        .env("PATH", &fixture.0)
        .args(["service", "toggle", "sing-box"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("service state is unknown"));
    assert_eq!(fs::read_to_string(marker).unwrap(), "99999999\n");
}

#[test]
fn transparent_observers_require_effective_configuration_and_preserve_pending_journals() {
    let fixture = Fixture::new();
    let config = fixture.0.join(".config/sing-box/config.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    let intent = fixture.0.join(".config/magicnet/transparent-mode.conf");
    fs::create_dir_all(intent.parent().unwrap()).unwrap();
    fs::write(&intent, "MAGICNET_TRANSPARENT_MODE=ebpf\n").unwrap();
    let status = || {
        let output = fixture.run(&["--json", "transparent", "status"]);
        assert!(output.status.success(), "{:?}", output.stderr);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["data"].clone()
    };
    for (text, expected_type, expected_mode) in [
        (None, "unknown", "unknown"),
        (Some("invalid json"), "unknown", "unknown"),
        (Some("{}"), "unknown", "unknown"),
        (
            Some(r#"{"inbounds":[{"tag":"tun-in","type":"redirect"}]}"#),
            "unknown",
            "unknown",
        ),
        (
            Some(r#"{"inbounds":[{"tag":"tun-in","type":"tun"},{"tag":"tun-in","type":"ebpf"}]}"#),
            "unknown",
            "unknown",
        ),
        (
            Some(r#"{"inbounds":[{"tag":"tun-in","type":"ebpf","mode":"invalid"}]}"#),
            "ebpf",
            "unknown",
        ),
        (
            Some(r#"{"inbounds":[{"tag":"tun-in","type":"ebpf"}]}"#),
            "ebpf",
            "local",
        ),
        (
            Some(r#"{"inbounds":[{"tag":"tun-in","type":"tun"}]}"#),
            "tun",
            "tun",
        ),
    ] {
        if let Some(text) = text {
            fs::write(&config, text).unwrap();
        }
        let observed = status();
        assert_eq!(observed["configured_mode"], "ebpf");
        assert_eq!(observed["effective_type"], expected_type);
        assert_eq!(observed["effective_mode"], expected_mode);
        let output = fixture.run(&["state", "reconcile"]);
        assert!(output.status.success(), "{:?}", output.stderr);
        let canonical =
            fs::read_to_string(fixture.0.join(".state/machines/transparent.state")).unwrap();
        assert!(canonical
            .lines()
            .any(|line| line == format!("effective_type={expected_type}")));
        assert!(canonical
            .lines()
            .any(|line| line == format!("effective_mode={expected_mode}")));
    }
    assert_eq!(status()["transition"], "idle");
    let journal = fixture.0.join(".state/transparent-transaction");
    fs::create_dir(&journal).unwrap();
    assert_eq!(status()["transition"], "unknown");
    for (phase, expected) in [
        ("candidate-starting\n", "candidate-starting"),
        ("\n", "unknown"),
        ("provider token\n", "unknown"),
    ] {
        fs::write(journal.join("phase"), phase).unwrap();
        assert_eq!(status()["transition"], expected);
        let output = fixture.run(&["state", "reconcile"]);
        assert!(output.status.success(), "{:?}", output.stderr);
        let canonical =
            fs::read_to_string(fixture.0.join(".state/machines/transparent.state")).unwrap();
        assert!(canonical
            .lines()
            .any(|line| line == format!("phase={expected}")));
        assert!(canonical.contains("transaction_active=1\n"));
    }
}

#[test]
fn subscription_machine_reads_are_structured_and_do_not_create_configuration() {
    for action in ["status", "inspect"] {
        let fixture = Fixture::new();
        let output = fixture.run(&["--json", "sub", action]);
        assert!(output.status.success(), "{:?}", output.stderr);
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["data"]["source"]["configured_count"], 0);
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);

        let config = fixture.0.join(".config/sing-box");
        fs::create_dir_all(&config).unwrap();
        let source = config.join("subscription.url");
        fs::write(&source, b"https://SOURCE-CANARY.invalid/?token=PRIVATE\xff").unwrap();
        let output = fixture.run(&["--json", "sub", action]);
        assert!(!output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schema"], 1);
        assert_eq!(value["ok"], false);
        assert_eq!(
            value["error"]["code"],
            "machine.subscription_observation_failed"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SOURCE-CANARY"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SOURCE-CANARY"));
        assert!(!fixture.0.join(".state").exists());
        assert_eq!(fs::read_dir(&config).unwrap().count(), 1);
    }
}

#[test]
fn help_and_rejected_commands_do_not_create_state() {
    for (args, success) in [
        (vec![], true),
        (vec!["help"], true),
        (vec!["--help"], true),
        (vec!["-h"], true),
        (vec!["not-a-magicnet-command"], false),
        (vec!["state", "not-an-operation"], false),
        (vec!["--json", "capabilities"], true),
        (vec!["--json", "connectivity", "status"], true),
        (vec!["--json", "connectivity", "tick"], false),
        (vec!["--json", "service", "start"], false),
    ] {
        let fixture = Fixture::new();
        let output = fixture.run(&args);
        assert_eq!(
            output.status.success(),
            success,
            "args={args:?}, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !fixture.0.join(".state").exists(),
            "observation created state: {args:?}"
        );
    }
}

#[test]
fn json_flags_always_route_internal_helpers_to_the_machine_dispatcher() {
    for args in [
        vec!["--json", "__module-update-worker", "request_1234"],
        vec!["__module-update-worker", "request_1234", "--json"],
        vec!["__module-update-worker", "--json"],
        vec!["__proc-cmdline", "/proc/self/cmdline", "--json"],
        vec!["__proc-comm", "/proc/self/comm", "--json"],
        vec!["__proc-stat", "/proc/self/stat", "--json"],
        vec!["__proc-pids", "magicnet-cli", "--json"],
        vec!["__proc-script-pids", "/proc", "/nonexistent", "--json"],
    ] {
        let fixture = Fixture::new();
        let output = fixture.run(&args);
        assert!(!output.status.success());
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["schema"], 1);
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["code"], "machine.unsupported_command");
        assert!(!fixture.0.join(".state").exists());
    }
}

#[test]
fn a_path_query_does_not_replace_existing_canonical_observations() {
    let fixture = Fixture::new();
    let machines = fixture.0.join(".state/machines");
    fs::create_dir_all(&machines).expect("create machines");
    let service = machines.join("service.state");
    let sentinel = "schema=1\ndomain=service\nstate=unknown\nlifecycle=pending\n";
    fs::write(&service, sentinel).expect("write observation");

    let output = fixture.run(&["sub", "file", "sing-box"]);
    assert!(output.status.success());
    assert_eq!(fs::read_to_string(service).unwrap(), sentinel);
    assert_eq!(fs::read_dir(machines).unwrap().count(), 1);
}

#[test]
fn a_failed_control_command_still_publishes_observed_state() {
    let fixture = Fixture::new();
    let output = fixture.run(&["core", "select", "not-a-supported-core"]);
    assert!(!output.status.success());
    assert!(
        fixture.0.join(".state/machines/service.state").is_file(),
        "failed control command skipped publication: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn live_singbox_with_unreadable_argv_is_unknown_not_stopped() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let fixture = Fixture::new();
    fs::create_dir_all(fixture.0.join("bin")).unwrap();
    // Ownership lookup needs a real module path even when argv cannot be
    // inspected. A live process may expose invalid argv bytes after rewriting
    // its title; that is not evidence that it has exited.
    let binary = fixture.0.join("bin/sing-box");
    fs::write(
        &binary,
        "#!/bin/sh\nprintf 'sing-box\\n' > /proc/$$/comm\nprintf 'ready\\n'\nread hold\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = ChildGuard(
        Command::new("/bin/sh")
            .args([
                "-c",
                "printf 'sing-box\\n' > /proc/$$/comm\nprintf 'ready\\n'\nread hold",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn live malformed-argv candidate"),
    );
    let mut ready = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let pidof = fixture.0.join("pidof");
    fs::write(
        &pidof,
        format!("#!/bin/sh\nprintf '%s\\n' {}\n", child.0.id()),
    )
    .unwrap();
    fs::set_permissions(&pidof, fs::Permissions::from_mode(0o755)).unwrap();

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_magicnet-cli"))
            .env("MODDIR", &fixture.0)
            .env("PATH", &fixture.0)
            .env("MAGICNET_API", "http://127.0.0.1:1")
            .args(args)
            .output()
            .expect("inspect process evidence")
    };
    let status = || {
        let output = run(&["--json", "service", "status"]);
        assert!(output.status.success(), "stderr={:?}", output.stderr);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let unknown = status();
    assert_eq!(
        unknown["data"]["core"]["sing_box"]["process_state"],
        "unknown"
    );
    assert!(unknown["data"]["core"]["sing_box"]["running"].is_null());
    assert_eq!(unknown["data"]["lifecycle"], "unknown");
    assert!(child.0.try_wait().unwrap().is_none());

    let pidfile = fixture
        .0
        .join(".state/wifi-policy/magicnet-wifi-policy.pid");
    fs::create_dir_all(pidfile.parent().unwrap()).unwrap();
    let sentinel = format!("{}\n", child.0.id());
    fs::write(&pidfile, &sentinel).unwrap();
    let stopped = run(&["service", "stop"]);
    assert!(!stopped.status.success());
    assert_eq!(fs::read_to_string(&pidfile).unwrap(), sentinel);
    assert!(child.0.try_wait().unwrap().is_none());

    // A valid owned generation must still be recognized. Combining its PID
    // with indeterminate evidence cannot hide that uncertainty.
    let config = fixture.0.join(".config/sing-box/config.json");
    let workdir = fixture.0.join(".config/sing-box");
    let mut owned = ChildGuard(
        Command::new(&binary)
            .arg("run")
            .arg("-c")
            .arg(&config)
            .arg("-D")
            .arg(&workdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    ready.clear();
    BufReader::new(owned.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let candidates = |pids: &str| {
        fs::write(&pidof, format!("#!/bin/sh\nprintf '%s\\n' '{pids}'\n")).unwrap();
    };
    candidates(&owned.0.id().to_string());
    let running = status();
    assert_eq!(
        running["data"]["core"]["sing_box"]["process_state"],
        "running"
    );
    assert_eq!(running["data"]["core"]["sing_box"]["running"], true);
    candidates(&format!("{} {}", owned.0.id(), child.0.id()));
    assert_eq!(
        status()["data"]["core"]["sing_box"]["process_state"],
        "unknown"
    );
    assert!(owned.0.try_wait().unwrap().is_none());
    assert!(child.0.try_wait().unwrap().is_none());

    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert_eq!(
        status()["data"]["core"]["sing_box"]["process_state"],
        "running"
    );

    // Keep the exited owned child unreaped so /proc still exists with state Z.
    // This must remain definite stopped evidence rather than becoming unknown.
    drop(owned.0.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(2);
    while !fs::read_to_string(format!("/proc/{}/stat", owned.0.id()))
        .unwrap()
        .rsplit_once(") ")
        .is_some_and(|(_, fields)| fields.starts_with("Z "))
    {
        assert!(Instant::now() < deadline, "owned child did not exit");
        std::thread::sleep(Duration::from_millis(5));
    }
    let stopped = status();
    assert_eq!(
        stopped["data"]["core"]["sing_box"]["process_state"],
        "stopped"
    );
    assert_eq!(stopped["data"]["core"]["sing_box"]["running"], false);
    owned.0.wait().unwrap();
    assert_eq!(
        status()["data"]["core"]["sing_box"]["process_state"],
        "stopped"
    );
}
