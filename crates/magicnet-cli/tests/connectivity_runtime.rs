//! The real CLI runs against an owned sleeping core and deterministic local
//! transport fixtures. No test in this suite sends an Internet request.
#![cfg(target_os = "linux")]

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Fixture {
    root: PathBuf,
    core: Child,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "magicnet-connectivity-{}-{nonce}",
            std::process::id()
        ));
        for path in [
            "bin",
            ".config/sing-box",
            ".state/machines",
            "lib/kamfw",
            ".log",
        ] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        let script = |path: &str, body: &str| {
            fs::write(root.join(path), format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o700)).unwrap();
        };
        fs::write(
            root.join(".config/sing-box/config.json"),
            r#"{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":7892}]}"#,
        )
        .unwrap();
        fs::write(
            root.join(".config/sing-box/subscription.url"),
            "https://subscription.invalid/private-source\n",
        )
        .unwrap();
        script("bin/sing-box", "trap 'exit 0' TERM INT\nprintf '%s' $$ >\"$MODDIR/core.pid\"\nwhile :; do sleep 30 & wait; done");
        script(
            "bin/pidof",
            "test \"$1\" = sing-box || exit 1\ncat \"$MODDIR/core.pid\"",
        );
        script("bin/ip", "test ! -f \"$MODDIR/no-route\" || exit 0\nprintf '%s\\n' 'default via 192.0.2.1 dev test0'");
        script(
            "bin/curl",
            r#"
printf '%s\n' "$*" >>"$MODDIR/calls"
test ! -f "$MODDIR/slow" || sleep 0.2
mode=$(cat "$MODDIR/mode")
case "$mode:$*" in
  dns:*) printf '000 0.001'; exit 6 ;;
  down:*baidu*) printf '200 0.002' ;;
  down:*) printf '000 0.010'; exit 28 ;;
  google:*google.com*) printf '500 0.003' ;;
  *) printf '204 0.004' ;;
esac
"#,
        );
        fs::write(root.join("mode"), "online").unwrap();
        fs::write(root.join("lib/kamfw/.kamfwrc"), "import() { :; }\n").unwrap();
        fs::write(
            root.join("lib/magicnet.sh"),
            r#"
magicnet_notify() { printf '%s\n' "$*" >>"$MODDIR/notifications"; }
magicnet_after_kernel_start_unlocked() { printf '%s\n' repair >>"$MODDIR/actions"; }
magicnet_connectivity_watchdog_start() { :; }
"#,
        )
        .unwrap();
        fs::write(root.join("lib/magicnet_singbox_subscribe.sh"), "magicnet_singbox_update_subscription() { printf '%s\\n' refresh >>\"$MODDIR/actions\"; }\n").unwrap();
        let mut command = Command::new(root.join("bin/sing-box"));
        command
            .args(["run", "-c"])
            .arg(root.join(".config/sing-box/config.json"))
            .arg("-D")
            .arg(root.join(".config/sing-box"))
            .env("MODDIR", &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let core = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !root.join("core.pid").exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        Self { root, core }
    }

    fn command(&self, args: &[&str]) -> Command {
        let module_cli = self.root.join("cli");
        let mut command = Command::new(if module_cli.exists() {
            module_cli
        } else {
            PathBuf::from(env!("CARGO_BIN_EXE_magicnet-cli"))
        });
        command
            .args(args)
            .env("MODDIR", &self.root)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        let output = self.command(args).output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn status(&self) -> Value {
        let output = self.run(&["--json", "connectivity", "status"]);
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["data"].clone()
    }

    fn state(&self) -> BTreeMap<String, String> {
        fs::read_to_string(self.root.join(".state/machines/connectivity.state"))
            .unwrap()
            .lines()
            .filter_map(|line| line.split_once('=').map(|(k, v)| (k.into(), v.into())))
            .collect()
    }

    fn edit_state(&self, changes: &[(&str, &str)]) {
        let mut state = self.state();
        for (key, value) in changes {
            state.insert((*key).into(), (*value).into());
        }
        let text = state
            .iter()
            .map(|(key, value)| format!("{key}={value}\n"))
            .collect::<String>();
        fs::write(self.root.join(".state/machines/connectivity.state"), text).unwrap();
    }

    fn calls(&self) -> usize {
        fs::read_to_string(self.root.join("calls"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    fn install_supervisor_activation_fixture(&self) {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src/MagicNet/lib");
        fs::create_dir_all(self.root.join("lib/magicnet/singbox_subscribe")).unwrap();
        for path in [
            "kamfw/watchdog.sh",
            "magicnet/primitives.sh",
            "magicnet/supervisors.sh",
            "magicnet/singbox_subscribe/config.sh",
            "magicnet/singbox_subscribe/update.sh",
        ] {
            fs::copy(source.join(path), self.root.join("lib").join(path)).unwrap();
        }
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_magicnet-cli"), self.root.join("cli"))
            .unwrap();
        fs::write(
            self.root.join("lib/kamfw/.kamfwrc"),
            r#"
KAM_HOME="$MODDIR"
KAMFW_DIR="$MODDIR/lib/kamfw"
export KAM_HOME KAMFW_DIR
print() { printf '%s\n' "$*"; }
set_i18n() { :; }
i18n() { printf '%s\n' "$1"; }
t() { cat; }
success() { :; }
warn() { :; }
error() { printf '%s\n' "$*" >&2; }
import() { case "$1" in watchdog) . "$MODDIR/lib/kamfw/watchdog.sh" ;; esac; }
"#,
        )
        .unwrap();
        fs::write(
            self.root.join("lib/magicnet.sh"),
            r#"
. "$MODDIR/lib/magicnet/primitives.sh"
. "$MODDIR/lib/magicnet/supervisors.sh"
magicnet_singbox_api_listener_exists() { return 1; }
. "$MODDIR/lib/magicnet/singbox_subscribe/config.sh"
magicnet_module_disabled() { test -f "$MODDIR/disable"; }
magicnet_kernel_running() { kill -0 "$(cat "$MODDIR/core.pid")"; }
magicnet_cmd_exists() { command -v "$1" >/dev/null 2>&1; }
magicnet_warn() { :; }
magicnet_detach_pid_from_app_cgroup() { :; }
magicnet_fswatch_status() { return 1; }
magicnet_fswatch_start() { :; }
magicnet_fswatch_stop() { :; }
magicnet_wifi_policy_start() { :; }
magicnet_wifi_policy_stop() { :; }
magicnet_subscription_refresh_start() { :; }
magicnet_subscription_refresh_stop() { :; }
magicnet_hotspot_watchdog_start() { :; }
magicnet_hotspot_watchdog_stop() { :; }
magicnet_hotspot_route_cleanup() { :; }
magicnet_notify() { :; }
magicnet_singbox_record_runtime_fingerprint() { :; }
magicnet_disable_dns_capture() { :; }
magicnet_disable_dns_leak_guard() { :; }
magicnet_singbox_stop_owned_config() { printf '%s\n' core_stop >>"$MODDIR/activation"; }
magicnet_singbox_ensure_start_owned() { printf '%s\n' core_start >>"$MODDIR/activation"; }
magicnet_reapply_post_start_policy() { printf '%s\n' policy >>"$MODDIR/activation"; }
magicnet_prepare_network_for_core_stop() { printf '%s\n' network_stop >>"$MODDIR/activation"; }
magicnet_lifecycle_after_stop() { printf '%s\n' stopped >>"$MODDIR/activation"; }
"#,
        )
        .unwrap();
        fs::write(
            self.root.join("lib/magicnet_singbox_subscribe.sh"),
            r#"
magicnet_singbox_update_subscription() {
    magicnet_singbox_restart_owned "$MODDIR/.config/sing-box/config.json" || return $?
    printf '%s\n' refresh >>"$MODDIR/actions"
}
"#,
        )
        .unwrap();
    }

    fn watchdog_pid(&self) -> u32 {
        fs::read_to_string(self.root.join(".state/watchdog/magicnet-kernel.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn wake_initial_watchdog_sleep(&self, pid: u32) {
        // Only the test accelerates the first 60-second wait. The generated
        // production loop, CLI child, restart, stop, and restore remain real.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            for child in process_children(pid) {
                let argv = fs::read(format!("/proc/{child}/cmdline")).unwrap_or_default();
                if argv.ends_with(b"sleep\x0060\x00") {
                    assert_eq!(unsafe { libc::kill(child as i32, libc::SIGTERM) }, 0);
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "watchdog did not enter its sleep: pid={pid} children={:?} argv={:?} log={:?}",
                process_children(pid),
                fs::read(format!("/proc/{pid}/cmdline")),
                fs::read_to_string(self.root.join(".log/connectivity-watchdog.log"))
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn process_children(pid: u32) -> Vec<u32> {
    // Some container kernels omit task/.../children. Read the ordinary PPID
    // field so the lifecycle fixture works in those restricted proc mounts.
    fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let child = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
            let stat = fs::read_to_string(entry.path().join("stat")).ok()?;
            let (_, fields) = stat.rsplit_once(") ")?;
            (fields.split_whitespace().nth(1)?.parse::<u32>().ok()? == pid).then_some(child)
        })
        .collect()
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(pid) = fs::read_to_string(self.root.join(".state/watchdog/magicnet-kernel.pid")) {
            if let Ok(pid) = pid.trim().parse::<u32>() {
                for child in process_children(pid).into_iter().chain([pid]) {
                    unsafe {
                        libc::kill(child as i32, libc::SIGKILL);
                    }
                }
            }
        }
        unsafe {
            libc::kill(-(self.core.id() as i32), libc::SIGKILL);
        }
        let _ = self.core.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn connectivity_real_ticks_share_a_persisted_budget_across_processes_and_status_reads() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("slow"), "").unwrap();
    let children = (0..6)
        .map(|_| fixture.command(&["connectivity", "tick"]).spawn().unwrap())
        .collect::<Vec<_>>();
    for child in children {
        assert!(child.wait_with_output().unwrap().status.success());
    }
    assert_eq!(
        fixture.calls(),
        1,
        "concurrent producers must issue one Google request"
    );
    let state = fixture.state();
    let status = fixture.status();
    assert_eq!(status["status"], "online");
    assert_eq!(status["http_status"], 204);
    assert_eq!(status["latency_ms"], 4);
    assert_eq!(status["probe_count"], 1);
    assert_eq!(status["backoff_seconds"], 300);
    for _ in 0..4 {
        fixture.run(&["connectivity", "tick"]);
        fixture.status();
    }
    assert_eq!(fixture.state(), state);
    assert_eq!(fixture.calls(), 1);
    let encoded = status.to_string();
    assert!(!encoded.contains("private-source"));
    assert!(!encoded.contains(&state["boot"]));
}

#[test]
fn connectivity_tun_checks_are_independent_of_successful_mixed_proxy_probes() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join(".config/sing-box/config.json"), r#"{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":7892},{"type":"tun","tag":"tun-in","interface_name":"magicnet0","address":["172.19.0.1/30"],"auto_route":true}]}"#).unwrap();
    fs::write(
        fixture.root.join("bin/ip"),
        r#"#!/bin/sh
case "$*" in
  *'table all default') printf '%s\n' 'default via 192.0.2.1 dev test0' ;;
  '-4 -N rule show')
    test ! -f "$MODDIR/rules-unknown" || exit 1
    cat "$MODDIR/rules" ;;
  '-4 route show table  2022') printf '%s\n' 'default dev magicnet0 scope link' ;;
  *) exit 64 ;;
esac
"#,
    )
    .unwrap();
    fs::write(fixture.root.join("rules"), "0: from all lookup 255\n9001: from all iif magicnet0 goto 9010\n9002: not from all iif lo lookup 2022\n9002: from 0.0.0.0 iif lo lookup 2022\n9002: from 172.19.0.0/30 iif lo lookup 2022\n9010: from all nop\n").unwrap();
    fixture.run(&["connectivity", "tick"]);
    let status = fixture.status();
    assert_eq!(status["status"], "online");
    assert_eq!(status["tun_auto_route"]["status"], "present");
    assert_eq!(fixture.calls(), 1);

    fs::write(fixture.root.join("rules"), "0: from all lookup 255\n").unwrap();
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    let pending = fixture.status();
    assert_eq!(pending["status"], "online");
    assert_eq!(
        pending["tun_auto_route"]["status"], "pending",
        "new core has startup grace"
    );
    assert_eq!(pending["tun_auto_route"]["recovery_attempts"], 0);
    assert_eq!(
        fixture.calls(),
        1,
        "a TUN check does not issue another Google request"
    );

    fs::write(fixture.root.join("rules-unknown"), "").unwrap();
    fixture.edit_state(&[
        ("tun_next_uptime", "0"),
        ("tun_failures", "2"),
        ("tun_status", "missing"),
    ]);
    fixture.run(&["connectivity", "tick"]);
    let unknown = fixture.status();
    assert_eq!(unknown["status"], "online");
    assert_eq!(unknown["warning"], false);
    assert_eq!(unknown["tun_auto_route"]["status"], "unknown");
    assert_eq!(unknown["tun_auto_route"]["warning"], true);
    assert_eq!(unknown["tun_auto_route"]["consecutive_failures"], 0);
    assert_eq!(unknown["tun_auto_route"]["recovery_attempts"], 0);
    assert!(!fixture.root.join("actions").exists());

    fs::create_dir_all(fixture.root.join(".config/magicnet")).unwrap();
    fs::write(
        fixture.root.join(".config/magicnet/transparent-mode.conf"),
        "MAGICNET_TRANSPARENT_MODE=ebpf\n",
    )
    .unwrap();
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["tun_auto_route"]["status"], "not_required");
    assert_eq!(fixture.calls(), 1);
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_real_failure_attempts_warning_backoff_repair_and_subscription_refresh() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode"), "down").unwrap();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(
        fixture.calls(),
        3,
        "Google, independent proxy, and direct control"
    );
    let first = fixture.status();
    assert_eq!(first["status"], "offline");
    assert_eq!(first["warning"], true);
    assert_eq!(first["backoff_seconds"], 60);
    assert_eq!(first["last_action"], "none");
    assert!(fs::read_to_string(fixture.root.join("notifications"))
        .unwrap()
        .contains("⚠️"));
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.calls(), 3);
    fixture.edit_state(&[("next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    let second = fixture.status();
    assert_eq!(second["consecutive_failures"], 2);
    assert_eq!(second["backoff_seconds"], 120);
    assert_eq!(second["last_action"], "repair");
    assert_eq!(second["action_status"], "ok");
    assert_eq!(
        fs::read_to_string(fixture.root.join("actions")).unwrap(),
        "repair\n"
    );
    fixture.edit_state(&[("next_uptime", "0"), ("action_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    let third = fixture.status();
    assert_eq!(third["last_action"], "refresh");
    assert_eq!(third["action_status"], "ok");
    assert_eq!(
        third["status"], "offline",
        "successful action alone is not a passed HTTPS probe"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("actions")).unwrap(),
        "repair\nrefresh\n"
    );
    fs::write(fixture.root.join("mode"), "online").unwrap();
    fixture.edit_state(&[("next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    let restored = fixture.status();
    assert_eq!(restored["status"], "online");
    assert_eq!(restored["consecutive_failures"], 0);
    assert_eq!(restored["backoff_seconds"], 300);
}

#[test]
fn connectivity_proxy_missing_default_route_and_dns_failures_do_not_create_false_success() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join(".config/sing-box/config.json"), "{}").unwrap();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.calls(), 0);
    assert_eq!(fixture.status()["reason"], "proxy_unavailable");
    fixture.edit_state(&[("next_uptime", "0")]);
    fs::write(fixture.root.join("no-route"), "").unwrap();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["reason"], "no_default_route");
    assert_eq!(fixture.calls(), 0);
    fs::remove_file(fixture.root.join("no-route")).unwrap();
    fs::write(
        fixture.root.join(".config/sing-box/config.json"),
        r#"{"inbounds":[{"type":"mixed","listen_port":7892}]}"#,
    )
    .unwrap();
    fs::write(fixture.root.join("mode"), "dns").unwrap();
    fixture.edit_state(&[("next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["status"], "offline");
    assert_eq!(fixture.status()["reason"], "upstream_unavailable");
    assert_eq!(fixture.status()["primary_reason"], "dns_failure");
    assert_eq!(fixture.calls(), 3);
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_stopped_core_and_module_disable_prevent_every_probe_and_action() {
    let mut fixture = Fixture::new();
    fs::write(fixture.root.join("disable"), "").unwrap();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.calls(), 0);
    assert_eq!(fixture.status()["reason"], "module_disabled");
    fs::remove_file(fixture.root.join("disable")).unwrap();
    unsafe {
        libc::kill(-(fixture.core.id() as i32), libc::SIGKILL);
    }
    fixture.core.wait().unwrap();
    fixture.edit_state(&[("next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["status"], "paused");
    assert_eq!(fixture.status()["reason"], "core_stopped");
    assert_eq!(fixture.calls(), 0);
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_refresh_survives_its_parent_watchdog_stop_and_restores_one_loop() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode"), "down").unwrap();
    fixture.run(&["connectivity", "tick"]);
    fixture.edit_state(&[
        ("next_uptime", "0"),
        ("failures", "2"),
        ("recovery_stage", "1"),
        ("action_uptime", "0"),
    ]);
    fixture.install_supervisor_activation_fixture();
    fixture.run(&["supervisor", "start", "all"]);
    let original = fixture.watchdog_pid();
    fixture.wake_initial_watchdog_sleep(original);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state = fixture.state();
        if state["last_action"] == "refresh" && state["action_status"] == "ok" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "recovery worker lost its completion receipt: {state:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let restored = fixture.watchdog_pid();
    assert_ne!(restored, original);
    assert_eq!(
        fs::read_to_string(fixture.root.join("activation")).unwrap(),
        "core_stop\ncore_start\npolicy\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("actions")).unwrap(),
        "refresh\n"
    );
    let loop_path = fixture.root.join(".state/watchdog/magicnet-kernel.loop.sh");
    let owners = fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .filter(|pid| {
            fs::read(format!("/proc/{pid}/cmdline"))
                .unwrap_or_default()
                .split(|b| *b == 0)
                .any(|arg| arg == loop_path.to_string_lossy().as_bytes())
        })
        .collect::<Vec<_>>();
    assert_eq!(owners, vec![restored], "one restored monitor owns the loop");
    for path in [
        ".state/connectivity.lock",
        ".state/config-apply.lock",
        ".state/watchdog/magicnet-connectivity.lifecycle.lock",
    ] {
        let path = fixture.root.join(path);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            assert!(Instant::now() < deadline, "maintenance retained {path:?}");
            thread::sleep(Duration::from_millis(10));
        }
        for fd in fs::read_dir(format!("/proc/{restored}/fd"))
            .unwrap()
            .flatten()
        {
            assert_ne!(fs::read_link(fd.path()).ok().as_ref(), Some(&path));
        }
    }
    let calls = fixture.calls();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(
        fixture.calls(),
        calls,
        "restoring the monitor retains the retry budget"
    );
    assert_eq!(fixture.status()["status"], "offline");
}

#[test]
fn connectivity_a_core_stopped_during_probing_cannot_be_restarted_by_recovery() {
    let mut fixture = Fixture::new();
    fs::write(fixture.root.join("mode"), "down").unwrap();
    fixture.run(&["connectivity", "tick"]);
    fixture.edit_state(&[("next_uptime", "0")]);
    fs::write(fixture.root.join("slow"), "").unwrap();
    let child = fixture.command(&["connectivity", "tick"]).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while fixture.calls() < 4 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    unsafe {
        libc::kill(-(fixture.core.id() as i32), libc::SIGKILL);
    }
    fixture.core.wait().unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    assert_eq!(fixture.status()["status"], "paused");
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_explicit_stop_cancels_slow_refresh_after_rollback_before_unlocking() {
    let mut fixture = Fixture::new();
    fs::write(fixture.root.join("mode"), "down").unwrap();
    fixture.run(&["connectivity", "tick"]);
    fixture.edit_state(&[
        ("next_uptime", "0"),
        ("failures", "2"),
        ("recovery_stage", "1"),
    ]);
    fixture.install_supervisor_activation_fixture();
    fs::write(fixture.root.join("bin/pidof"), "#!/bin/sh\ncase \"$1\" in sing-box) cat \"$MODDIR/core.pid\" ;; magicnet-cli) test -f \"$MODDIR/worker-pids\" && cat \"$MODDIR/worker-pids\" ;; *) exit 1 ;; esac\n").unwrap();
    fs::write(
        fixture.root.join("lib/magicnet_singbox_subscribe.sh"),
        r#"
. "$MODDIR/lib/magicnet/singbox_subscribe/update.sh"
magicnet_singbox_update_lock_acquire() { mkdir "$MODDIR/held-update-lock"; }
magicnet_singbox_update_lock_release() { rmdir "$MODDIR/held-update-lock"; printf '%s\n' update_unlocked >>"$MODDIR/cancel-events"; }
magicnet_config_lock_release() { printf '%s\n' config_unlocked >>"$MODDIR/cancel-events"; }
magicnet_with_config_lock() {
    MAGICNET_CONFIG_LOCK_HELD=1
    "$@"
    _fixture_rc=$?
    MAGICNET_CONFIG_LOCK_HELD=0
    return "$_fixture_rc"
}
magicnet_singbox_transaction_reconcile() {
    test -f "$MODDIR/refresh-started" || return 0
    printf '%s\n' rollback_started >>"$MODDIR/cancel-events"
    sleep 0.25
    printf '%s\n' rollback_done >>"$MODDIR/cancel-events"
}
magicnet_singbox_status_mark_interrupted() { printf '%s\n' interrupted >>"$MODDIR/cancel-events"; }
magicnet_singbox_cleanup_stale_candidates() { :; }
magicnet_singbox_update_subscription_unlocked() {
    printf '%s\n' $$ >"$MODDIR/refresh-started"
    sleep 60 &
    wait
    printf '%s\n' should_not_finish >>"$MODDIR/cancel-events"
}
"#,
    )
    .unwrap();
    let foreign = Fixture::new();
    let worker = fixture.command(&["connectivity", "tick"]).spawn().unwrap();
    fs::write(
        fixture.root.join("worker-pids"),
        format!("{} {}", worker.id(), foreign.core.id()),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fixture.root.join("refresh-started").exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let started = Instant::now();
    let stop = fixture.command(&["service", "stop"]).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !fs::read_to_string(fixture.root.join("cancel-events"))
        .unwrap_or_default()
        .contains("rollback_started")
    {
        assert!(
            Instant::now() < deadline,
            "stop did not request cooperative rollback"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let lifecycle = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.root.join(".state/config-apply.lock"))
        .unwrap();
    assert_ne!(
        unsafe { libc::flock(lifecycle.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "recovery released lifecycle ownership before rollback finished"
    );
    let output = stop.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "stop waited for the 60-second fixture refresh"
    );
    assert!(worker.wait_with_output().unwrap().status.success());
    fixture.core.wait().unwrap();
    assert_eq!(
        fs::read_to_string(fixture.root.join("cancel-events")).unwrap(),
        "rollback_started\nrollback_done\ninterrupted\nconfig_unlocked\nupdate_unlocked\n"
    );
    assert!(!fixture.root.join("held-update-lock").exists());
    assert!(!fixture
        .root
        .join(".state/watchdog/magicnet-kernel.pid")
        .exists());
    let state = fixture.state();
    assert_eq!(state["phase"], "paused");
    assert_eq!(state["reason"], "stop_requested");
    assert_eq!(state["action_status"], "failed");
    assert_eq!(fixture.status()["reason"], "core_stopped");
    let calls = fixture.calls();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.calls(), calls);
    assert_eq!(
        unsafe { libc::kill(foreign.core.id() as i32, 0) },
        0,
        "an unrelated candidate must survive automatic-worker cancellation"
    );
}

#[test]
fn connectivity_machine_rejections_keep_the_complete_error_envelope() {
    let fixture = Fixture::new();
    for (args, code) in [
        (
            vec!["--json", "connectivity", "tick"],
            "machine.unsupported_command",
        ),
        (
            vec!["--json", "connectivity", "status", "extra"],
            "machine.unsupported_command",
        ),
        (
            vec!["--json", "--json", "connectivity", "status"],
            "machine.invalid_request",
        ),
    ] {
        let output = fixture.command(&args).output().unwrap();
        assert!(!output.status.success());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schema"], 1);
        assert_eq!(value["ok"], false);
        assert_eq!(value["command"], "machine.error");
        assert_eq!(value["error"]["code"], code);
        assert!(value["error"]["message"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
        assert!(value.get("data").is_none());
        assert_eq!(fixture.calls(), 0);
        assert!(!fixture
            .root
            .join(".state/machines/connectivity.state")
            .exists());
        assert!(!fixture.root.join(".state/connectivity.lock").exists());
    }
}
