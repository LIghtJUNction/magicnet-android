#![cfg(any(target_os = "android", target_os = "linux"))]

use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn identity(pid: i32) -> Option<(String, bool)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    Some((
        fields.get(19)?.to_string(),
        !matches!(fields.first()?, &"Z" | &"X"),
    ))
}

fn wait_until(mut condition: impl FnMut() -> bool, seconds: u64) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while !condition() {
        assert!(Instant::now() < deadline, "lifecycle deadline expired");
        thread::sleep(Duration::from_millis(10));
    }
}

struct Fixture {
    root: PathBuf,
    cli: Option<Child>,
    owned: Vec<(i32, String)>,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "magicnet-service-handoff-{}-{nonce}",
            std::process::id()
        ));
        for directory in [
            "bin",
            "lib/kamfw",
            "lib/magicnet/singbox_subscribe",
            ".config/sing-box",
            ".log",
            ".state",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("module.prop"), "id=MagicNet\n").unwrap();
        fs::write(root.join(".config/sing-box/config.json"), "{}\n").unwrap();
        fs::write(root.join("lib/kamfw/.kamfwrc"), "import() { :; }\n").unwrap();
        fs::write(
            root.join("lib/primitives.sh"),
            include_str!("../../../src/MagicNet/lib/magicnet/primitives.sh"),
        )
        .unwrap();
        fs::write(
            root.join("lib/magicnet/primitives.sh"),
            include_str!("../../../src/MagicNet/lib/magicnet/primitives.sh"),
        )
        .unwrap();
        fs::write(
            root.join("lib/magicnet/subscribe_bootstrap.sh"),
            include_str!("../../../src/MagicNet/lib/magicnet/subscribe_bootstrap.sh"),
        )
        .unwrap();
        fs::write(
            root.join("lib/magicnet/singbox_subscribe/bootstrap.sh"),
            include_str!("../../../src/MagicNet/lib/magicnet/singbox_subscribe/bootstrap.sh"),
        )
        .unwrap();
        fs::write(
            root.join("lib/subscription-config.sh"),
            include_str!("../../../src/MagicNet/lib/magicnet/singbox_subscribe/config.sh"),
        )
        .unwrap();
        fs::write(
            root.join("lib/common.sh"),
            include_str!("../../../src/MagicNet/lib/magicnet/common.sh"),
        )
        .unwrap();
        fs::write(
            root.join("lib/lifecycle.sh"),
            include_str!("../../../src/MagicNet/lib/magicnet/singbox_lifecycle.sh"),
        )
        .unwrap();
        fs::copy(
            env!("CARGO_BIN_EXE_magicnet-cli"),
            root.join("bin/magicnet-cli"),
        )
        .unwrap();
        fs::hard_link(root.join("bin/magicnet-cli"), root.join("cli")).unwrap();
        fs::write(
            root.join("lib/magicnet.sh"),
            r#"
set_i18n() { :; }
info() { :; }
warn() { :; }
success() { :; }
error() { printf '%s\n' "$*" >&2; }
i18n() { printf '%s\n' "$1"; }
print() { :; }
. "$MODDIR/lib/primitives.sh"
. "$MODDIR/lib/lifecycle.sh"
magicnet_proc_query_temp_create() { mktemp "$MODDIR/pids.XXXXXX"; }
singbox_pids_to_file() {
    : >"$1"
    [ -s "$MODDIR/core.pid" ] || return 1
    pid=$(cat "$MODDIR/core.pid")
    [ -r "/proc/$pid/stat" ] || return 1
    state=$(awk '{print $3}' "/proc/$pid/stat")
    [ "$state" != Z ] || return 1
    printf '%s\n' "$pid" >"$1"
}
is_singbox_running() { singbox_pids_to_file "$MODDIR/observed.pid"; }
singbox_prepare_dataplane() { :; }
singbox_prepare_route_config() { :; }
singbox_wait_ready() {
    while [ ! -s "$MODDIR/core.pid" ]; do sleep 0.01; done
    if [ "$MAGICNET_TEST_READY" = yes ]; then return 0; fi
    sleep 30 & wait
    return 1
}
magicnet_fswatch_start() {
    printf '%s\n' "$$" >"$MODDIR/worker.pid"
    singbox_start || return $?
    : >"$MODDIR/handed-off"
    sleep 30 & wait
}
"#,
        )
        .unwrap();
        fs::write(
            root.join("bin/sing-box"),
            r#"#!/bin/sh
awk '{print $4}' "/proc/$$/stat" >"$MODDIR/core-parent.pid"
printf '%s\n' "${MAGICNET_COMMAND_TIMEOUT-unset}" >"$MODDIR/core.timeout"
printf '%s\n' "${GOMEMLIMIT-unset}" >"$MODDIR/core.memory"
trap ': >"$MODDIR/terminated"; exit 0' TERM
printf '%s\n' "$$" >"$MODDIR/core.pid"
sleep 30 &
printf '%s\n' "$!" >"$MODDIR/core-child.pid"
wait
"#,
        )
        .unwrap();
        fs::set_permissions(root.join("bin/sing-box"), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            root,
            cli: None,
            owned: Vec::new(),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(self.root.join("cli"));
        command
            .env("MODDIR", &self.root)
            .env("GOMEMLIMIT", "96MiB")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn start(&mut self, ready: bool) -> i32 {
        self.start_with_timeout(ready, "1")
    }

    fn start_with_timeout(&mut self, ready: bool, timeout: &str) -> i32 {
        self.cli = Some(
            self.command()
                .args(["supervisor", "start", "fswatch"])
                .env("MAGICNET_COMMAND_TIMEOUT", timeout)
                .env("MAGICNET_TEST_READY", if ready { "yes" } else { "no" })
                .spawn()
                .unwrap(),
        );
        let core = self.pid("core.pid");
        self.pid("core-child.pid");
        self.pid("worker.pid");
        if ready {
            wait_until(|| self.root.join("handed-off").exists(), 5);
        }
        core
    }

    fn launch_command(&self) -> Command {
        let guard = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join(".state/config.lock.guard"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let mut command = self.command();
        command.arg("__singbox-launch").stdin(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(guard.as_raw_fd(), 8) == -1 || libc::fcntl(8, libc::F_SETFD, 0) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }

    fn config_writer(&self) -> bool {
        Command::new("sh")
            .args([
                "-c",
                r#"
import() { :; }
. "$MODDIR/lib/magicnet.sh"
. "$MODDIR/lib/common.sh"
MAGICNET_CONFIG_LOCK_TIMEOUT=0
magicnet_config_lock_acquire || exit 1
magicnet_config_lock_release
"#,
            ])
            .env("MODDIR", &self.root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    }

    fn pid(&mut self, file: &str) -> i32 {
        let path = self.root.join(file);
        let mut pid = 0;
        wait_until(
            || {
                pid = fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| text.trim().parse().ok())
                    .unwrap_or(0);
                pid > 0
            },
            5,
        );
        self.owned
            .push((pid, identity(pid).expect("owned process exited too soon").0));
        pid
    }

    fn kill_cli(&mut self) {
        self.cli.as_mut().unwrap().kill().unwrap();
        self.cli.as_mut().unwrap().wait().unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(cli) = self.cli.as_mut() {
            let _ = cli.kill();
            let _ = cli.wait();
        }
        for (pid, start) in &self.owned {
            if identity(*pid).is_some_and(|(current, live)| live && current == *start) {
                unsafe {
                    if libc::getpgid(*pid) == *pid {
                        libc::kill(-*pid, libc::SIGKILL);
                    }
                    libc::kill(*pid, libc::SIGKILL);
                }
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn ready_core_survives_controller_timeout_and_parent_death() {
    for killed in [false, true] {
        let mut fixture = Fixture::new();
        let core = fixture.start(true);
        assert_eq!(
            unsafe { libc::getpgid(core) },
            core,
            "core did not get its own process group"
        );
        if killed {
            fixture.kill_cli();
        }
        let worker = fs::read_to_string(fixture.root.join("worker.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        wait_until(|| identity(worker).is_none_or(|(_, live)| !live), 5);
        assert!(
            identity(core).is_some_and(|(_, live)| live),
            "ready core died with controller"
        );
        assert!(!fixture.root.join("terminated").exists());
        assert_eq!(
            fs::read_to_string(fixture.root.join("core.timeout")).unwrap(),
            "unset\n"
        );
        assert_eq!(
            fs::read_to_string(fixture.root.join("core.memory")).unwrap(),
            "96MiB\n"
        );
        let startup_worker = fs::read_to_string(fixture.root.join("core-parent.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            identity(startup_worker).is_none_or(|(_, live)| !live),
            "startup worker stayed resident"
        );
        assert!(
            fixture.config_writer(),
            "ready core retained the metadata flock"
        );
    }
}

#[test]
fn unready_core_is_reclaimed_after_controller_timeout_and_sigkill() {
    for killed in [false, true] {
        let mut fixture = Fixture::new();
        let core = fixture.start(false);
        if killed {
            fixture.kill_cli();
        }
        wait_until(|| identity(core).is_none_or(|(_, live)| !live), 5);
        assert!(
            fixture.root.join("terminated").exists(),
            "partial core missed graceful TERM"
        );
        assert!(!fixture.root.join("handed-off").exists());
        let descendant = fs::read_to_string(fixture.root.join("core-child.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        wait_until(|| identity(descendant).is_none_or(|(_, live)| !live), 2);
    }
}

#[test]
fn launcher_sigkill_before_readiness_still_reclaims_core() {
    let mut fixture = Fixture::new();
    fixture.cli = Some(fixture.launch_command().spawn().unwrap());
    let core = fixture.pid("core.pid");
    fixture.pid("core-child.pid");
    fixture.kill_cli();
    wait_until(|| identity(core).is_none_or(|(_, live)| !live), 5);
    assert!(fixture.root.join("terminated").exists());
}

#[test]
fn invalid_acknowledgement_and_eof_reclaim_pending_core() {
    for marker in [Some(b'X'), None] {
        let mut fixture = Fixture::new();
        fixture.cli = Some(fixture.launch_command().spawn().unwrap());
        let core = fixture.pid("core.pid");
        fixture.pid("core-child.pid");
        let mut pipe = fixture.cli.as_mut().unwrap().stdin.take().unwrap();
        if let Some(marker) = marker {
            pipe.write_all(&[marker]).unwrap();
        }
        drop(pipe);
        wait_until(|| identity(core).is_none_or(|(_, live)| !live), 5);
        assert!(!fixture.cli.as_mut().unwrap().wait().unwrap().success());
    }
}

#[test]
fn machine_and_non_pipe_invocations_cannot_launch_core() {
    let fixture = Fixture::new();
    for args in [
        vec!["__singbox-launch"],
        vec!["__singbox-launch", "--json"],
        vec!["--json", "__singbox-launch"],
        vec!["__singbox-launch-worker", "--json"],
        vec!["--json", "__singbox-launch-worker"],
    ] {
        assert!(!fixture.command().args(args).status().unwrap().success());
        assert!(!fixture.root.join("core.pid").exists());
    }
}

#[test]
fn pending_core_cleanup_holds_config_guard_after_controller_death() {
    let mut fixture = Fixture::new();
    let core_path = fixture.root.join("bin/sing-box");
    let source = fs::read_to_string(&core_path).unwrap().replace(
        "trap ': >\"$MODDIR/terminated\"; exit 0' TERM",
        "trap ': >\"$MODDIR/terminated\"; sleep 2; : >\"$MODDIR/cleanup-finished\"; exit 0' TERM",
    );
    fs::write(&core_path, source).unwrap();
    let core = fixture.start(false);
    let worker: i32 = fs::read_to_string(fixture.root.join("worker.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    fs::create_dir(fixture.root.join(".state/config.lock")).unwrap();
    fs::write(
        fixture.root.join(".state/config.lock/pid"),
        format!("{worker}:{}\n", identity(worker).unwrap().0),
    )
    .unwrap();
    fixture.kill_cli();
    wait_until(|| fixture.root.join("terminated").exists(), 5);
    assert!(!fixture.root.join("cleanup-finished").exists());
    assert!(
        !fixture.config_writer(),
        "second writer entered during core cleanup"
    );
    wait_until(|| identity(core).is_none_or(|(_, live)| !live), 5);
    wait_until(|| fixture.config_writer(), 3);
}

#[test]
fn launcher_death_kills_term_ignoring_descendant_after_leader_exits() {
    let mut fixture = Fixture::new();
    let core_path = fixture.root.join("bin/sing-box");
    let source = fs::read_to_string(&core_path).unwrap().replace(
        "sleep 30 &\nprintf '%s\\n' \"$!\" >\"$MODDIR/core-child.pid\"",
        "sh -c 'trap \"\" TERM; printf \"%s\\n\" \"$$\" >\"$MODDIR/core-child.pid\"; sleep 30 & wait' &",
    );
    fs::write(&core_path, source).unwrap();
    fixture.cli = Some(fixture.launch_command().spawn().unwrap());
    let core = fixture.pid("core.pid");
    let descendant = fixture.pid("core-child.pid");
    fixture.kill_cli();
    wait_until(|| identity(core).is_none_or(|(_, live)| !live), 5);
    wait_until(|| identity(descendant).is_none_or(|(_, live)| !live), 3);
    assert!(
        fixture.config_writer(),
        "failed startup left its metadata guard locked"
    );
}

#[test]
fn short_supervisor_budget_does_not_reach_later_daemon_commands() {
    let mut fixture = Fixture::new();
    fs::write(fixture.root.join("lib/magicnet.sh"), r#"
magicnet_fswatch_start() {
    sh -c 'sleep 1.2; "$MODDIR/cli" supervisor start wifi-policy' </dev/null >"$MODDIR/daemon.log" 2>&1 &
    printf '%s\n' "$!" >"$MODDIR/daemon.pid"
}

magicnet_wifi_policy_start() {
    sleep 2
    printf '%s\n' "${MAGICNET_COMMAND_TIMEOUT-unset}" >"$MODDIR/daemon.completed"
}
"#).unwrap();
    fixture.cli = Some(
        fixture
            .command()
            .args(["supervisor", "start", "fswatch"])
            .env("MAGICNET_COMMAND_TIMEOUT", "1")
            .spawn()
            .unwrap(),
    );
    fixture.pid("daemon.pid");
    wait_until(|| fixture.root.join("daemon.completed").exists(), 7);
    assert_eq!(
        fs::read_to_string(fixture.root.join("daemon.completed")).unwrap(),
        "unset\n"
    );
}

#[test]
fn subscription_activation_uses_the_same_service_handoff() {
    let mut fixture = Fixture::new();
    let module = fixture.root.join("lib/magicnet.sh");
    let mut source = fs::read_to_string(&module).unwrap().replace(
        "    singbox_start || return $?",
        "    magicnet_singbox_ensure_start_owned \"$MODDIR/.config/sing-box/config.json\" || return $?",
    );
    source.push_str(
        r#"
magicnet_singbox_api_listener_exists() { return 1; }
. "$MODDIR/lib/subscription-config.sh"
magicnet_singbox_owned_pids_to_file() { singbox_pids_to_file "$2"; }
magicnet_singbox_config_has_clash_api() { return 1; }
"#,
    );
    fs::write(module, source).unwrap();
    // The subscription readiness probe polls once per second. Leave room for
    // its first empty probe without changing the one-second timeout cases.
    let core = fixture.start_with_timeout(true, "3");
    fixture.kill_cli();
    let worker = fs::read_to_string(fixture.root.join("worker.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    wait_until(|| identity(worker).is_none_or(|(_, live)| !live), 5);
    assert!(identity(core).is_some_and(|(_, live)| live));
    assert!(!fixture.root.join("terminated").exists());
    assert!(fixture.config_writer());
}
