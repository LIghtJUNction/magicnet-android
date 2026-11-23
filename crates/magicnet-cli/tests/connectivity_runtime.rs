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
            r#"{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":7892}],"outbounds":[{"type":"selector","tag":"proxy","outbounds":["node-a"]},{"type":"vmess","tag":"node-a"}]}"#,
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
url= method=GET body= previous=
for argument in "$@"; do
  case "$previous" in -X|--request) method=$argument ;; --data|--data-binary|--data-raw) body=$argument ;; esac
  case "$argument" in http://*|https://*) url=$argument ;; esac
  previous=$argument
done
proxy=$(cat "$MODDIR/selected-proxy")
ai=$(cat "$MODDIR/selected-ai-proxy")
restricted=$(cat "$MODDIR/selected-restricted-ai")
members='"node-a"'
test ! -f "$MODDIR/allow-failover" || members='"node-a","node-b"'
group_json() {
  case "$1" in
    proxy) printf '{"type":"Selector","now":"%s","all":[%s]}' "$proxy" "$members" ;;
    ai-proxy) printf '{"type":"Selector","now":"%s","all":["node-a","node-b"]}' "$ai" ;;
    restricted-ai) printf '{"type":"Selector","now":"%s","all":["node-a"]}' "$restricted" ;;
    node-a|node-b) printf '{"type":"VMess"}' ;;
    *) exit 22 ;;
  esac
}
case "$url" in
  */configs) printf '{"mode":"%s"}' "$(cat "$MODDIR/clash-mode")"; exit 0 ;;
  */connections) printf '{"connections":[]}'; exit 0 ;;
  */proxies)
    printf '{"proxies":{"proxy":'; group_json proxy
    printf ',"ai-proxy":'; group_json ai-proxy
    printf ',"restricted-ai":'; group_json restricted-ai
    printf ',"node-a":{"type":"VMess"},"node-b":{"type":"VMess"}}}'; exit 0 ;;
  */proxies/*/delay\?*) ;;
  */proxies/*)
    group=${url##*/}
    if test "$method" = PUT; then
      node=$(printf '%s' "$body" | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
      test -n "$node" || exit 22
      printf '%s' "$node" >"$MODDIR/selected-$group"
      printf '%s=%s\n' "$group" "$node" >>"$MODDIR/selector-changes"
    else
      if test "$group" = proxy && test "$proxy" = node-b && test -f "$MODDIR/unreadable-after-put"; then exit 22; fi
      group_json "$group"
    fi
    exit 0 ;;
esac
printf '%s\n' "$*" >>"$MODDIR/calls"
test ! -f "$MODDIR/slow" || sleep 0.2
mode=$(cat "$MODDIR/mode")
case "$url" in
  */proxies/*/delay\?*)
    case "$url" in */proxies/node-b/delay*)
      if test -f "$MODDIR/slow-candidate"; then
        : >"$MODDIR/candidate-started"
        sleep 0.7
      fi ;;
    esac
    case "$url" in
      */proxies/proxy/delay*) selected=$proxy ;;
      */proxies/node-b/delay*) selected=node-b ;;
      *) selected=node-a ;;
    esac
    reason= status=null
    case "$mode:$selected:$url" in
      old-core:*) printf '{"delay":4}'; exit 0 ;;
      unsupported-error:*) exit 22 ;;
      down:*) reason=timeout ;;
      dns:*) reason=transport_failure ;;
      masked:node-a:*|failover:node-a:*|verify-fails:node-a:*) reason=timeout ;;
      google:*google.com*) reason=http_status; status=500 ;;
    esac
    if test -n "$reason"; then
      printf '{"strict_probe":true,"expected_status":204,"ok":false,"reason":"%s","http_status":%s}' "$reason" "$status"
    else printf '{"strict_probe":true,"expected_status":204,"ok":true,"http_status":204,"delay":4}'; fi ;;
  *baidu*)
    if test "$mode" = dns; then printf '000 0.001'; exit 6; fi
    printf '200 0.002' ;;
  *)
    case "$mode:$proxy:$url" in
      dns:*) printf '000 0.001'; exit 6 ;;
      down:*|mixed-down:*|verify-fails:*|failover:node-a:*) printf '000 0.010'; exit 28 ;;
      google:*google.com*) printf '500 0.003' ;;
      *) printf '204 0.004' ;;
    esac ;;
esac
"#,
        );
        fs::write(root.join("mode"), "online").unwrap();
        fs::write(root.join("clash-mode"), "rule").unwrap();
        for group in ["proxy", "ai-proxy", "restricted-ai"] {
            fs::write(root.join(format!("selected-{group}")), "node-a").unwrap();
        }
        fs::write(root.join("lib/kamfw/.kamfwrc"), "import() { :; }\n").unwrap();
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src/MagicNet/lib");
        fs::create_dir_all(root.join("lib/magicnet/singbox_subscribe")).unwrap();
        for path in [
            "magicnet/common.sh",
            "magicnet/primitives.sh",
            "magicnet/subscribe_bootstrap.sh",
            "magicnet/singbox_subscribe/bootstrap.sh",
        ] {
            fs::copy(source.join(path), root.join("lib").join(path)).unwrap();
        }
        fs::write(
            root.join("lib/magicnet.sh"),
            r#"
. "$MODDIR/lib/magicnet/common.sh"
magicnet_warn() { :; }
magicnet_notify() { printf '%s\n' "$*" >>"$MODDIR/notifications"; }
magicnet_after_kernel_start_unlocked() { printf '%s\n' repair >>"$MODDIR/actions"; }
magicnet_connectivity_watchdog_start() { :; }
magicnet_lifecycle_after_stop() {
    printf '%s\n' cleanup >>"$MODDIR/cleanup-actions"
    test ! -f "$MODDIR/cleanup-fails" || return 1
    rm -f "$MODDIR/dns-capture-attached"
}
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

    fn config(&self, mut config: Value) {
        let previous: Value = serde_json::from_slice(
            &fs::read(self.root.join(".config/sing-box/config.json")).unwrap(),
        )
        .unwrap();
        if config.get("outbounds").is_none() {
            config["outbounds"] = previous["outbounds"].clone();
        }
        fs::write(
            self.root.join(".config/sing-box/config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
    }

    fn enable_failover(&self) {
        fs::write(self.root.join("allow-failover"), "").unwrap();
        self.config(serde_json::json!({
            "inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":7892}],
            "outbounds":[
                {"type":"selector","tag":"proxy","outbounds":["node-a","node-b"]},
                {"type":"selector","tag":"ai-proxy","outbounds":["node-a","node-b"]},
                {"type":"selector","tag":"restricted-ai","outbounds":["node-a"]},
                {"type":"vmess","tag":"node-a"},{"type":"vmess","tag":"node-b"}
            ]
        }));
    }

    fn selected(&self, group: &str) -> String {
        fs::read_to_string(self.root.join(format!("selected-{group}"))).unwrap()
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
magicnet_with_sub_config_lock() { "$@"; }
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
        3,
        "concurrent producers share one two-site directed check and one mixed check"
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
    assert_eq!(fixture.calls(), 3);
    let encoded = status.to_string();
    assert!(!encoded.contains("private-source"));
    assert!(!encoded.contains(&state["boot"]));
}

#[test]
fn connectivity_tun_checks_are_independent_of_successful_mixed_proxy_probes() {
    let fixture = Fixture::new();
    fixture.config(serde_json::json!({"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":7892},{"type":"tun","tag":"tun-in","interface_name":"magicnet0","address":["172.19.0.1/30"],"auto_route":true}]}));
    fs::write(
        fixture.root.join("bin/ip"),
        r#"#!/bin/sh
case "$*" in
  *'table all default') printf '%s\n' 'default via 192.0.2.1 dev test0' ;;
  '-4 -N rule show')
    test ! -f "$MODDIR/rules-unknown" || exit 1
    cat "$MODDIR/rules" ;;
  '-4 route show table  2022') cat "$MODDIR/routes" ;;
  *) exit 64 ;;
esac
"#,
    )
    .unwrap();
    let routes = fixture.root.join("routes");
    fs::write(&routes, "default dev magicnet0 scope link\n").unwrap();
    fs::write(fixture.root.join("rules"), "0: from all lookup 255\n9001: from all iif magicnet0 goto 9010\n9002: not from all iif lo lookup 2022\n9002: from 0.0.0.0 iif lo lookup 2022\n9002: from 172.19.0.0/30 iif lo lookup 2022\n9010: from all nop\n").unwrap();
    fixture.run(&["connectivity", "tick"]);
    let status = fixture.status();
    assert_eq!(status["status"], "online");
    assert_eq!(status["tun_auto_route"]["status"], "present");
    assert_eq!(fixture.calls(), 3);

    fs::write(&routes, "default tos 0x10 dev magicnet0 scope link\n").unwrap();
    fixture.edit_state(&[
        ("tun_next_uptime", "0"),
        ("tun_failures", "2"),
        ("tun_status", "missing"),
    ]);
    fixture.run(&["connectivity", "tick"]);
    let conditional = fixture.status();
    assert_eq!(conditional["status"], "online");
    assert_eq!(conditional["tun_auto_route"]["status"], "unknown");
    assert_eq!(conditional["tun_auto_route"]["warning"], true);
    assert_eq!(conditional["tun_auto_route"]["consecutive_failures"], 0);
    assert_eq!(conditional["tun_auto_route"]["recovery_attempts"], 0);
    assert_eq!(fixture.calls(), 3);
    assert!(!fixture.root.join("actions").exists());
    fs::write(&routes, "default dev magicnet0 scope link\n").unwrap();

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
        3,
        "a TUN check does not issue another HTTPS request"
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
    assert_eq!(unknown["warning"], true);
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
    assert_eq!(fixture.calls(), 3);
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_real_failure_attempts_warning_backoff_repair_and_subscription_refresh() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode"), "down").unwrap();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(
        fixture.calls(),
        4,
        "two directed sites, direct control, and mixed ingress"
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
    assert_eq!(fixture.calls(), 4);
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
    assert_eq!(fixture.status()["reason"], "probe_unavailable");
    fixture.edit_state(&[("next_uptime", "0")]);
    fs::write(fixture.root.join("no-route"), "").unwrap();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["reason"], "no_default_route");
    assert_eq!(fixture.calls(), 0);
    fs::remove_file(fixture.root.join("no-route")).unwrap();
    fs::write(
        fixture.root.join(".config/sing-box/config.json"),
        r#"{"inbounds":[{"type":"mixed","listen_port":7892}],"outbounds":[{"type":"selector","tag":"proxy","outbounds":["node-a"]},{"type":"vmess","tag":"node-a"}]}"#,
    )
    .unwrap();
    fs::write(fixture.root.join("mode"), "dns").unwrap();
    fixture.edit_state(&[("next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["status"], "offline");
    assert_eq!(fixture.status()["reason"], "upstream_unavailable");
    assert_eq!(fixture.status()["primary_reason"], "transport_failure");
    assert_eq!(fixture.calls(), 4);
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_stopped_core_and_module_disable_prevent_every_probe_and_action() {
    let mut fixture = Fixture::new();
    fs::write(fixture.root.join("disable"), "").unwrap();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.calls(), 0);
    assert_eq!(fixture.status()["reason"], "module_disabled");
    assert!(!fixture.root.join("cleanup-actions").exists());
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
fn connectivity_crashed_core_releases_interception_without_probing_or_restarting() {
    let mut fixture = Fixture::new();
    fixture.run(&["connectivity", "tick"]);
    fs::write(fixture.root.join("dns-capture-attached"), "1053").unwrap();
    unsafe { libc::kill(-(fixture.core.id() as i32), libc::SIGKILL) };
    fixture.core.wait().unwrap();
    // Crash cleanup follows the local watchdog interval, not the independent
    // five-minute HTTPS schedule. A status read must remain read-only.
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    assert_eq!(fixture.status()["reason"], "core_stopped");
    assert!(fixture.root.join("dns-capture-attached").exists());
    fixture.run(&["connectivity", "tick"]);
    assert!(!fixture.root.join("dns-capture-attached").exists());
    assert_eq!(
        fs::read_to_string(fixture.root.join("cleanup-actions")).unwrap(),
        "cleanup\n"
    );
    assert_eq!(fixture.calls(), 3);
    assert!(!fixture.root.join("actions").exists());
    assert_eq!(fixture.status()["status"], "paused");
    assert_eq!(fixture.status()["reason"], "core_stopped");
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(
        fs::read_to_string(fixture.root.join("cleanup-actions")).unwrap(),
        "cleanup\n"
    );
}

#[test]
fn connectivity_pending_manual_check_does_not_block_crashed_core_cleanup() {
    let mut fixture = Fixture::new();
    fixture.run(&["connectivity", "tick"]);
    fs::write(fixture.root.join("dns-capture-attached"), "1053").unwrap();
    unsafe { libc::kill(-(fixture.core.id() as i32), libc::SIGKILL) };
    fixture.core.wait().unwrap();

    fixture.run(&["connectivity", "check"]);
    assert_eq!(fixture.status()["reason"], "core_stopped");
    assert!(fixture.root.join("dns-capture-attached").exists());
    assert!(!fixture.root.join("cleanup-actions").exists());
    assert_eq!(
        fixture.calls(),
        3,
        "a manual check cannot probe a stopped core"
    );

    // The queued observation must not veto the next background cleanup.
    fixture.run(&["connectivity", "tick"]);
    assert!(!fixture.root.join("dns-capture-attached").exists());
    assert_eq!(
        fs::read_to_string(fixture.root.join("cleanup-actions")).unwrap(),
        "cleanup\n"
    );
    assert_eq!(fixture.status()["status"], "paused");
    assert_eq!(fixture.status()["reason"], "core_stopped");
    assert_eq!(fixture.calls(), 3);
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_crash_cleanup_defers_lifecycle_contention_and_retries_failures() {
    let mut fixture = Fixture::new();
    fixture.run(&["connectivity", "tick"]);
    fs::write(fixture.root.join("dns-capture-attached"), "1053").unwrap();
    unsafe { libc::kill(-(fixture.core.id() as i32), libc::SIGKILL) };
    fixture.core.wait().unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(fixture.root.join(".state/config-apply.lock"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert!(fixture.root.join("dns-capture-attached").exists());
    assert!(!fixture.root.join("cleanup-actions").exists());
    drop(lock);
    fs::write(fixture.root.join("cleanup-fails"), "").unwrap();
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    let failed = fixture.command(&["connectivity", "tick"]).output().unwrap();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("connectivity.cleanup_failed"));
    assert!(fixture.root.join("dns-capture-attached").exists());
    assert_eq!(fixture.status()["status"], "paused");
    fs::remove_file(fixture.root.join("cleanup-fails")).unwrap();
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert!(!fixture.root.join("dns-capture-attached").exists());
    assert_eq!(
        fs::read_to_string(fixture.root.join("cleanup-actions")).unwrap(),
        "cleanup\ncleanup\n"
    );
    assert_eq!(fixture.calls(), 3);
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_unknown_core_cannot_authorize_crash_cleanup() {
    let fixture = Fixture::new();
    fixture.run(&["connectivity", "tick"]);
    fs::write(fixture.root.join("dns-capture-attached"), "1053").unwrap();
    fs::write(fixture.root.join("bin/pidof"), "#!/bin/sh\nexit 2\n").unwrap();
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["status"], "unknown");
    assert!(fixture.root.join("dns-capture-attached").exists());
    assert!(!fixture.root.join("cleanup-actions").exists());
    assert_eq!(fixture.calls(), 3);
}

#[test]
fn connectivity_crash_cleanup_respects_the_shell_startup_lock() {
    let mut fixture = Fixture::new();
    fixture.run(&["connectivity", "tick"]);
    unsafe { libc::kill(-(fixture.core.id() as i32), libc::SIGKILL) };
    fixture.core.wait().unwrap();
    let startup_lock = fixture.root.join(".state/config.lock");
    fs::create_dir(&startup_lock).unwrap();
    fs::write(startup_lock.join("pid"), std::process::id().to_string()).unwrap();
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    assert!(!fixture
        .command(&["connectivity", "tick"])
        .output()
        .unwrap()
        .status
        .success());
    assert!(startup_lock.join("pid").is_file());
    assert!(!fixture.root.join("cleanup-actions").exists());
    fs::remove_file(startup_lock.join("pid")).unwrap();
    fs::remove_dir(startup_lock).unwrap();
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(
        fs::read_to_string(fixture.root.join("cleanup-actions")).unwrap(),
        "cleanup\n"
    );
    assert_eq!(fixture.calls(), 3);
}

#[test]
fn connectivity_rechecks_a_stopped_core_before_cleanup() {
    let fixture = Fixture::new();
    fixture.run(&["connectivity", "tick"]);
    fs::write(
        fixture.root.join("bin/pidof"),
        r#"#!/bin/sh
test "$1" = sing-box || exit 1
if [ ! -f "$MODDIR/discovered-once" ]; then
    touch "$MODDIR/discovered-once"
    exit 1
fi
cat "$MODDIR/core.pid"
"#,
    )
    .unwrap();
    fixture.edit_state(&[("tun_next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert!(!fixture.root.join("cleanup-actions").exists());
    assert_eq!(fixture.calls(), 3);
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
    while fixture.calls() < 5 {
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
            vec!["--json", "connectivity", "check"],
            "machine.unsupported_command",
        ),
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

#[test]
fn connectivity_selected_failure_is_visible_even_when_domain_routing_mixed_probe_succeeds() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode"), "masked").unwrap();
    fixture.run(&["connectivity", "tick"]);
    let status = fixture.status();
    assert_eq!(status["path"], "selected_proxy");
    assert_eq!(status["status"], "offline");
    assert_eq!(status["primary_reason"], "timeout");
    assert_eq!(status["secondary_status"], "failed");
    assert_eq!(status["direct_status"], "online");
    assert_eq!(status["mixed_status"], "online");
    assert_eq!(status["warning"], true);
    assert_eq!(fixture.calls(), 4);
}

#[test]
fn connectivity_working_selected_proxy_requires_a_working_mixed_ingress_for_online() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode"), "mixed-down").unwrap();
    fixture.run(&["connectivity", "tick"]);
    let status = fixture.status();
    assert_eq!(status["status"], "degraded");
    assert_eq!(status["reason"], "mixed_path_failed");
    assert_eq!(status["primary_reason"], "ok");
    assert_eq!(status["http_status"], 204);
    assert_eq!(status["secondary_status"], "online");
    assert_eq!(status["mixed_status"], "failed");
    assert_eq!(status["mixed_reason"], "timeout");
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_legacy_delay_or_unmarked_error_cannot_authorize_online_or_recovery() {
    for (mode, reason) in [
        ("old-core", "probe_unsupported"),
        ("unsupported-error", "probe_unavailable"),
    ] {
        let fixture = Fixture::new();
        fixture.enable_failover();
        fs::write(fixture.root.join("mode"), mode).unwrap();
        fixture.run(&["connectivity", "tick"]);
        fixture.edit_state(&[("next_uptime", "0")]);
        fixture.run(&["connectivity", "tick"]);
        let status = fixture.status();
        assert_eq!(status["status"], "unknown", "{mode}");
        assert_eq!(status["reason"], reason);
        assert_eq!(status["consecutive_failures"], 0);
        assert_eq!(status["secondary_status"], "unknown");
        assert_eq!(status["direct_status"], "not_run");
        assert_eq!(status["mixed_status"], "online");
        assert_eq!(status["last_action"], "none");
        assert!(!fixture.root.join("selector-changes").exists());
        assert!(!fixture.root.join("actions").exists());
    }
}

#[test]
fn connectivity_manual_check_bypasses_observation_backoff_without_recovery_or_cooldown_reset() {
    let fixture = Fixture::new();
    fixture.enable_failover();
    fs::write(fixture.root.join("mode"), "down").unwrap();
    fixture.run(&["connectivity", "tick"]);
    let now = fixture.state()["checked_uptime"].parse::<u64>().unwrap();
    fixture.edit_state(&[
        ("failures", "7"),
        ("next_uptime", &(now + 1800).to_string()),
        ("last_action", "refresh"),
        ("action_uptime", &now.to_string()),
        ("refresh_uptime", &now.to_string()),
        ("recovery_stage", "2"),
        ("tun_attempts", "2"),
        ("tun_action_uptime", &now.to_string()),
    ]);
    let before = fixture.state();
    fixture.run(&["connectivity", "check"]);
    let after = fixture.state();
    assert_eq!(fixture.calls(), 8);
    assert_eq!(after["failures"], "8");
    for field in [
        "action_uptime",
        "refresh_uptime",
        "recovery_stage",
        "tun_action_uptime",
        "tun_attempts",
    ] {
        assert_eq!(after[field], before[field], "{field}");
    }
    assert_eq!(fixture.status()["status"], "offline");
    assert!(!fixture.root.join("selector-changes").exists());
    assert!(!fixture.root.join("actions").exists());
    let second = fixture
        .command(&["connectivity", "check"])
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("connectivity.check_throttled"));
    assert_eq!(fixture.calls(), 8);
    assert_eq!(
        fixture.state(),
        after,
        "throttled requests do not rewrite observations or action budgets"
    );
}

#[test]
fn connectivity_manual_selection_requests_real_check_and_replaces_cached_outage_without_waiting() {
    let fixture = Fixture::new();
    fixture.enable_failover();
    fs::write(fixture.root.join("mode"), "failover").unwrap();
    fixture.run(&["connectivity", "tick"]);
    let now = fixture.state()["checked_uptime"].parse::<u64>().unwrap();
    fixture.edit_state(&[
        ("next_uptime", &(now + 1800).to_string()),
        ("action_uptime", &now.to_string()),
        ("refresh_uptime", &now.to_string()),
        ("recovery_stage", "2"),
    ]);
    fixture.run(&["api", "select", "proxy", "node-b"]);
    assert_eq!(fixture.status()["status"], "pending");
    assert_eq!(fixture.status()["reason"], "selection_changed");
    assert_eq!(
        fixture.calls(),
        4,
        "request scheduling itself never reports a successful probe"
    );
    fixture.run(&["connectivity", "tick"]);
    let state = fixture.state();
    assert_eq!(fixture.status()["status"], "online");
    assert_eq!(fixture.calls(), 7);
    assert_eq!(state["action_uptime"], now.to_string());
    assert_eq!(state["refresh_uptime"], now.to_string());
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_selection_changed_during_probe_never_publishes_the_old_result_for_new_node() {
    let fixture = Fixture::new();
    fixture.enable_failover();
    fixture.run(&["connectivity", "tick"]);
    fixture.edit_state(&[("next_uptime", "0")]);
    fs::write(fixture.root.join("slow"), "").unwrap();
    let child = fixture.command(&["connectivity", "tick"]).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while fixture.calls() < 4 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    fixture.run(&["api", "select", "proxy", "node-b"]);
    assert!(child.wait_with_output().unwrap().status.success());
    assert_eq!(fixture.state()["reason"], "selection_changed");
    assert_eq!(
        fixture.state()["probes"],
        "1",
        "mixed snapshots are discarded before recording"
    );
    assert_eq!(fixture.status()["status"], "pending");
    fs::remove_file(fixture.root.join("slow")).unwrap();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["status"], "online");
    assert_eq!(fixture.state()["probes"], "2");
}

#[test]
fn connectivity_direct_or_unknown_clash_mode_disables_automatic_selector_and_lifecycle_actions() {
    for mode in ["direct", "unknown"] {
        let fixture = Fixture::new();
        fixture.enable_failover();
        fs::write(fixture.root.join("mode"), "masked").unwrap();
        fs::write(fixture.root.join("clash-mode"), mode).unwrap();
        fixture.run(&["connectivity", "tick"]);
        fixture.edit_state(&[("next_uptime", "0")]);
        fixture.run(&["connectivity", "tick"]);
        assert_eq!(fixture.status()["status"], "offline");
        assert_eq!(fixture.status()["last_action"], "none");
        assert_eq!(fixture.selected("proxy"), "node-a");
        assert!(!fixture.root.join("selector-changes").exists());
        assert!(!fixture.root.join("actions").exists());
    }
}

#[test]
fn connectivity_verified_failover_updates_only_compatible_selectors_and_saves_restart_intent() {
    let fixture = Fixture::new();
    fixture.enable_failover();
    fs::write(fixture.root.join("mode"), "failover").unwrap();
    fixture.run(&["connectivity", "tick"]);
    fixture.edit_state(&[("next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    let status = fixture.status();
    assert_eq!(status["status"], "online");
    assert_eq!(status["last_action"], "failover");
    assert_eq!(status["action_status"], "ok");
    assert_eq!(fixture.selected("proxy"), "node-b");
    assert_eq!(fixture.selected("ai-proxy"), "node-b");
    assert_eq!(fixture.selected("restricted-ai"), "node-a");
    let saved: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join(".config/magicnet/selector-selections.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(saved["proxy"], "node-b");
    assert_eq!(saved["ai-proxy"], "node-b");
    assert!(saved.get("restricted-ai").is_none());
    assert_eq!(
        fixture.calls(),
        13,
        "two failing cycles, one two-site candidate, and three verification probes"
    );
    assert!(!fixture.root.join("actions").exists());
    let encoded = status.to_string();
    assert!(!encoded.contains("node-a") && !encoded.contains("node-b"));
}

#[test]
fn connectivity_failed_verification_rolls_back_every_changed_selector_and_persisted_choice() {
    let fixture = Fixture::new();
    fixture.enable_failover();
    fs::write(fixture.root.join("mode"), "verify-fails").unwrap();
    fixture.run(&["connectivity", "tick"]);
    fixture.edit_state(&[("next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["status"], "offline");
    assert_eq!(fixture.status()["last_action"], "failover");
    assert_eq!(fixture.status()["action_status"], "failed");
    assert_eq!(fixture.selected("proxy"), "node-a");
    assert_eq!(fixture.selected("ai-proxy"), "node-a");
    let saved: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join(".config/magicnet/selector-selections.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(saved.get("proxy").is_none());
    assert!(saved.get("ai-proxy").is_none());
    let changes = fs::read_to_string(fixture.root.join("selector-changes")).unwrap();
    assert_eq!(
        changes.lines().collect::<Vec<_>>(),
        [
            "proxy=node-b",
            "ai-proxy=node-b",
            "ai-proxy=node-a",
            "proxy=node-a"
        ]
    );
}

#[test]
fn connectivity_unwritable_saved_selection_prevents_runtime_change_and_false_success() {
    let fixture = Fixture::new();
    fixture.enable_failover();
    fs::create_dir_all(
        fixture
            .root
            .join(".config/magicnet/selector-selections.json"),
    )
    .unwrap();
    fs::write(fixture.root.join("mode"), "failover").unwrap();
    fixture.run(&["connectivity", "tick"]);
    fixture.edit_state(&[("next_uptime", "0")]);
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.status()["status"], "offline");
    assert_eq!(fixture.status()["action_status"], "failed");
    assert_eq!(fixture.selected("proxy"), "node-a");
    assert!(!fixture.root.join("selector-changes").exists());
    assert!(!fixture.root.join("actions").exists());
}

#[test]
fn connectivity_manual_a_to_b_to_a_during_candidate_probe_wins_over_automatic_failover() {
    let fixture = Fixture::new();
    fixture.enable_failover();
    fs::write(fixture.root.join("mode"), "failover").unwrap();
    fixture.run(&["connectivity", "tick"]);
    fixture.edit_state(&[("next_uptime", "0")]);
    fs::write(fixture.root.join("slow-candidate"), "").unwrap();
    let child = fixture.command(&["connectivity", "tick"]).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fixture.root.join("candidate-started").exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    fixture.run(&["api", "select", "proxy", "node-b"]);
    fixture.run(&["api", "select", "proxy", "node-a"]);
    assert!(child.wait_with_output().unwrap().status.success());
    assert_eq!(fixture.selected("proxy"), "node-a");
    assert_eq!(fixture.selected("ai-proxy"), "node-a");
    assert_eq!(fixture.state()["action_status"], "conflict");
    assert_eq!(fixture.status()["status"], "pending");
    assert_eq!(
        fs::read_to_string(fixture.root.join("selector-changes")).unwrap(),
        "proxy=node-b\nproxy=node-a\n"
    );
}

#[test]
fn connectivity_failed_inner_compensation_is_not_mislabeled_as_a_completed_rollback() {
    let fixture = Fixture::new();
    fixture.enable_failover();
    fs::write(fixture.root.join("mode"), "failover").unwrap();
    fs::write(fixture.root.join("unreadable-after-put"), "").unwrap();
    fixture.run(&["connectivity", "tick"]);
    fixture.edit_state(&[("next_uptime", "0")]);
    let output = fixture.command(&["connectivity", "tick"]).output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("connectivity.failover_rollback_failed")
    );
    assert_eq!(fixture.status()["action_status"], "rollback_failed");
    assert_eq!(fixture.status()["status"], "offline");
    assert_eq!(
        fixture.selected("proxy"),
        "node-b",
        "unobservable API prevented compensation"
    );
    assert_eq!(fixture.selected("ai-proxy"), "node-a");
    let saved: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join(".config/magicnet/selector-selections.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        saved.get("proxy").is_none(),
        "persistent intent is still restored independently"
    );
}

#[test]
fn connectivity_tun_cached_generation_projection_is_read_only() {
    let fixture = Fixture::new();
    fixture.run(&["connectivity", "tick"]);
    assert_eq!(fixture.calls(), 3);
    assert_eq!(fixture.status()["tun_auto_route"]["status"], "not_required");

    let pid = fixture.core.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let starttime: u64 = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    let saved_path = fixture.root.join(".state/machines/connectivity.state");
    for cached_status in ["present", "missing"] {
        for (saved_pid, saved_starttime, expected) in [
            (pid, starttime, cached_status),
            (if pid == 1 { 2 } else { 1 }, starttime, "unknown"),
            (pid, starttime + 1, "unknown"),
        ] {
            // Seed earlier observations while keeping the real owned core alive.
            // Neither status command may rewrite these persisted observations.
            fixture.edit_state(&[
                ("tun_status", cached_status),
                ("tun_core_pid", &saved_pid.to_string()),
                ("tun_core_starttime", &saved_starttime.to_string()),
                ("tun_attempts", "2"),
                ("tun_failures", "2"),
            ]);
            let before = fs::read(&saved_path).unwrap();
            let connectivity = fixture.status();
            let output = fixture.run(&["--json", "service", "status"]);
            let service: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(service["schema"], 1);
            assert_eq!(service["ok"], true);
            for projected in [&connectivity, &service["data"]["connectivity"]] {
                assert_eq!(
                    projected["status"], "online",
                    "proxy evidence stays separate"
                );
                assert_eq!(
                    projected["warning"],
                    expected != "present",
                    "TUN loss or unknown identity must reach the connection warning"
                );
            }
            for projected in [
                &connectivity["tun_auto_route"],
                &service["data"]["connectivity"]["tun_auto_route"],
            ] {
                assert_eq!(projected["status"], expected);
                assert_eq!(projected["warning"], expected != "present");
                assert_eq!(projected["recovery_attempts"], 2);
                assert_eq!(projected["consecutive_failures"], 2);
                assert!(projected.get("core_pid").is_none());
                assert!(projected.get("core_starttime").is_none());
            }
            assert_eq!(fs::read(&saved_path).unwrap(), before);
            assert_eq!(fixture.calls(), 3, "status triggered a network probe");
            assert!(!fixture.root.join("actions").exists());
        }
    }
}
