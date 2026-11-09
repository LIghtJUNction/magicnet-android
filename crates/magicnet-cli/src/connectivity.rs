//! Low-frequency end-to-end probes, with one persisted retry budget per boot.
//! Status readers never perform an Internet probe or a recovery operation.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::{run_bounded_command, App};

#[path = "connectivity_tun.rs"]
mod tun;

pub(crate) const TARGET: &str = "https://www.google.com/generate_204";
const SECONDARY_TARGET: &str = "https://cp.cloudflare.com/generate_204";
const DIRECT_TARGET: &str = "https://www.baidu.com/";
const STATE: &str = ".state/machines/connectivity.state";
const INTERVAL: u64 = 300;
const MAX_BACKOFF: u64 = 1800;
const ACTION_COOLDOWN: u64 = 300;
const REFRESH_COOLDOWN: u64 = 3600;
const MAX_STATE_BYTES: u64 = 4096;
const LOG_LIMIT: u64 = 64 * 1024;
static CANCELLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn cancelled() -> bool {
    CANCELLED.load(Ordering::Relaxed)
}

extern "C" fn cancel_maintenance(_signal: libc::c_int) {
    CANCELLED.store(true, Ordering::Relaxed);
}

struct CancellationGuard(libc::sigaction);

impl CancellationGuard {
    fn install() -> Result<Self, String> {
        CANCELLED.store(false, Ordering::Relaxed);
        // Only the explicit tick command installs this handler. Ordinary
        // service/config/subscription commands retain their existing signals.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            let mut previous: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = cancel_maintenance as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGTERM, &action, &mut previous) != 0 {
                return Err("connectivity.signal_unavailable".into());
            }
            Ok(Self(previous))
        }
    }
}

impl Drop for CancellationGuard {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGTERM, &self.0, std::ptr::null_mut());
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Clock {
    boot: String,
    uptime: u64,
    epoch: u64,
}

impl Clock {
    fn now() -> Result<Self, String> {
        let mut stamp = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // BOOTTIME includes device suspend and is unaffected by wall-clock/NTP
        // changes. The boot token prevents old uptime deadlines after reboot.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut stamp) } != 0 || stamp.tv_sec < 0
        {
            return Err("connectivity.clock_unavailable".into());
        }
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| "connectivity.clock_unavailable")?;
        let boot = boot.trim();
        if boot.len() != 36 || !boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Err("connectivity.clock_unavailable".into());
        }
        Ok(Self {
            boot: boot.into(),
            uptime: stamp.tv_sec as u64,
            epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }
}

#[derive(Clone, Debug)]
struct Observation {
    ok: bool,
    reason: &'static str,
    http: Option<u16>,
    millis: Option<u64>,
}

impl Observation {
    fn failed(reason: &'static str) -> Self {
        Self {
            ok: false,
            reason,
            http: None,
            millis: None,
        }
    }
}

#[derive(Clone, Debug)]
struct State {
    boot: String,
    phase: &'static str,
    reason: &'static str,
    primary_reason: &'static str,
    checked_at: u64,
    checked_uptime: u64,
    next_uptime: u64,
    failures: u32,
    probes: u64,
    http: Option<u16>,
    millis: Option<u64>,
    secondary: &'static str,
    direct: &'static str,
    last_action: &'static str,
    action_status: &'static str,
    action_at: u64,
    action_uptime: u64,
    refresh_at: u64,
    refresh_uptime: u64,
    recovery_stage: u8,
    tun: tun::State,
}

impl State {
    fn new(clock: &Clock) -> Self {
        Self {
            boot: clock.boot.clone(),
            phase: "unknown",
            reason: "not_checked",
            primary_reason: "not_checked",
            checked_at: 0,
            checked_uptime: 0,
            next_uptime: 0,
            failures: 0,
            probes: 0,
            http: None,
            millis: None,
            secondary: "not_run",
            direct: "not_run",
            last_action: "none",
            action_status: "none",
            action_at: 0,
            action_uptime: 0,
            refresh_at: 0,
            refresh_uptime: 0,
            recovery_stage: 0,
            tun: tun::State::read(&BTreeMap::new(), clock),
        }
    }

    fn read(app: &App, clock: &Clock) -> Self {
        let mut fresh = Self::new(clock);
        let text =
            match crate::utils::read_module_text_bounded(app, Path::new(STATE), MAX_STATE_BYTES) {
                Ok(Some(text)) => text,
                Ok(None) => return fresh,
                Err(_) => {
                    fresh.tun.block_recovery();
                    return fresh;
                }
            };
        let values = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<BTreeMap<_, _>>();
        if text.lines().count() != values.len()
            || values.get("schema") != Some(&"1")
            || values.get("domain") != Some(&"connectivity")
        {
            fresh.tun.block_recovery();
            return fresh;
        }
        if values.get("boot") != Some(&clock.boot.as_str()) {
            if !values.get("boot").is_some_and(|boot| {
                boot.len() == 36
                    && boot
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
            }) {
                fresh.tun.block_recovery();
            }
            return fresh;
        }
        let num = |key| {
            values
                .get(key)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        };
        let token = |key, allowed: &[&'static str], default| {
            allowed
                .iter()
                .copied()
                .find(|value| values.get(key) == Some(value))
                .unwrap_or(default)
        };
        Self {
            boot: clock.boot.clone(),
            phase: token(
                "phase",
                &["pending", "online", "degraded", "offline", "paused"],
                "unknown",
            ),
            reason: token(
                "reason",
                &[
                    "ok",
                    "probing",
                    "core_stopped",
                    "core_unknown",
                    "module_disabled",
                    "stop_requested",
                    "no_default_route",
                    "dns_failure",
                    "proxy_refused",
                    "timeout",
                    "tls_failure",
                    "http_error",
                    "probe_unavailable",
                    "probe_invalid",
                    "proxy_unavailable",
                    "endpoint_specific",
                    "upstream_unavailable",
                    "transport_failure",
                ],
                "not_checked",
            ),
            primary_reason: token(
                "primary_reason",
                &[
                    "ok",
                    "no_default_route",
                    "dns_failure",
                    "proxy_refused",
                    "timeout",
                    "tls_failure",
                    "http_error",
                    "probe_unavailable",
                    "probe_invalid",
                    "proxy_unavailable",
                    "transport_failure",
                ],
                "not_checked",
            ),
            checked_at: num("checked_at"),
            checked_uptime: num("checked_uptime"),
            next_uptime: num("next_uptime").min(clock.uptime.saturating_add(MAX_BACKOFF)),
            failures: num("failures").min(1000) as u32,
            probes: num("probes"),
            http: num("http_code")
                .try_into()
                .ok()
                .filter(|n| (100..=599).contains(n)),
            millis: values
                .get("latency_ms")
                .and_then(|v| v.parse().ok())
                .filter(|n| *n <= 9000),
            secondary: token("secondary", &["online", "failed"], "not_run"),
            direct: token("direct", &["online", "failed"], "not_run"),
            last_action: token(
                "last_action",
                &["repair", "refresh", "restart", "deferred"],
                "none",
            ),
            action_status: token(
                "action_status",
                &["pending", "ok", "failed", "busy"],
                "none",
            ),
            action_at: num("action_at"),
            action_uptime: num("action_uptime"),
            refresh_at: num("refresh_at"),
            refresh_uptime: num("refresh_uptime"),
            recovery_stage: num("recovery_stage").min(3) as u8,
            tun: tun::State::read(&values, clock),
        }
    }

    fn due(&self, clock: &Clock) -> bool {
        clock.uptime >= self.next_uptime
    }

    fn publish(&self, app: &App) -> Result<(), String> {
        let mut text = format!(
            "schema=1\ndomain=connectivity\nboot={}\nphase={}\nreason={}\nprimary_reason={}\nchecked_at={}\nchecked_uptime={}\nnext_uptime={}\nfailures={}\nprobes={}\nhttp_code={}\nlatency_ms={}\nsecondary={}\ndirect={}\nlast_action={}\naction_status={}\naction_at={}\naction_uptime={}\nrefresh_at={}\nrefresh_uptime={}\nrecovery_stage={}\n",
            self.boot, self.phase, self.reason, self.primary_reason, self.checked_at, self.checked_uptime, self.next_uptime,
            self.failures, self.probes, self.http.map_or_else(|| "unknown".into(), |n| n.to_string()),
            self.millis.map_or_else(|| "unknown".into(), |n| n.to_string()), self.secondary, self.direct,
            self.last_action, self.action_status, self.action_at, self.action_uptime, self.refresh_at,
            self.refresh_uptime, self.recovery_stage,
        );
        text.push_str(&self.tun.encode());
        crate::write_text_file(app, Path::new(STATE), &text)
    }

    fn record(
        &mut self,
        clock: &Clock,
        primary: &Observation,
        secondary: Option<&Observation>,
        direct: Option<&Observation>,
    ) {
        self.checked_at = clock.epoch;
        self.checked_uptime = clock.uptime;
        self.probes = self.probes.saturating_add(1);
        self.http = primary.http;
        self.millis = primary.millis;
        self.reason = primary.reason;
        self.primary_reason = primary.reason;
        self.secondary = secondary.map_or("not_run", |p| if p.ok { "online" } else { "failed" });
        self.direct = direct.map_or("not_run", |p| if p.ok { "online" } else { "failed" });
        if primary.ok {
            self.phase = "online";
            self.failures = 0;
            self.recovery_stage = 0;
            self.next_uptime = clock.uptime.saturating_add(INTERVAL);
        } else {
            self.failures = self.failures.saturating_add(1).min(1000);
            self.phase = if self.secondary == "online" {
                "degraded"
            } else {
                "offline"
            };
            // A missing or malformed local executor is not evidence that an
            // endpoint or the uplink failed. Keep that actionable cause even
            // when the same executor also fails the direct control.
            if !matches!(primary.reason, "probe_unavailable" | "probe_invalid") {
                if self.secondary == "online" {
                    self.reason = "endpoint_specific";
                } else if direct.is_some_and(|probe| {
                    !probe.ok && !matches!(probe.reason, "probe_unavailable" | "probe_invalid")
                }) {
                    self.reason = "upstream_unavailable";
                }
            }
            self.next_uptime = clock.uptime.saturating_add(backoff(self.failures));
        }
    }

    fn action(&self, clock: &Clock, has_remote_subscription: bool) -> Option<&'static str> {
        if self.failures < 2
            || self.phase != "offline"
            || self.secondary != "failed"
            || self.direct != "online"
            || self.reason == "no_default_route"
            || matches!(self.primary_reason, "probe_unavailable" | "probe_invalid")
            || !cooldown_elapsed(clock, self.action_uptime.max(self.tun.action_uptime))
        {
            return None;
        }
        Some(match self.recovery_stage {
            0 | 3 => "repair",
            1 if has_remote_subscription
                && (self.refresh_uptime == 0
                    || clock.uptime.saturating_sub(self.refresh_uptime) >= REFRESH_COOLDOWN) =>
            {
                "refresh"
            }
            _ => "restart",
        })
    }

    fn reserve_action(&mut self, clock: &Clock, action: &'static str) {
        self.last_action = action;
        self.action_status = "pending";
        self.action_at = clock.epoch;
        self.action_uptime = clock.uptime;
        if action == "refresh" {
            self.refresh_at = clock.epoch;
            self.refresh_uptime = clock.uptime;
        }
        self.recovery_stage = match action {
            "repair" => 1,
            "refresh" => 2,
            _ => 3,
        };
        // Persist a crash-safe reservation without exceeding the 30-minute
        // retry cap. The producer lock covers an action still in progress.
        self.next_uptime = clock
            .uptime
            .saturating_add(backoff(self.failures).max(ACTION_COOLDOWN));
    }
}

fn cooldown_elapsed(clock: &Clock, action_uptime: u64) -> bool {
    action_uptime == 0 || clock.uptime.saturating_sub(action_uptime) >= ACTION_COOLDOWN
}

fn backoff(failures: u32) -> u64 {
    60_u64
        .saturating_mul(1_u64 << failures.saturating_sub(1).min(5))
        .min(MAX_BACKOFF)
}

fn disabled(app: &App) -> bool {
    ["disable", "remove"]
        .iter()
        .any(|name| app.moddir.join(name).exists())
}

fn live(app: &App) -> Result<bool, String> {
    if disabled(app) {
        return Ok(false);
    }
    crate::owned_singbox_pids(app).map(|pids| !pids.is_empty())
}

pub(crate) fn status(app: &App) -> Value {
    status_with_core(app, &crate::singbox_pid_summary(app))
}

pub(crate) fn status_with_core(app: &App, core: &str) -> Value {
    status_with_clock(app, core, Clock::now())
}

fn status_with_clock(app: &App, core: &str, clock: Result<Clock, String>) -> Value {
    let Ok(clock) = clock else {
        return json!({
            "target":TARGET, "path":"mixed_proxy", "status":"unknown",
            "reason":"clock_unavailable", "primary_reason":"not_checked", "warning":true,
            "checked_at":null, "next_check_at":null, "retry_in_seconds":null,
            "consecutive_failures":0, "probe_count":0, "backoff_seconds":INTERVAL,
            "latency_ms":null, "http_status":null,
            "secondary_status":"not_run", "direct_status":"not_run",
            "last_action":"none", "action_status":"none", "last_action_at":null,
            "last_refresh_at":null,
            "tun_auto_route":State::new(&Clock::default()).tun.json(None, core, disabled(app)),
        });
    };
    let state = State::read(app, &clock);
    let mut phase = state.phase;
    let mut reason = state.reason;
    if disabled(app) || core == "stopped" {
        phase = "paused";
        reason = if disabled(app) {
            "module_disabled"
        } else {
            "core_stopped"
        };
    } else if !core
        .split(',')
        .all(|pid| pid.parse::<u32>().is_ok_and(|n| n > 0))
    {
        phase = "unknown";
        reason = "core_unknown";
    } else if state.checked_at > 0 && clock.uptime > state.next_uptime.saturating_add(120) {
        phase = "stale";
        reason = "monitor_overdue";
    }
    let waiting = phase != "paused" && state.next_uptime > 0;
    let retry = waiting.then(|| state.next_uptime.saturating_sub(clock.uptime));
    json!({
        "target":TARGET, "path":"mixed_proxy", "status":phase, "reason":reason, "primary_reason":state.primary_reason,
        "warning":matches!(phase, "offline" | "degraded" | "stale") || (phase == "pending" && state.failures > 0),
        "checked_at":(state.checked_at > 0).then_some(state.checked_at),
        "next_check_at":retry.map(|n| clock.epoch.saturating_add(n)),
        "retry_in_seconds":retry, "consecutive_failures":state.failures, "probe_count":state.probes,
        "backoff_seconds":if state.failures > 0 { backoff(state.failures) } else { INTERVAL },
        "latency_ms":state.millis, "http_status":state.http,
        "secondary_status":state.secondary, "direct_status":state.direct,
        "last_action":state.last_action, "action_status":state.action_status,
        "last_action_at":(state.action_at > 0).then_some(state.action_at),
        "last_refresh_at":(state.refresh_at > 0).then_some(state.refresh_at),
        "tun_auto_route":state.tun.json(Some(&clock), core, disabled(app)),
    })
}

pub(crate) fn command(app: &App, args: &[String]) -> Result<(), String> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["status"] => {
            let value = status(app);
            if value["warning"] == true {
                println!("⚠️ Google.com connectivity warning");
            }
            println!("{value}");
            Ok(())
        }
        ["tick"] => {
            let _signals = CancellationGuard::install()?;
            tick(app)
        }
        _ => Err("Usage: cli connectivity {status|tick}".into()),
    }
}

fn lock(app: &App) -> Result<Option<File>, String> {
    let directory = app.moddir.join(".state");
    fs::create_dir_all(&directory).map_err(|_| "connectivity.state_io")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join("connectivity.lock"))
        .map_err(|_| "connectivity.state_io")?;
    if !file
        .metadata()
        .map_err(|_| "connectivity.state_io")?
        .is_file()
    {
        return Err("connectivity.state_io".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err("connectivity.lock_failed".into())
    }
}

pub(crate) fn tick(app: &App) -> Result<(), String> {
    let Some(_guard) = lock(app)? else {
        return Ok(());
    };
    let clock = Clock::now()?;
    let mut state = State::read(app, &clock);
    if cancelled() {
        return pause_cancelled(app, &mut state);
    }
    let probe_due = state.due(&clock);
    let tun_due = state.tun.due(&clock);
    if !probe_due && !tun_due {
        return Ok(());
    }
    let reason = if disabled(app) {
        Some("module_disabled")
    } else {
        match live(app) {
            Ok(true) => None,
            Ok(false) => Some("core_stopped"),
            Err(_) => Some("core_unknown"),
        }
    };
    if let Some(reason) = reason {
        if state.phase != "paused" || state.reason != reason {
            state.phase = "paused";
            state.reason = reason;
            state.next_uptime = clock.uptime.saturating_add(INTERVAL);
            state.tun.record(
                &clock,
                if reason == "core_unknown" {
                    "unknown"
                } else {
                    "paused"
                },
            );
            state.publish(app)?;
        }
        return Ok(());
    }
    if tun_due {
        state.tun.next_uptime = clock.uptime.saturating_add(tun::INTERVAL);
        state.publish(app)?;
        let observed = tun::observe(app, &clock);
        if cancelled() {
            return pause_cancelled(app, &mut state);
        }
        state.tun.record_observation(&Clock::now()?, &observed);
        state.publish(app)?;
        if state.tun.recovery_due(&clock, state.action_uptime) {
            let attempts = state.tun.attempts;
            tun::recover(app, &mut state, &clock, &observed)?;
            if state.tun.attempts > attempts {
                return Ok(());
            }
        }
    }
    if !probe_due {
        return Ok(());
    }
    let was_warning = matches!(state.phase, "offline" | "degraded");
    // Reserve the retry window before I/O: killing a curl or restarting the
    // monitor cannot turn the next invocation into an unthrottled retry.
    state.phase = "pending";
    state.reason = "probing";
    state.next_uptime = clock
        .uptime
        .saturating_add(backoff(state.failures.saturating_add(1)));
    state.publish(app)?;
    let proxy = mixed_proxy(app);
    let (primary, secondary, direct) = if default_route() == Some(false) {
        (Observation::failed("no_default_route"), None, None)
    } else if let Some(proxy) = proxy.as_deref() {
        let primary = probe(app, TARGET, Some(proxy), true);
        if cancelled() {
            return pause_cancelled(app, &mut state);
        }
        if primary.ok {
            (primary, None, None)
        } else {
            let secondary = probe(app, SECONDARY_TARGET, Some(proxy), true);
            if cancelled() {
                return pause_cancelled(app, &mut state);
            }
            let direct = (!secondary.ok).then(|| probe(app, DIRECT_TARGET, None, false));
            (primary, Some(secondary), direct)
        }
    } else {
        (Observation::failed("proxy_unavailable"), None, None)
    };
    if cancelled() {
        return pause_cancelled(app, &mut state);
    }
    let clock = Clock::now()?;
    state.record(&clock, &primary, secondary.as_ref(), direct.as_ref());
    state.publish(app)?;
    log_event(app, &state);
    let warning = state.phase != "online";
    if warning != was_warning {
        notify(app, warning);
    }
    let has_remote = crate::subscriptions::observe_source_configuration(app)
        .is_ok_and(|source| source.mode() == "remote_url" && !source.urls.is_empty());
    if let Some(action) = state
        .action(&clock, has_remote)
        .filter(|_| matches!(state.tun.status, "present" | "not_required"))
    {
        recover(app, &mut state, &clock, action)?;
    }
    Ok(())
}

fn pause_cancelled(app: &App, state: &mut State) -> Result<(), String> {
    state.phase = "paused";
    state.reason = "stop_requested";
    let clock = Clock::now()?;
    state.next_uptime = clock.uptime.saturating_add(INTERVAL);
    state.tun.record(&clock, "paused");
    state.publish(app)
}

fn mixed_proxy(app: &App) -> Option<String> {
    let config = crate::utils::read_json_file_bounded(
        &app.moddir.join(".config/sing-box/config.json"),
        4 * 1024 * 1024,
    )?;
    let inbound = config["inbounds"]
        .as_array()?
        .iter()
        .find(|v| v["type"] == "mixed")?;
    if inbound["users"]
        .as_array()
        .is_some_and(|users| !users.is_empty())
    {
        return None;
    }
    let mut ip = inbound["listen"]
        .as_str()
        .unwrap_or("127.0.0.1")
        .parse::<IpAddr>()
        .ok()?;
    if ip.is_unspecified() {
        ip = if ip.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };
    }
    if !ip.is_loopback() {
        return None;
    }
    let port: u16 = inbound["listen_port"].as_u64()?.try_into().ok()?;
    (port > 0).then(|| format!("http://{}", SocketAddr::new(ip, port)))
}

fn probe_command(app: &App, url: &str, proxy: Option<&str>) -> Command {
    let mut command = crate::trusted_curl(app);
    command.args([
        "-q",
        "--silent",
        "--head",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code} %{time_total}",
        "--connect-timeout",
        "4",
        "--max-time",
        "8",
        "--retry",
        "0",
        "--max-redirs",
        "0",
        "--proto",
        "=https",
    ]);
    if let Some(proxy) = proxy {
        command.args(["--noproxy", "", "--proxy", proxy]);
    } else {
        command.args(["--noproxy", "*", "--proxy", ""]);
    }
    command.arg("--url").arg(url);
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        command.env_remove(name);
    }
    command
}

fn probe(app: &App, url: &str, proxy: Option<&str>, exact_204: bool) -> Observation {
    match run_bounded_command(probe_command(app, url, proxy), Duration::from_secs(9), 1024) {
        Ok(result) => parse_probe(&result, exact_204),
        Err(_) => Observation::failed("probe_unavailable"),
    }
}

fn parse_probe(result: &crate::utils::BoundedCommandOutput, exact_204: bool) -> Observation {
    if result.timed_out {
        return Observation::failed("timeout");
    }
    if result.truncated {
        return Observation::failed("probe_invalid");
    }
    let exit = result.status.as_ref().and_then(|s| s.code());
    if exit != Some(0) {
        return Observation::failed(match exit {
            Some(5 | 6) => "dns_failure",
            Some(7) => "proxy_refused",
            Some(28) => "timeout",
            Some(35 | 51 | 58 | 60 | 77 | 80 | 82 | 83 | 90 | 91) => "tls_failure",
            _ => "transport_failure",
        });
    }
    let text = String::from_utf8_lossy(&result.stdout);
    let parts = text.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 2 {
        return Observation::failed("probe_invalid");
    }
    let (Ok(http), Ok(seconds)) = (parts[0].parse::<u16>(), parts[1].parse::<f64>()) else {
        return Observation::failed("probe_invalid");
    };
    if !(100..=599).contains(&http) || !seconds.is_finite() || !(0.0..=9.0).contains(&seconds) {
        return Observation::failed("probe_invalid");
    }
    let ok = if exact_204 {
        http == 204
    } else {
        (200..400).contains(&http)
    };
    Observation {
        ok,
        reason: if ok { "ok" } else { "http_error" },
        http: Some(http),
        millis: Some((seconds * 1000.0).round() as u64),
    }
}

fn default_route() -> Option<bool> {
    let ip = if cfg!(target_os = "android") {
        "/system/bin/ip"
    } else {
        "ip"
    };
    let mut observed_families = 0;
    for family in ["-4", "-6"] {
        let mut command = Command::new(ip);
        command.args([family, "route", "show", "table", "all", "default"]);
        crate::process::sanitize_cli_child_environment(&mut command);
        if let Ok(output) = run_bounded_command(command, Duration::from_secs(2), 16 * 1024) {
            if !output.timed_out && !output.truncated && output.status.is_some_and(|s| s.success())
            {
                observed_families += 1;
                if String::from_utf8_lossy(&output.stdout).lines().any(|line| {
                    let words = line.split_whitespace().collect::<Vec<_>>();
                    words.first() == Some(&"default")
                        && !words.contains(&"linkdown")
                        && words
                            .windows(2)
                            .any(|p| p[0] == "dev" && !matches!(p[1], "lo" | "magicnet0"))
                }) {
                    return Some(true);
                }
            }
        }
    }
    (observed_families == 2).then_some(false)
}

fn recover(
    app: &App,
    state: &mut State,
    clock: &Clock,
    action: &'static str,
) -> Result<(), String> {
    if cancelled() {
        return pause_cancelled(app, state);
    }
    let Some(guard) = crate::service::try_config_apply_lock(app)? else {
        state.last_action = "deferred";
        state.action_status = "busy";
        return state.publish(app);
    };
    // A stop/restart may have won the lifecycle lock while the probes ran.
    // Never turn an absent or unobservable process into permission to start.
    if cancelled() || live(app) != Ok(true) {
        return Ok(());
    }
    let routes = tun::observe(app, clock);
    if !matches!(routes.status, "present" | "not_required") {
        state.tun.record_observation(clock, &routes);
        return state.publish(app);
    }
    if cancelled() || live(app) != Ok(true) {
        return Ok(());
    }
    state.reserve_action(clock, action);
    state.publish(app)?;
    let result = match action {
        "repair" => crate::process::run_magicnet_function_quiet(
            app,
            "magicnet_after_kernel_start_unlocked",
            Duration::from_secs(45),
        ),
        "refresh" => {
            let update = crate::process::run_magicnet_function_quiet(app,
                ". \"$MODDIR/lib/magicnet_singbox_subscribe.sh\"; magicnet_singbox_update_subscription",
                Duration::from_secs(300));
            crate::subscriptions::cleanup_stale_update_lock(app);
            if update.is_ok() && !cancelled() {
                crate::clear_node_cache(app);
                let _ = crate::selector_store::replay(app);
            }
            // The subscription activation path owns a core restart and stops
            // supervisors. Resume monitoring even when no fswatch was enabled.
            if !cancelled() && live(app) == Ok(true) {
                let _ = crate::process::run_magicnet_function_quiet(
                    app,
                    "magicnet_connectivity_watchdog_start",
                    Duration::from_secs(10),
                );
            }
            update
        }
        _ => crate::service::restart_current_core_locked(app, &guard),
    };
    state.action_status = if result.is_ok() { "ok" } else { "failed" };
    if cancelled() {
        state.action_status = "failed";
        // The shell group has now finished its TERM rollback (or bounded
        // cleanup). Only now release lifecycle ownership to the waiting stop.
        pause_cancelled(app, state)?;
        log_event(app, state);
        return Ok(());
    }
    let clock = Clock::now()?;
    // Actions never cause an immediate follow-up network burst. A successful
    // action is recorded separately; online requires a later HTTPS result.
    state.next_uptime = clock.uptime.saturating_add(backoff(state.failures));
    state.publish(app)?;
    log_event(app, state);
    let _ = crate::state::reconcile(app);
    Ok(())
}

fn log_event(app: &App, state: &State) {
    let _ = fs::create_dir_all(&app.log_dir);
    let Ok(mut file) = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(app.log_dir.join("connectivity.log"))
    else {
        return;
    };
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if !metadata.is_file() {
        return;
    }
    if metadata.len() > LOG_LIMIT {
        let _ = file.set_len(0);
    }
    let _ = writeln!(file, "epoch={} level={} target=google phase={} reason={} primary_reason={} failures={} next_uptime={} action={} action_status={} tun_status={} tun_failures={} tun_attempts={} tun_action_status={}",
        state.checked_at, if state.phase == "online" { "info" } else { "warn" }, state.phase, state.reason, state.primary_reason,
        state.failures, state.next_uptime, state.last_action, state.action_status,
        state.tun.status, state.tun.failures, state.tun.attempts, state.tun.action_status);
}

fn notify(app: &App, warning: bool) {
    let script = if warning {
        "magicnet_notify magicnet_connectivity MagicNet '⚠️ Google.com connection failed. Open Diagnostics; recovery uses exponential backoff.'"
    } else {
        "magicnet_notify magicnet_connectivity MagicNet 'Google.com connection restored.'"
    };
    let _ = crate::process::run_magicnet_function_quiet(app, script, Duration::from_secs(3));
}

#[cfg(test)]
#[path = "../tests/internal/connectivity.rs"]
mod tests;
