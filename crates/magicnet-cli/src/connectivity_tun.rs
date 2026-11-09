//! The mixed proxy bypasses TUN policy, so its HTTPS result cannot authorize
//! or suppress recovery of a missing auto_route group.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{cancelled, Clock, ACTION_COOLDOWN};
use crate::App;

pub(super) const INTERVAL: u64 = 60;
const STARTUP_GRACE: u64 = 90;
const RECOVERY_LIMIT: u32 = 3;

#[derive(Clone, Debug)]
pub(super) struct State {
    pub(super) status: &'static str,
    pub(super) checked_at: u64,
    pub(super) next_uptime: u64,
    pub(super) failures: u32,
    pub(super) attempts: u32,
    pub(super) action_status: &'static str,
    pub(super) action_at: u64,
    pub(super) action_uptime: u64,
    pub(super) retry_uptime: u64,
    core: Option<Core>,
}

impl State {
    pub(super) fn read(values: &BTreeMap<&str, &str>, clock: &Clock) -> Self {
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
        let invalid_budget = values.keys().any(|key| key.starts_with("tun_"))
            && [
                "tun_attempts",
                "tun_action_uptime",
                "tun_retry_uptime",
                "action_uptime",
            ]
            .iter()
            .any(|key| {
                values
                    .get(key)
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_none()
            });
        Self {
            status: token(
                "tun_status",
                &["not_required", "pending", "present", "missing", "paused"],
                "unknown",
            ),
            checked_at: num("tun_checked_at"),
            next_uptime: num("tun_next_uptime").min(clock.uptime.saturating_add(INTERVAL)),
            failures: num("tun_failures").min(1000) as u32,
            attempts: if invalid_budget {
                RECOVERY_LIMIT
            } else {
                num("tun_attempts").min(RECOVERY_LIMIT.into()) as u32
            },
            action_status: token(
                "tun_action_status",
                &["pending", "ok", "failed", "busy"],
                "none",
            ),
            action_at: num("tun_action_at"),
            action_uptime: num("tun_action_uptime"),
            retry_uptime: num("tun_retry_uptime")
                .min(clock.uptime.saturating_add(super::MAX_BACKOFF)),
            core: values
                .get("tun_core_pid")
                .and_then(|pid| pid.parse::<u32>().ok())
                .filter(|pid| *pid > 0 && *pid <= libc::pid_t::MAX as u32)
                .zip(
                    values
                        .get("tun_core_starttime")
                        .and_then(|start| start.parse::<u64>().ok()),
                )
                .map(|(pid, starttime)| Core { pid, starttime }),
        }
    }

    pub(super) fn block_recovery(&mut self) {
        self.attempts = RECOVERY_LIMIT;
    }

    pub(super) fn encode(&self) -> String {
        format!("tun_status={}\ntun_checked_at={}\ntun_next_uptime={}\ntun_failures={}\ntun_attempts={}\ntun_action_status={}\ntun_action_at={}\ntun_action_uptime={}\ntun_retry_uptime={}\ntun_core_pid={}\ntun_core_starttime={}\n",
            self.status, self.checked_at, self.next_uptime, self.failures, self.attempts,
            self.action_status, self.action_at, self.action_uptime, self.retry_uptime,
            self.core.as_ref().map_or(0, |core| core.pid), self.core.as_ref().map_or(0, |core| core.starttime))
    }

    pub(super) fn due(&self, clock: &Clock) -> bool {
        clock.uptime >= self.next_uptime
    }

    pub(super) fn record(&mut self, clock: &Clock, status: &'static str) {
        self.status = status;
        self.checked_at = clock.epoch;
        self.next_uptime = clock.uptime.saturating_add(INTERVAL);
        self.failures = if status == "missing" {
            self.failures.saturating_add(1).min(1000)
        } else {
            0
        };
        if self.action_status == "pending" {
            self.action_status = "failed";
        }
        // Attempts belong to the boot, not the incident. Neither a transient
        // ready observation nor a new CLI process replenishes the budget.
    }

    pub(super) fn record_observation(&mut self, clock: &Clock, observed: &Observation) {
        if self.core != observed.core {
            self.failures = 0;
        }
        self.core = observed.core.clone();
        self.record(clock, observed.status);
    }

    pub(super) fn recovery_due(&self, clock: &Clock, proxy_action_uptime: u64) -> bool {
        self.status == "missing"
            && self.failures >= 2
            && self.attempts < RECOVERY_LIMIT
            && clock.uptime >= self.retry_uptime
            && super::cooldown_elapsed(clock, proxy_action_uptime.max(self.action_uptime))
    }

    fn reserve(&mut self, clock: &Clock) {
        self.attempts += 1;
        self.action_status = "pending";
        self.action_at = clock.epoch;
        self.action_uptime = clock.uptime;
        self.retry_uptime = clock.uptime.saturating_add(recovery_backoff(self.attempts));
        self.next_uptime = clock.uptime.saturating_add(INTERVAL);
    }

    pub(super) fn json(&self, clock: Option<&Clock>, core: &str, disabled: bool) -> Value {
        let status = if disabled || core == "stopped" {
            "paused"
        } else if clock.is_none()
            || !core
                .split(',')
                .all(|pid| pid.parse::<u32>().is_ok_and(|n| n > 0))
        {
            "unknown"
        } else if clock.is_some_and(|now| {
            self.checked_at > 0 && now.uptime > self.next_uptime.saturating_add(120)
        }) {
            "stale"
        } else {
            self.status
        };
        let retry = clock
            .filter(|_| status != "paused" && self.next_uptime > 0)
            .map(|now| self.next_uptime.saturating_sub(now.uptime));
        let recovery_status = if self.action_status == "pending" {
            "pending"
        } else if status == "missing" && self.attempts >= RECOVERY_LIMIT {
            "exhausted"
        } else if status == "missing" && clock.is_some_and(|now| now.uptime < self.retry_uptime) {
            "cooldown"
        } else {
            self.action_status
        };
        json!({
            "status":status, "warning":matches!(status, "missing" | "unknown" | "stale"),
            "checked_at":(self.checked_at > 0).then_some(self.checked_at),
            "next_check_at":retry.zip(clock).map(|(n, now)| now.epoch.saturating_add(n)),
            "retry_in_seconds":retry, "consecutive_failures":self.failures,
            "recovery_attempts":self.attempts, "recovery_limit":RECOVERY_LIMIT,
            "recovery_status":recovery_status,
            "last_recovery_at":(self.action_at > 0).then_some(self.action_at),
        })
    }
}

fn recovery_backoff(attempts: u32) -> u64 {
    ACTION_COOLDOWN.saturating_mul(1 << attempts.saturating_sub(1).min(2))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Core {
    pid: u32,
    starttime: u64,
}

fn core_identity(app: &App) -> Option<Core> {
    let pids = crate::owned_singbox_pids(app).ok()?;
    let [pid] = pids.as_slice() else {
        return None;
    };
    let pid = pid.parse().ok()?;
    let identity = crate::process::live_process_identity(pid).ok()??;
    Some(Core {
        pid,
        starttime: identity.starttime,
    })
}

fn managed_inbound(app: &App) -> Result<Option<Value>, ()> {
    if !crate::service::automatic_tun_recovery_allowed(app).map_err(|_| ())? {
        return Ok(None);
    }
    let config = crate::utils::read_json_file_bounded(
        &app.moddir.join(".config/sing-box/config.json"),
        4 * 1024 * 1024,
    )
    .ok_or(())?;
    let inbounds = config["inbounds"].as_array().ok_or(())?;
    if inbounds.iter().any(|inbound| inbound["type"] == "ebpf") {
        return Err(());
    }
    let tun = inbounds
        .iter()
        .filter(|inbound| inbound["type"] == "tun")
        .collect::<Vec<_>>();
    let inbound = match tun.as_slice() {
        [] => return Ok(None),
        [inbound] if inbound["tag"] == "tun-in" && inbound["interface_name"] == "magicnet0" => {
            *inbound
        }
        _ => return Err(()),
    };
    if inbounds
        .iter()
        .filter(|inbound| inbound["tag"] == "tun-in")
        .count()
        != 1
    {
        return Err(());
    }
    match inbound.get("auto_route") {
        None | Some(Value::Bool(false)) => Ok(None),
        Some(Value::Bool(true)) => Ok(Some(inbound.clone())),
        _ => Err(()),
    }
}

pub(super) struct Observation {
    pub(super) status: &'static str,
    core: Option<Core>,
}

pub(super) fn observe(app: &App, clock: &Clock) -> Observation {
    let mut observation = Observation {
        status: "unknown",
        core: None,
    };
    let inbound = match managed_inbound(app) {
        Ok(Some(inbound)) => inbound,
        Ok(None) => {
            observation.status = "not_required";
            return observation;
        }
        Err(()) => return observation,
    };
    let Some(core) = core_identity(app) else {
        return observation;
    };
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let Some(age) = u64::try_from(ticks)
        .ok()
        .filter(|ticks| *ticks > 0)
        .and_then(|ticks| {
            let age = clock.uptime.checked_sub(core.starttime / ticks)?;
            Some(age.saturating_sub(u64::from(core.starttime % ticks != 0)))
        })
    else {
        return observation;
    };
    let routes = crate::diagnostics::tun::auto_route_observation(&inbound);
    if !routes.fully_observed || core_identity(app).as_ref() != Some(&core) {
        return observation;
    }
    observation.status = match routes.ready {
        Some(true) => "present",
        Some(false) if age < STARTUP_GRACE => "pending",
        Some(false) => "missing",
        None => "unknown",
    };
    observation.core = Some(core);
    observation
}

pub(super) fn recover(
    app: &App,
    state: &mut super::State,
    clock: &Clock,
    missing: &Observation,
) -> Result<(), String> {
    if cancelled() {
        return super::pause_cancelled(app, state);
    }
    let Some(guard) = crate::service::try_config_apply_lock(app)? else {
        state.tun.action_status = "busy";
        return state.publish(app);
    };
    if cancelled() || super::live(app) != Ok(true) {
        return Ok(());
    }
    // Re-read configuration, journals, generation and every RPDB/FIB snapshot
    // under lifecycle ownership. An earlier missing result is not authority.
    let mut current = observe(app, clock);
    if current.status != "missing" || current.core != missing.core {
        if current.status == "missing" && current.core != missing.core {
            current.status = "unknown";
        }
        state.tun.record_observation(clock, &current);
        return state.publish(app);
    }
    if cancelled()
        || super::live(app) != Ok(true)
        || crate::service::automatic_tun_recovery_allowed(app) != Ok(true)
        || !state.tun.recovery_due(clock, state.action_uptime)
    {
        return Ok(());
    }
    state.tun.reserve(clock);
    state.publish(app)?;
    let result = crate::service::restart_current_core_locked(app, &guard);
    state.tun.action_status = if result.is_ok() { "ok" } else { "failed" };
    if cancelled() {
        state.tun.action_status = "failed";
        super::pause_cancelled(app, state)?;
    } else {
        // Success only acknowledges the lifecycle action. A later complete
        // kernel snapshot must establish that the route group is present.
        state.tun.next_uptime = Clock::now()?.uptime.saturating_add(INTERVAL);
        state.publish(app)?;
    }
    super::log_event(app, state);
    let _ = crate::state::reconcile(app);
    Ok(())
}

#[cfg(test)]
#[path = "../tests/internal/connectivity_tun.rs"]
mod tests;
