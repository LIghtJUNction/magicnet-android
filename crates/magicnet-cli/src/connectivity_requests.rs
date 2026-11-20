//! Private, coalesced probe requests; canonical observations remain in STATE.
use super::{Clock, State};
use crate::App;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUEST: &str = ".state/connectivity-check.request";
pub(super) const MIN_INTERVAL: u64 = 10;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// No producer/lifecycle lock is acquired here. Concurrent requests coalesce
/// through atomic replacement; a request arriving during I/O remains pending.
pub(super) fn enqueue(app: &App) -> Result<(), String> {
    let clock = Clock::now()?;
    let generation = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "connectivity.clock_unavailable")?
        .as_nanos() as u64)
        .wrapping_add(u64::from(std::process::id()))
        .wrapping_add(SEQUENCE.fetch_add(1, Ordering::Relaxed))
        .max(1);
    crate::write_text_file(
        app,
        Path::new(REQUEST),
        &format!("schema=1\nboot={}\ngeneration={generation}\n", clock.boot),
    )
    .map_err(|_| "connectivity.request_io".into())
}

pub(super) fn generation(app: &App, clock: &Clock) -> Result<u64, String> {
    let Some(text) = crate::utils::read_module_text_bounded(app, Path::new(REQUEST), 256)
        .map_err(|_| "connectivity.request_io")?
    else {
        return Ok(0);
    };
    let values = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect::<BTreeMap<_, _>>();
    if text.lines().count() != 3 || values.len() != 3 || values.get("schema") != Some(&"1") {
        return Err("connectivity.request_invalid".into());
    }
    if values.get("boot") != Some(&clock.boot.as_str()) {
        return Ok(0);
    }
    values
        .get("generation")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| "connectivity.request_invalid".into())
}

pub(super) fn available(state: &State, clock: &Clock) -> bool {
    state.manual_checked_uptime == 0
        || clock.uptime.saturating_sub(state.manual_checked_uptime) >= MIN_INTERVAL
}

pub(super) fn pending(state: &State, generation: u64) -> bool {
    generation != 0 && generation != state.request_generation
}
