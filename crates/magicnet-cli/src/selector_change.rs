//! Selector writes share the lifecycle lock with configuration activation.
use super::{api_response, close_connections_through_chain, curl_get_json, encode_path_segment};
use crate::{selector_store, service::ConfigApplyGuard, App};
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub(crate) struct SelectorChange {
    pub(crate) group: String,
    pub(crate) previous: String,
    pub(crate) previous_saved: Option<String>,
    pub(crate) selected: String,
}

fn observe(app: &App, group: &str) -> Result<Value, String> {
    let value = curl_get_json(app, &format!("/proxies/{}", encode_path_segment(group)))
        .map_err(|_| "selector.runtime_unavailable")?;
    if !value["type"]
        .as_str()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("selector"))
        || value["now"].as_str().is_none_or(str::is_empty)
        || !value["all"].is_array()
    {
        return Err("selector.runtime_invalid".into());
    }
    Ok(value)
}

fn put(app: &App, group: &str, node: &str) -> Result<(), String> {
    api_response(
        app,
        "PUT",
        &format!("/proxies/{}", encode_path_segment(group)),
        &json!({"name": node}).to_string(),
        5,
        4096,
    )
    .map(|_| ())
    .map_err(|_| "selector.apply_failed".into())
}

fn restore_saved(app: &App, change: &SelectorChange) -> Result<(), String> {
    let saved = selector_store::selected_checked(app, &change.group)
        .map_err(|_| "selector.rollback_store_unavailable")?;
    if saved == change.previous_saved {
        return Ok(());
    }
    if saved.as_deref() != Some(change.selected.as_str()) {
        return Err("selector.rollback_store_conflict".into());
    }
    selector_store::set_checked(app, &change.group, change.previous_saved.as_deref())
        .map_err(|_| "selector.rollback_store_failed".to_string())?;
    if selector_store::selected_checked(app, &change.group)
        .map_err(|_| "selector.rollback_store_unavailable")?
        != change.previous_saved
    {
        return Err("selector.rollback_store_mismatch".into());
    }
    Ok(())
}

/// Compensate only values still owned by this change. An external dashboard
/// selection is a conflict, never permission to overwrite the newer choice.
pub(crate) fn rollback_selector_locked(
    app: &App,
    _guard: &ConfigApplyGuard,
    change: &SelectorChange,
) -> Result<(), String> {
    let runtime = (|| {
        let value = observe(app, &change.group)?;
        let current = value["now"].as_str().ok_or("selector.runtime_invalid")?;
        if current != change.previous {
            if current != change.selected {
                return Err("selector.rollback_runtime_conflict".to_string());
            }
            if !value["all"].as_array().is_some_and(|members| {
                members
                    .iter()
                    .any(|member| member.as_str() == Some(change.previous.as_str()))
            }) {
                return Err("selector.rollback_member_missing".into());
            }
            put(app, &change.group, &change.previous)?;
            if observe(app, &change.group)?["now"].as_str() != Some(change.previous.as_str()) {
                return Err("selector.rollback_runtime_mismatch".into());
            }
        }
        Ok(())
    })();
    // Compensate each owned surface independently, including when the API
    // disappears. Do not replay an unverified new choice at the next restart.
    let saved = restore_saved(app, change);
    if runtime.is_ok() && close_connections_through_chain(app, &change.group).is_err() {
        eprintln!("[warn] selector.rollback_connection_cleanup_failed");
    }
    match (runtime, saved) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(runtime), Err(saved)) => Err(format!("{runtime}; {saved}")),
    }
}

/// The caller owns the lifecycle lock until validation or rollback completes.
/// Persist before touching runtime so an unwritable store cannot report success.
pub(crate) fn change_selector_locked(
    app: &App,
    guard: &ConfigApplyGuard,
    group: &str,
    node: &str,
    expected_current: Option<&str>,
) -> Result<SelectorChange, String> {
    if group.is_empty() || node.is_empty() || group == "hotspot" {
        return Err("selector.invalid_request".into());
    }
    let before = observe(app, group)?;
    let previous = before["now"].as_str().ok_or("selector.runtime_invalid")?;
    if expected_current.is_some_and(|expected| expected != previous) {
        return Err("selector.concurrent_change".into());
    }
    if !before["all"]
        .as_array()
        .is_some_and(|members| members.iter().any(|member| member.as_str() == Some(node)))
    {
        return Err("selector.member_not_allowed".into());
    }
    let change = SelectorChange {
        group: group.into(),
        previous: previous.into(),
        previous_saved: selector_store::selected_checked(app, group)
            .map_err(|_| "selector.store_unavailable")?,
        selected: node.into(),
    };
    if selector_store::set_checked(app, group, Some(node)).is_err() {
        // A durable write can fail after promotion. Restore our value only;
        // no runtime write has been attempted yet.
        return match restore_saved(app, &change) {
            Ok(()) => Err("selector.persist_failed".into()),
            Err(error) => Err(format!(
                "selector.rollback_failed; selector.persist_failed; {error}"
            )),
        };
    }
    let applied = (|| {
        // A dashboard can bypass the module's lifecycle lock. Reobserve before
        // writing and verify afterward rather than trusting HTTP success alone.
        if observe(app, group)?["now"].as_str() != Some(previous) {
            return Err("selector.concurrent_change".into());
        }
        if previous != node {
            put(app, group, node)?;
        }
        if observe(app, group)?["now"].as_str() != Some(node) {
            return Err("selector.runtime_mismatch".into());
        }
        if selector_store::selected_checked(app, group)
            .map_err(|_| "selector.store_unavailable")?
            .as_deref()
            != Some(node)
        {
            return Err("selector.store_mismatch".into());
        }
        Ok(())
    })();
    if let Err(error) = applied {
        return match rollback_selector_locked(app, guard, &change) {
            Ok(()) => Err(error),
            Err(rollback) => Err(format!("selector.rollback_failed; {error}; {rollback}")),
        };
    }
    if close_connections_through_chain(app, group).is_err() {
        eprintln!("[warn] selector.committed_connection_cleanup_failed");
    }
    Ok(change)
}

#[cfg(test)]
#[path = "../tests/internal/selector_change.rs"]
mod tests;
