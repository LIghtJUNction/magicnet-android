use std::fmt;
use std::io::{self, Write};

// Rust's standard print macros panic when a WebUI/background-task reader closes
// its pipe before a long-running command reports completion.  Release builds
// abort on that panic, creating a tombstone and bypassing normal cleanup.  CLI
// output is best-effort: keep executing cleanup and preserve the real status
// even after the consumer disconnects.
fn write_stdout(args: fmt::Arguments<'_>) {
    let _ = io::stdout().lock().write_fmt(args);
}

fn write_stderr(args: fmt::Arguments<'_>) {
    let _ = io::stderr().lock().write_fmt(args);
}

macro_rules! print {
    ($($arg:tt)*) => {{ crate::write_stdout(format_args!($($arg)*)); }};
}

macro_rules! println {
    () => {{ crate::write_stdout(format_args!("\n")); }};
    ($($arg:tt)*) => {{ crate::write_stdout(format_args!("{}\n", format_args!($($arg)*))); }};
}

macro_rules! eprintln {
    ($($arg:tt)*) => {{ crate::write_stderr(format_args!("{}\n", format_args!($($arg)*))); }};
}

mod app;
mod app_catalog;
mod base64;
#[cfg(test)]
mod base64_tests;
mod chain;
mod commands;
mod config_editor;
mod connection_control;
mod connectivity;
mod diagnostics;
mod diagnostics_dns;
mod diagnostics_routing;
mod dns;
mod ebpf_runtime;
mod ecapture;
#[cfg(test)]
mod hotspot_tests;
mod local_http;
mod machine;
mod mcp;
mod mcp_server;
mod module_update;
mod network;
mod network_access;
mod network_observation;
mod node_delay;
mod nodes;
mod overrides;
mod ping;
mod process;
mod routing_overlay;
mod rules;
mod selector_store;
mod service;
mod state;
mod subscriptions;
mod tailscale_control;
#[cfg(test)]
mod test_support;
mod utils;
mod warp;
mod webui_api;
mod webui_backup;
mod webui_payload;
mod wifi;

use std::env;

pub(crate) use app::App;
pub(crate) use base64::{decode_base64, encode_base64};
use commands::dispatch;
pub(crate) use mcp_server::{files, logs, rpc, run_cli, tools, Server};
pub(crate) use process::{
    owned_singbox_pids, run_magicnet_function, run_subscription_source_update_from_inherited_fd,
    run_subscription_update_from_inherited_fd, singbox_pid_summary, stop_owned_singbox,
    trusted_curl, SHORT_TIMEOUT,
};
pub(crate) use utils::{
    clean_module_lines, clear_node_cache, cmdline_has_command, cmdline_has_script,
    command_text_timeout, cstring_from_os_str, first_clean_module_line, proc_start_time, read_kv,
    read_proc_argv, read_proc_text_bounded, replace_module_text_files_transactionally,
    run_bounded_command, shell_inert_conf_value, write_kv, write_secret_file, write_text_file,
    MAX_PROC_COMM_BYTES, MAX_PROC_STAT_BYTES,
};

fn reconcile_state(app: &App, phase: &str) {
    if let Err(err) = state::reconcile(app) {
        eprintln!("[warning] canonical state {phase} reconciliation failed: {err}");
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let json = args.iter().any(|arg| arg == "--json");
    if let Err(error) = utils::mark_inherited_fds_cloexec() {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "schema": 1, "ok": false, "command": "machine.error",
                    "error": {"code": "machine.io", "message": "unable to isolate inherited file descriptors"}
                })
            );
        }
        exit_result(
            Err(format!("isolate inherited file descriptors: {error}")),
            1,
        );
    }

    // Once --json appears, only the machine dispatcher can own the request.
    // Internal helpers must never print raw proc data around a JSON envelope.
    if !json {
        if let Some(result) = proc_command(&args) {
            exit_result(result, 2);
        }
    }
    let app = App::from_env();
    let result = if json {
        machine::dispatch(&app, &args).expect("explicit machine request")
    } else {
        match args.first().map(String::as_str) {
            Some("__singbox-launch") if args.len() == 1 => process::launch_singbox(&app),
            Some("__singbox-launch-worker") if args.len() == 1 => {
                process::launch_singbox_worker(&app)
            }
            Some("__module-update-worker") => {
                module_update::worker(&app, &args[1..]).map_err(str::to_owned)
            }
            Some("__override-materialize") if args.len() == 1 => {
                let result = overrides::materialize(&app).map_err(str::to_owned);
                reconcile_state(&app, "override-materialize");
                result
            }
            _ => dispatch(&app, &args),
        }
    };
    // Failed mutations also publish the observed rollback result. Observations
    // and detached producers remain read-only or publish at their own boundary.
    if commands::needs_state_reconcile(&args) {
        reconcile_state(&app, "post-command");
    }
    exit_result(result, 1);
}

fn proc_command(args: &[String]) -> Option<Result<(), String>> {
    let command = args.first()?.as_str();
    let args = &args[1..];
    Some(match command {
        "__proc-cmdline" => utils::proc_cmdline_command(args),
        "__proc-comm" => utils::proc_comm_command(args),
        "__proc-stat" => utils::proc_stat_command(args),
        "__proc-pids" => process::proc_named_pids_command(args),
        "__proc-script-pids" => process::proc_script_pids_command(args),
        _ => return None,
    })
}

fn exit_result(result: Result<(), String>, failure_code: i32) -> ! {
    match result {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            eprintln!("[error] {error}");
            std::process::exit(failure_code);
        }
    }
}
