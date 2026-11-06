//! A bounded, read-only snapshot. Export is the only operation that writes a file.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::{utils::read_module_text_bounded, App};

const BUDGET: Duration = Duration::from_secs(25);
const STREAM_LIMIT: usize = 32 * 1024;
const SECTION_LIMIT: usize = 48 * 1024;
const REPORT_LIMIT: usize = 512 * 1024;
const CONFIG_LIMIT: u64 = 4 * 1024 * 1024;
const EXPORT_NAME: &str = "MagicNet-diagnostics.txt";
const CURL_BUILD_RECORD: &str = "licenses/curl/build-provenance.json";
const CURL_BUILD_LIMIT: u64 = 16 * 1024;
static NEXT_EXPORT: AtomicU64 = AtomicU64::new(0);

pub(crate) struct SupportExport {
    pub(crate) path: String,
    pub(crate) bytes: usize,
}

pub(crate) fn export_bundle(app: &App) -> Result<SupportExport, String> {
    let text = bundle(app);
    let directory = if cfg!(target_os = "android") {
        PathBuf::from("/sdcard/Download/MagicNet")
    } else {
        app.moddir.join(".state/diagnostics")
    };
    persist_bundle(&directory, &text)
}

fn persist_bundle(directory: &Path, text: &str) -> Result<SupportExport, String> {
    if text.len() > REPORT_LIMIT {
        return Err("diagnostic report exceeds the export limit".into());
    }
    fs::create_dir_all(directory).map_err(|_| "diagnostic export directory is unavailable")?;
    if !fs::symlink_metadata(directory)
        .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
    {
        return Err("diagnostic export directory is unsafe".into());
    }
    let destination = directory.join(EXPORT_NAME);
    let sequence = NEXT_EXPORT.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".MagicNet-diagnostics-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| "cannot create diagnostic export")?;
    let write = (|| {
        file.write_all(text.as_bytes())
            .map_err(|_| "cannot write diagnostic export")?;
        file.sync_all()
            .map_err(|_| "cannot sync diagnostic export")?;
        fs::rename(&temporary, &destination).map_err(|_| "cannot publish diagnostic export")?;
        Ok::<_, String>(())
    })();
    if write.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write?;
    // External Android storage may not implement directory fsync or Unix modes.
    if let Ok(parent) = File::open(directory) {
        let _ = parent.sync_all();
    }
    Ok(SupportExport {
        path: destination.to_string_lossy().into_owned(),
        bytes: text.len(),
    })
}

pub(super) fn bundle(app: &App) -> String {
    let started = Instant::now();
    let config =
        read_module_text_bounded(app, Path::new(".config/sing-box/config.json"), CONFIG_LIMIT)
            .ok()
            .flatten()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let mut collector = Collector::new(started, config.as_ref());
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    collector.report.push_str(&format!(
        "MagicNet canonical support bundle\nschema=1\nformat=diagnostic-text-v1\ncaptured_epoch={epoch}\nsnapshot=sequential\nexternal_network_probes=not_run\nprivacy=redacted\ncommand_budget_seconds={}\nreport_limit_bytes={REPORT_LIMIT}\n",
        BUDGET.as_secs()
    ));
    collector.append("platform and versions", &platform(app));
    if cfg!(target_os = "android") {
        for property in [
            "ro.build.version.release",
            "ro.build.version.sdk",
            "ro.build.version.security_patch",
        ] {
            let value = collector.command(
                system_command("getprop"),
                &[property],
                Duration::from_secs(1),
            );
            collector.append_capture(&format!("Android: {property}"), &value);
        }
        let selinux = collector.command(system_command("getenforce"), &[], Duration::from_secs(1));
        collector.append_capture("SELinux mode", &selinux);
    }
    collector.append("system resources", &system_resources());
    collector.append("subscription lifecycle", &super::subscription_evidence(app));
    collector.append("startup state", &super::startup_state_evidence(app));
    collector.append("canonical state", &canonical_states(app));
    collector.append("connectivity history", &connectivity_snapshot(app));
    let curl_command = crate::trusted_curl(app);
    let curl_path = PathBuf::from(curl_command.get_program());
    let curl = collector.command(curl_command, &["--version"], Duration::from_secs(2));
    if curl.complete && curl_version_evidence(&curl).is_none() {
        collector.incomplete_commands += 1;
    }
    let curl_evidence = curl_executor_evidence(app, &curl_path, &curl, &collector.privacy);
    collector.append_safe("curl executor", &curl_evidence);
    collector.append("configuration structure", if config.is_some() {
        "status=available\nreferences=stable_report_local_aliases\nsecrets_and_device_identifiers=omitted\narray_entry_limit=128"
    } else { "status=unavailable reason=missing_invalid_or_oversized_config" });
    if let Some(config) = &config {
        // Put route order and DNS before potentially large node inventories.
        for key in [
            "route",
            "dns",
            "inbounds",
            "outbounds",
            "endpoints",
            "experimental",
            "log",
        ] {
            if let Some(value) = config.get(key) {
                let safe = collector.privacy.project(value, key, 0);
                collector.append_safe(
                    &format!("configuration: {key}"),
                    &serde_json::to_string_pretty(&safe).unwrap_or_default(),
                );
            }
        }
    }
    collector.append(
        "subscription refresh log counts",
        &super::subscription_refresh_log_counts(app.log_dir.join("subscription-refresh.log")),
    );
    for name in [
        "sing-box",
        "service",
        "subscription-refresh",
        "connectivity",
        "magicnet-kernel",
        "fswatch",
        "supervisors",
        "connectivity-watchdog",
    ] {
        collector.append(&format!("recent logs: {name}"), &log_tail(app, name));
    }

    // Subprocess isolation applies one monotonic deadline even if a platform
    // utility or a nested health observation hangs. No write command is called.
    let service = collector.cli(
        app,
        &["--json", "service", "status"],
        Duration::from_secs(5),
    );
    collector.append_machine_capture("service status", &service, "service.status");
    collector.append("core resources", &core_resources(service.json().as_ref()));
    let health = collector.cli(app, &["health"], Duration::from_secs(7));
    collector.append_capture("health", &health);
    let version = collector.command(
        Command::new(app.moddir.join("bin/sing-box")),
        &["version"],
        Duration::from_secs(2),
    );
    collector.append_capture("sing-box version", &version);
    collector.append_safe("sing-box build identity", &version_identity(&version));
    let mut check = Command::new(app.moddir.join("bin/sing-box"));
    check.current_dir(app.moddir.join(".config/sing-box"));
    let checked = collector.command(
        check,
        &["check", "-c", "config.json"],
        Duration::from_secs(3),
    );
    collector.append_capture("sing-box configuration check", &checked);

    let listeners = collector.command(system_command("ss"), &["-lntu"], Duration::from_secs(2));
    collector.append_capture("core process and listeners", &listeners);
    collector.append(
        "tun routes and ip rules",
        "families=ipv4,ipv6\nevidence=following_route_sections",
    );
    for (label, args) in [
        ("links", vec!["-d", "-s", "link", "show"]),
        ("addresses", vec!["-o", "addr", "show"]),
        ("ipv4 rules", vec!["-4", "rule", "show"]),
        ("ipv6 rules", vec!["-6", "rule", "show"]),
        ("ipv4 routes", vec!["-4", "route", "show", "table", "all"]),
        ("ipv6 routes", vec!["-6", "route", "show", "table", "all"]),
    ] {
        let captured = collector.command(system_command("ip"), &args, Duration::from_secs(2));
        collector.append_capture(&format!("routes: {label}"), &captured);
    }
    for family in ["iptables-save", "ip6tables-save"] {
        let captured = collector.command(system_command(family), &["-c"], Duration::from_secs(2));
        collector.append(&format!("firewall: {family}"), &managed_firewall(&captured));
    }
    let transparent = collector.cli(
        app,
        &["--json", "transparent", "status"],
        Duration::from_secs(5),
    );
    collector.append_machine_capture(
        "transparent TUN and eBPF observation",
        &transparent,
        "transparent.status",
    );
    collector.append("kernel networking", &kernel_networking());

    let proxies = collector.cli(app, &["api", "proxies"], Duration::from_secs(3));
    let connections = collector.cli(app, &["api", "conns"], Duration::from_secs(3));
    collector.append(
        "proxy selector and connection chains",
        &format!(
            "proxies: {}\nconnections: {}\n{}",
            proxies.status,
            connections.status,
            super::proxy_chain_evidence_from_values(
                proxies.json().as_ref(),
                connections.json().as_ref()
            ),
        ),
    );
    let dns = collector.cli(app, &["--json", "dns", "status"], Duration::from_secs(2));
    let mcp = collector.cli(app, &["mcp", "status"], Duration::from_secs(2));
    let dns = collector.machine_text(&dns, "dns.status");
    let mcp = collector.redacted_text(&mcp.text());
    collector.append_safe(
        "dns api and mcp",
        &format!("--- dns ---\n{dns}\n--- mcp ---\n{mcp}"),
    );
    collector.finish()
}

struct Capture {
    status: String,
    stdout: String,
    stderr: String,
    complete: bool,
}

impl Capture {
    fn unavailable(reason: &str) -> Self {
        Self {
            status: format!("status=unavailable reason={reason}"),
            stdout: String::new(),
            stderr: String::new(),
            complete: false,
        }
    }
    fn text(&self) -> String {
        format!(
            "{}\n{}{}{}",
            self.status,
            self.stdout,
            if self.stderr.is_empty() {
                ""
            } else {
                "\nstderr:\n"
            },
            self.stderr
        )
    }
    fn json(&self) -> Option<Value> {
        self.complete
            .then(|| serde_json::from_str(&self.stdout).ok())
            .flatten()
    }
}

struct Collector {
    started: Instant,
    report: String,
    privacy: Privacy,
    incomplete_commands: usize,
    truncated_sections: usize,
}

impl Collector {
    fn new(started: Instant, config: Option<&Value>) -> Self {
        Self {
            started,
            report: String::new(),
            privacy: Privacy::new(config),
            incomplete_commands: 0,
            truncated_sections: 0,
        }
    }

    fn append_capture(&mut self, title: &str, capture: &Capture) {
        self.append(title, &capture.text());
    }

    fn redacted_text(&self, text: &str) -> String {
        text.lines()
            .map(|line| self.privacy.line(line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn append_machine_capture(&mut self, title: &str, capture: &Capture, command: &str) {
        let text = self.machine_text(capture, command);
        self.append_safe(title, &text);
    }

    fn machine_text(&mut self, capture: &Capture, command: &str) -> String {
        // Only these bounded, read-only machine responses use structural redaction.
        // A compact JSON URL must not cause the text redactor to discard its envelope.
        let value = (matches!(
            command,
            "service.status" | "transparent.status" | "dns.status"
        ) && capture.stdout.len() <= STREAM_LIMIT)
            .then(|| capture.json())
            .flatten()
            .filter(|value| {
                value["schema"] == 1
                    && value["ok"] == true
                    && value["command"] == command
                    && value["data"].is_object()
            });
        let mut stdout = if let Some(value) = value {
            serde_json::to_string(&self.privacy.machine_value(&value, "", 0))
                .unwrap_or_else(|_| "{\"omitted\":\"machine_json_serialization_failed\"}".into())
        } else {
            if capture.complete {
                self.incomplete_commands += 1;
            }
            // Do not fall back to raw malformed/truncated JSON: arbitrary string
            // values and dynamic keys may carry secrets absent from the config.
            "{\"omitted\":\"invalid_or_incomplete_machine_json\"}".into()
        };
        let available = (SECTION_LIMIT - 1024)
            .min(REPORT_LIMIT.saturating_sub(self.report.len() + 8192 + 1024));
        if stdout.len() > available {
            stdout = "{\"omitted\":\"machine_json_output_limit\"}".into();
            self.truncated_sections += 1;
        }
        // Serialize on one line: append_lines can omit the entire value at a
        // report boundary, but can never cut a JSON document between its lines.
        let mut text = format!("{}\n{stdout}", self.privacy.line(&capture.status));
        if !capture.stderr.is_empty() {
            text.push_str("\nstderr:\n");
            text.push_str(&self.redacted_text(&capture.stderr));
        }
        text
    }

    fn append(&mut self, title: &str, text: &str) {
        let mut redacted = text.lines().map(|line| self.privacy.line(line)).peekable();
        // Preserve the old join/lines treatment of a final empty redacted line.
        let lines = std::iter::from_fn(|| {
            let line = redacted.next()?;
            (!line.is_empty() || redacted.peek().is_some()).then_some(line)
        });
        Self::append_lines(&mut self.report, &mut self.truncated_sections, title, lines);
    }

    fn append_safe(&mut self, title: &str, text: &str) {
        Self::append_lines(
            &mut self.report,
            &mut self.truncated_sections,
            title,
            text.lines(),
        );
    }

    fn append_lines<S: AsRef<str>>(
        report: &mut String,
        truncated: &mut usize,
        title: &str,
        lines: impl Iterator<Item = S>,
    ) {
        report.push_str("\n[");
        report.push_str(title);
        report.push_str("]\n");
        let start = report.len();
        for line in lines {
            let line = line.as_ref();
            if report.len() - start + line.len() > SECTION_LIMIT
                || report.len() + line.len() > REPORT_LIMIT - 8192
            {
                report.push_str("status=truncated reason=report_output_limit\n");
                *truncated += 1;
                break;
            }
            report.push_str(line);
            report.push('\n');
        }
        if report.len() == start {
            report.push_str("status=unavailable reason=no_evidence\n");
        }
    }

    fn command(&mut self, mut command: Command, args: &[&str], timeout: Duration) -> Capture {
        let remaining = BUDGET.saturating_sub(self.started.elapsed());
        if remaining.is_zero() {
            self.incomplete_commands += 1;
            return Capture::unavailable("collection_deadline");
        }
        command.args(args);
        let started = Instant::now();
        let captured =
            match crate::run_bounded_command(command, timeout.min(remaining), STREAM_LIMIT) {
                Ok(output) => {
                    let complete = output.status.is_some_and(|status| status.success())
                        && !output.timed_out
                        && !output.truncated;
                    Capture {
                        status: format!(
                        "status={} exit_code={} timed_out={} output_truncated={} duration_ms={}",
                        if complete { "ok" } else { "incomplete" },
                        output
                            .status
                            .and_then(|status| status.code())
                            .map_or("unknown".into(), |code| code.to_string()),
                        output.timed_out,
                        output.truncated,
                        started.elapsed().as_millis()
                    ),
                        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                        complete,
                    }
                }
                Err(error) => Capture::unavailable(&format!(
                    "command_spawn_failed detail={}",
                    super::redact(&error)
                )),
            };
        if !captured.complete {
            self.incomplete_commands += 1;
        }
        captured
    }

    fn cli(&mut self, app: &App, args: &[&str], timeout: Duration) -> Capture {
        let executable = std::env::current_exe()
            .ok()
            .filter(|path| path.file_name().is_some_and(|name| name == "magicnet-cli"))
            .unwrap_or_else(|| app.moddir.join("bin/magicnet-cli"));
        let mut command = Command::new(executable);
        command
            .env("MODDIR", &app.moddir)
            .env("MAGICNET_API", &app.api);
        self.command(command, args, timeout)
    }

    fn finish(mut self) -> String {
        self.report.push_str(&format!(
            "\n[collection summary]\nduration_ms={}\nincomplete_commands={}\ntruncated_sections={}\nexternal_network_probes=not_run\nstate_mutations=none\nmissing_or_truncated_evidence_is_not_success=true\nend_of_report=true\n",
            self.started.elapsed().as_millis(), self.incomplete_commands, self.truncated_sections
        ));
        self.report
    }
}

fn system_command(program: &str) -> Command {
    let android = Path::new("/system/bin").join(program);
    Command::new(if cfg!(target_os = "android") {
        android
    } else {
        PathBuf::from(program)
    })
}

fn version_identity(capture: &Capture) -> String {
    if !capture.complete {
        return "status=unavailable reason=version_command_incomplete".into();
    }
    let Some(version) = capture
        .stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("sing-box version "))
    else {
        return "status=unavailable reason=version_format_unknown".into();
    };
    let numeric = version.split(['-', '+']).next().unwrap_or_default();
    let parts = numeric.split('.').collect::<Vec<_>>();
    if version.len() <= 96
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
        && parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        format!("version={version}")
    } else {
        "status=unavailable reason=version_format_unknown".into()
    }
}

fn public_numeric_version(value: &str) -> Option<&str> {
    let parts = value.split('.').collect::<Vec<_>>();
    (value.len() <= 32
        && (2..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())))
    .then_some(value)
}

fn public_digest(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|text| text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn public_date(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| {
        text.len() == 10
            && text.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 4 | 7) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit()
                }
            })
    })
}

fn curl_version_evidence(capture: &Capture) -> Option<Value> {
    if !capture.complete || capture.stdout.len() > STREAM_LIMIT {
        return None;
    }
    let first = capture.stdout.lines().next()?;
    let mut words = first.split_whitespace();
    if words.next()? != "curl" {
        return None;
    }
    let version = public_numeric_version(words.next()?)?;
    let library = |name: &str| {
        first.split_whitespace().find_map(|word| {
            word.strip_prefix(name)
                .and_then(|value| value.strip_prefix('/'))
                .and_then(public_numeric_version)
        })
    };
    let libcurl = library("libcurl")?;
    let list = |prefix| {
        let mut lines = capture
            .stdout
            .lines()
            .filter_map(|line| line.strip_prefix(prefix));
        let line = lines.next()?;
        lines.next().is_none().then_some(line)
    };
    let protocols = list("Protocols:")?;
    let features = list("Features:")?;
    let tls = [
        "OpenSSL", "LibreSSL", "GnuTLS", "mbedTLS", "wolfSSL", "rustls",
    ]
    .into_iter()
    .find_map(|backend| library(backend).map(|version| (backend, version)));
    Some(json!({
        "curl_version": version,
        "libcurl_version": libcurl,
        "tls_backend": tls.map(|(backend, _)| backend),
        "tls_version": tls.map(|(_, version)| version),
        "zlib_version": library("zlib"),
        "capabilities": {
            "https": protocols.split_whitespace().any(|word| word == "https"),
            "tls": features.split_whitespace().any(|word| word == "SSL"),
            "gzip": features.split_whitespace().any(|word| word == "libz"),
        },
        "network_request": "not_run",
        "unrecognized_version_text": "omitted"
    }))
}

fn curl_build_evidence(app: &App, selected_module_binary: bool) -> Value {
    let invalid = || json!({"status":"unavailable", "reason":"build_record_invalid_or_oversized"});
    let text = match read_module_text_bounded(app, Path::new(CURL_BUILD_RECORD), CURL_BUILD_LIMIT) {
        Ok(Some(text)) => text,
        Ok(None) => return json!({"status":"unavailable", "reason":"build_record_missing"}),
        Err(_) => return invalid(),
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return invalid();
    };
    let target = &value["target"];
    let versions = &value["versions"];
    let ca = &value["ca"];
    let numeric_version = |key: &str| versions[key].as_str().and_then(public_numeric_version);
    if value["schema"] != 1
        || value["scope"] != "production-android-curl"
        || target["os"] != "android"
        || !matches!(target["abi"].as_str(), Some("arm64-v8a" | "x86_64"))
        || !target["api"]
            .as_u64()
            .is_some_and(|api| (21..=100).contains(&api))
        || ["curl", "openssl", "zlib"]
            .iter()
            .any(|key| numeric_version(key).is_none())
        || ca["mode"] != "embedded"
        || public_date(&ca["version"]).is_none()
        || public_digest(&ca["sha256"]).is_none()
        || !ca["bytes"]
            .as_u64()
            .is_some_and(|bytes| (1..=2 * 1024 * 1024).contains(&bytes))
        || !ca["cert_count"]
            .as_u64()
            .is_some_and(|count| (1..=4096).contains(&count))
        || ca["runtime_bundle"] != false
        || ca["system_store"] != false
        || public_digest(&value["curl_sha256"]).is_none()
        || !value["curl_bytes"]
            .as_u64()
            .is_some_and(|bytes| (1..=32 * 1024 * 1024).contains(&bytes))
    {
        return invalid();
    }
    // This is a declaration from the packaged build, not runtime attestation.
    // Select only public, typed fields; never expose source URLs, compiler
    // strings, arbitrary keys or private data injected into this JSON file.
    let sources = ["curl", "openssl", "zlib", "ca"]
        .into_iter()
        .map(|name| {
            (
                name,
                json!({"sha256":public_digest(&value["sources"][name]["sha256"])}),
            )
        })
        .collect::<BTreeMap<_, _>>();
    json!({
        "status": "available",
        "source": "packaged_build_record",
        "applies_to_selected_path": selected_module_binary,
        "binary_digest_verification": "not_run",
        "schema": 1,
        "scope": "production-android-curl",
        "target": {"os":"android", "abi":target["abi"], "api":target["api"]},
        "versions": {"curl":numeric_version("curl"), "openssl":numeric_version("openssl"), "zlib":numeric_version("zlib")},
        "ca": {"mode":"embedded", "version":public_date(&ca["version"]),
            "sha256":public_digest(&ca["sha256"]), "bytes":ca["bytes"],
            "cert_count":ca["cert_count"], "runtime_bundle":false, "system_store":false},
        "sources": sources,
        "curl_sha256": public_digest(&value["curl_sha256"]),
        "curl_bytes": value["curl_bytes"],
        "builder_sha256": public_digest(&value["builder_sha256"]),
        "toolchain": {
            "ndk_revision":value["toolchain"]["ndk_revision"].as_str().and_then(public_numeric_version),
            "ndk_source_properties_sha256":public_digest(&value["toolchain"]["ndk_source_properties_sha256"])
        },
        "runtime_capability": value["runtime_capability"].as_str().filter(|value| *value == "not_tested"),
        "other_build_fields": "omitted"
    })
}

fn curl_executor_evidence(app: &App, path: &Path, capture: &Capture, privacy: &Privacy) -> String {
    let module_binary = path == app.moddir.join("bin/curl");
    let selection = if !path.is_file() {
        "missing"
    } else if module_binary {
        "module_bin"
    } else if path == app.moddir.join("system/bin/curl") {
        "module_system"
    } else {
        "system"
    };
    let version = curl_version_evidence(capture);
    let mut text = format!(
        "selection={selection} available={}\nnetwork_request=not_run\n--- version ---\n{}\n{}",
        version.is_some(),
        privacy.line(&capture.status),
        version.unwrap_or_else(|| json!({"omitted":"version_unavailable_or_invalid"}))
    );
    if !capture.stderr.is_empty() {
        text.push_str("\nstderr:\n");
        for line in capture.stderr.lines() {
            text.push_str(&privacy.line(line));
            text.push('\n');
        }
    }
    text.push_str("\n--- build provenance ---\n");
    text.push_str(&curl_build_evidence(app, module_binary).to_string());
    text
}

fn module_text(app: &App, path: &str, limit: u64) -> String {
    match read_module_text_bounded(app, Path::new(path), limit) {
        Ok(Some(text)) => text,
        Ok(None) => "status=unavailable reason=missing".into(),
        Err(_) => "status=unavailable reason=unreadable_or_oversized".into(),
    }
}

fn platform(app: &App) -> String {
    let module = module_text(app, "module.prop", 16384)
        .lines()
        .filter(|line| {
            line.split_once('=')
                .is_some_and(|(key, _)| matches!(key, "id" | "version" | "versionCode"))
        })
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .join("\n");
    let kernel = read_system("/proc/sys/kernel/osrelease", 256);
    let version = kernel
        .trim()
        .split('-')
        .next()
        .filter(|value| value.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        .unwrap_or("unknown");
    format!(
        "{module}\ncli_version={}\nos={}\narch={}\nkernel_version={version}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

fn read_system(path: &str, limit: u64) -> String {
    // Kernel proc/sys files report a length of zero; the descriptor read is bounded.
    let result = (|| {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        let mut text = String::new();
        file.take(limit + 1).read_to_string(&mut text)?;
        if text.len() as u64 > limit {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        Ok::<_, std::io::Error>(text)
    })();
    result.unwrap_or_else(|_| "unavailable".into())
}

fn system_resources() -> String {
    let memory = read_system("/proc/meminfo", 16384)
        .lines()
        .filter(|line| {
            line.split_once(':').is_some_and(|(key, _)| {
                matches!(
                    key,
                    "MemTotal"
                        | "MemFree"
                        | "MemAvailable"
                        | "Buffers"
                        | "Cached"
                        | "SwapTotal"
                        | "SwapFree"
                        | "SReclaimable"
                        | "Slab"
                )
            })
        })
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .join("\n");
    let uptime = read_system("/proc/uptime", 256);
    let load = read_system("/proc/loadavg", 256)
        .split_whitespace()
        .take(4)
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "uptime_seconds={}\nload={load}\n{memory}",
        uptime.split_whitespace().next().unwrap_or("unknown")
    )
}

fn core_resources(service: Option<&Value>) -> String {
    let Some(pids) = service
        .and_then(|value| value.pointer("/data/core/sing_box/pid_summary"))
        .and_then(Value::as_str)
    else {
        return "status=unavailable reason=owned_core_process_unknown".into();
    };
    if pids == "stopped" {
        return "process=stopped".into();
    }
    let mut text = String::new();
    for pid in pids
        .split(',')
        .take(8)
        .filter(|pid| pid.parse::<u32>().is_ok_and(|n| n != 0))
    {
        text.push_str(&format!("pid={pid}\n"));
        let status = read_system(&format!("/proc/{pid}/status"), 16384);
        for line in status.lines().filter(|line| {
            line.split_once(':').is_some_and(|(key, _)| {
                matches!(
                    key,
                    "State"
                        | "FDSize"
                        | "VmPeak"
                        | "VmSize"
                        | "VmHWM"
                        | "VmRSS"
                        | "RssAnon"
                        | "RssFile"
                        | "VmSwap"
                        | "Threads"
                        | "voluntary_ctxt_switches"
                        | "nonvoluntary_ctxt_switches"
                )
            })
        }) {
            text.push_str(line);
            text.push('\n');
        }
        let fd_count = fs::read_dir(format!("/proc/{pid}/fd"))
            .ok()
            .map(|entries| entries.take(65536).count());
        text.push_str(&format!(
            "fd_count={}\n",
            fd_count.map_or("unknown".into(), |n| n.to_string())
        ));
        for name in ["schedstat", "io"] {
            text.push_str(&format!(
                "{name}:\n{}\n",
                read_system(&format!("/proc/{pid}/{name}"), 4096)
            ));
        }
    }
    if text.is_empty() {
        "status=unavailable reason=owned_core_process_unknown".into()
    } else {
        text
    }
}

fn canonical_states(app: &App) -> String {
    let mut text = String::new();
    for domain in [
        "service",
        "transparent",
        "subscription",
        "subscription-refresh",
        "selectors",
        "app-policy",
        "supervisors",
        "wifi",
        "hotspot",
        "dns",
        "mcp",
        "tailscale",
        "transactions",
        "overrides",
        "module-update",
    ] {
        text.push_str(&format!("--- {domain} ---\n"));
        let state = module_text(app, &format!(".state/machines/{domain}.state"), 16384);
        for line in state.lines().take(128) {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.len() <= 64
                && value.len() <= 256
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !key.contains("boot")
                && !key.contains("identity")
            {
                text.push_str(line);
                text.push('\n');
            }
        }
    }
    text
}

fn connectivity_snapshot(app: &App) -> String {
    // Read the canonical producer snapshot; report collection never causes probes.
    module_text(app, ".state/machines/connectivity.state", 16384)
        .lines()
        .filter(|line| {
            !line
                .split_once('=')
                .is_some_and(|(key, _)| key.contains("boot"))
        })
        .take(96)
        .collect::<Vec<_>>()
        .join("\n")
}

fn log_tail(app: &App, name: &str) -> String {
    let path = app.log_dir.join(format!("{name}.log"));
    let read = (|| {
        let module = fs::canonicalize(&app.moddir)?;
        if !fs::canonicalize(&path)?.starts_with(module) {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        let file = crate::files::open_regular_file(&path)?;
        let len = file.metadata()?.len();
        let text = crate::logs::read_log_snapshot(file, len, STREAM_LIMIT as u64)?;
        if len > STREAM_LIMIT as u64 && !text.contains('\n') {
            return Ok(format!("total_bytes={len} tail_only=true status=truncated reason=oversized_unterminated_line"));
        }
        let tail = crate::logs::tail_lines(&text, 120)
            .collect::<Vec<_>>()
            .join("\n");
        Ok::<_, std::io::Error>(format!(
            "total_bytes={len} tail_only=true retained_lines={} retained_bytes={}\n{tail}",
            tail.lines().count(),
            tail.len()
        ))
    })();
    read.unwrap_or_else(|_| "status=unavailable reason=missing_or_unreadable_log".into())
}

fn managed_firewall(capture: &Capture) -> String {
    let mut lines = vec![capture.status.clone()];
    let mut table = "";
    for line in capture.stdout.lines() {
        if line.starts_with('*') {
            table = line;
        }
        // Keep policies and MagicNet rule counters; unrelated app UID rules and
        // comments are private and do not diagnose our owned interception rules.
        let upper = line.to_ascii_uppercase();
        if line.starts_with(':') && !line.contains("- [") || upper.contains("MAGICNET") {
            lines.push(format!("{table} {line}"));
        }
    }
    if !capture.stderr.is_empty() {
        lines.push(format!("stderr: {}", capture.stderr));
    }
    lines.join("\n")
}

fn kernel_networking() -> String {
    let mut text = String::new();
    for path in [
        "net/ipv4/ip_forward",
        "net/ipv4/conf/all/rp_filter",
        "net/ipv4/conf/default/rp_filter",
        "net/ipv6/conf/all/forwarding",
        "net/ipv6/conf/all/disable_ipv6",
        "net/ipv6/conf/default/disable_ipv6",
        "net/core/rmem_max",
        "net/core/wmem_max",
        "net/netfilter/nf_conntrack_count",
        "net/netfilter/nf_conntrack_max",
    ] {
        text.push_str(&format!(
            "{}={}\n",
            path.replace('/', "."),
            read_system(&format!("/proc/sys/{path}"), 256).trim()
        ));
    }
    for name in ["snmp", "netstat", "dev"] {
        text.push_str(&format!(
            "--- {name} ---\n{}\n",
            read_system(&format!("/proc/net/{name}"), 16384)
        ));
    }
    text
}

#[derive(Default)]
struct Privacy {
    private: Vec<String>,
    aliases: BTreeMap<String, usize>,
    inventory_complete: bool,
}

impl Privacy {
    fn new(config: Option<&Value>) -> Self {
        fn collect(value: &Value, strings: &mut BTreeSet<String>, complete: &mut bool) {
            if strings.len() >= 4096 {
                *complete = false;
                return;
            }
            match value {
                Value::String(value) if !value.is_empty() && !public_value(value) => {
                    strings.insert(value.clone());
                }
                Value::Array(items) => {
                    for item in items {
                        collect(item, strings, complete);
                    }
                }
                Value::Object(items) => {
                    for item in items.values() {
                        collect(item, strings, complete);
                    }
                }
                _ => (),
            }
        }
        let mut private = BTreeSet::new();
        let mut inventory_complete = true;
        if let Some(config) = config {
            collect(config, &mut private, &mut inventory_complete);
        }
        let mut private: Vec<_> = private.into_iter().collect();
        private.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self {
            private,
            aliases: BTreeMap::new(),
            inventory_complete,
        }
    }

    fn line(&self, line: &str) -> String {
        let mut safe = strip_controls(line);
        // Credential headers can contain multiword values.
        let lower = safe.to_ascii_lowercase();
        if let Some(index) = [
            "authorization",
            "proxy-authorization",
            "x-magicnet-mcp-secret",
            "cookie",
            "set-cookie",
        ]
        .iter()
        .filter_map(|name| {
            lower.match_indices(name).find_map(|(index, _)| {
                lower[index + name.len()..]
                    .trim_start()
                    .starts_with(':')
                    .then_some(index)
            })
        })
        .min()
        {
            safe.truncate(index);
            safe.push_str("<redacted-header>");
        }
        if !self.inventory_complete {
            return "status=omitted reason=redaction_inventory_limit".into();
        }
        for value in &self.private {
            if value.len() >= 4 {
                safe = safe.replace(value, "<private-value>");
            }
        }
        // sing-box puts node labels inside brackets, often without `node=`.
        for prefix in ["outbound/", "inbound/", "endpoint/"] {
            let mut from = 0;
            while let Some(offset) = safe[from..].find(prefix) {
                let start = from + offset;
                let Some(open) = safe[start..].find('[').map(|n| start + n) else {
                    break;
                };
                let Some(close) = safe[open..].find(']').map(|n| open + n) else {
                    break;
                };
                if safe[start..open].chars().any(char::is_whitespace) {
                    from = start + prefix.len();
                    continue;
                }
                safe.replace_range(open + 1..close, "private-label");
                from = open + "[private-label]".len();
            }
        }
        let mut hide_next = false;
        let mut filtered = String::with_capacity(safe.len());
        for token in safe.split_whitespace() {
            let value = if hide_next {
                hide_next = false;
                "<private-uid-or-comment>"
            } else {
                hide_next = matches!(
                    token,
                    "uidrange" | "uid" | "uid-owner" | "--uid-owner" | "--gid-owner" | "--comment"
                );
                if self.private.iter().any(|value| {
                    value.len() < 4
                        && token.trim_matches(['\"', '\'', '[', ']', '(', ')', ',', ':']) == value
                }) {
                    "<private-value>"
                } else {
                    token
                }
            };
            if !filtered.is_empty() {
                filtered.push(' ');
            }
            filtered.push_str(value);
        }
        super::redact(&filtered)
    }

    fn symbol(&mut self, value: &str) -> String {
        if public_value(value) {
            return value.into();
        }
        self.private_symbol(value)
    }

    fn private_symbol(&mut self, value: &str) -> String {
        let next = self.aliases.len() + 1;
        let id = self.aliases.entry(value.into()).or_insert(next);
        format!("<ref:{id}>")
    }

    fn machine_value(&mut self, value: &Value, key: &str, depth: usize) -> Value {
        if depth > 24 {
            return json!({"omitted": "depth_limit"});
        }
        if machine_private_key(key) {
            return json!({"present": !value.is_null(), "count": value.as_array().map(Vec::len)});
        }
        match value {
            Value::Object(items) => Value::Object(
                items
                    .iter()
                    .map(|(key, value)| {
                        // A node name, device identifier or credential can also be a key.
                        // Keep unknown fields observable using report-local aliases.
                        let safe_key = if machine_key(key) {
                            key.clone()
                        } else {
                            self.private_symbol(key)
                        };
                        (safe_key, self.machine_value(value, key, depth + 1))
                    })
                    .collect(),
            ),
            Value::Array(items) => {
                let mut result = items
                    .iter()
                    .take(128)
                    .map(|value| self.machine_value(value, key, depth + 1))
                    .collect::<Vec<_>>();
                if items.len() > 128 {
                    result.push(json!({"omitted_entries": items.len() - 128}));
                }
                Value::Array(result)
            }
            Value::String(value) if machine_public_value(key, value) => value.clone().into(),
            Value::String(value) if value.contains("://") => "<redacted-url>".into(),
            Value::String(value) => self.private_symbol(value).into(),
            _ => value.clone(),
        }
    }

    fn project(&mut self, value: &Value, key: &str, depth: usize) -> Value {
        if depth > 24 {
            return json!({"omitted": "depth_limit"});
        }
        if private_key(key) {
            return json!({"present": !value.is_null(), "count": value.as_array().map(Vec::len)});
        }
        match value {
            Value::Object(items) => {
                let mut result = serde_json::Map::new();
                let mut omitted = 0;
                for (key, value) in items {
                    if known_key(key) {
                        result.insert(key.clone(), self.project(value, key, depth + 1));
                    } else {
                        omitted += 1;
                    }
                }
                if omitted > 0 {
                    result.insert("unrecognized_fields".into(), json!(omitted));
                }
                Value::Object(result)
            }
            Value::Array(items) => {
                let mut result = items
                    .iter()
                    .take(128)
                    .map(|value| self.project(value, key, depth + 1))
                    .collect::<Vec<_>>();
                if items.len() > 128 {
                    result.push(json!({"omitted_entries": items.len() - 128}));
                }
                Value::Array(result)
            }
            Value::String(value) => Value::String(self.symbol(value)),
            _ => value.clone(),
        }
    }
}

fn machine_private_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let compact = lower.replace(['_', '-'], "");
    private_key(&lower)
        || compact.contains("uid")
        || compact.contains("boot")
        || matches!(
            compact.as_str(),
            "id" | "gid"
                | "gids"
                | "devid"
                | "deviceid"
                | "androidid"
                | "serial"
                | "serialnumber"
                | "imei"
                | "imsi"
                | "mac"
                | "macaddress"
                | "authorization"
                | "proxyauthorization"
                | "cookie"
                | "setcookie"
                | "header"
                | "headers"
                | "auth"
        )
        || [
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "privatekey",
            "publickey",
            "authkey",
        ]
        .iter()
        .any(|suffix| compact.ends_with(suffix))
}

// This is the schema of the three captured machine commands, independent of
// sing-box's configuration vocabulary. Unknown fields are aliased, not dropped.
fn machine_key(key: &str) -> bool {
    matches!(
        key,
        "schema"
            | "ok"
            | "command"
            | "data"
            | "error"
            | "code"
            | "message"
            | "lifecycle"
            | "core"
            | "selected"
            | "sing_box"
            | "process_state"
            | "running"
            | "pid_summary"
            | "rss_kib"
            | "supervisors"
            | "fswatch"
            | "wifi_policy"
            | "transparent"
            | "api"
            | "url"
            | "webui"
            | "ready"
            | "readiness"
            | "dataplane"
            | "overall"
            | "subscription"
            | "source"
            | "connectivity"
            | "mode"
            | "configured_mode"
            | "effective_type"
            | "effective_mode"
            | "capability"
            | "local_cgroup"
            | "shared_tc"
            | "shared_interface_count"
            | "transition"
            | "has_recent_error"
            | "dataplane_ready"
            | "local_ready"
            | "shared_ready"
            | "target"
            | "path"
            | "status"
            | "phase"
            | "reason"
            | "primary_reason"
            | "warning"
            | "checked_at"
            | "next_check_at"
            | "retry_in_seconds"
            | "consecutive_failures"
            | "probe_count"
            | "backoff_seconds"
            | "latency_ms"
            | "http_status"
            | "secondary_status"
            | "direct_status"
            | "last_action"
            | "action_status"
            | "last_action_at"
            | "last_refresh_at"
            | "profile"
            | "primary"
            | "secondary"
            | "transport"
    )
}

fn machine_public_value(key: &str, value: &str) -> bool {
    match key {
        "command" => matches!(
            value,
            "service.status" | "transparent.status" | "dns.status"
        ),
        "target" => value == crate::connectivity::TARGET,
        "path" => value == "mixed_proxy",
        "selected" => value == "sing-box",
        "pid_summary" | "fswatch" | "wifi_policy" => {
            matches!(value, "stopped" | "unknown")
                || (value.len() <= 96
                    && value.split(',').count() <= 8
                    && value
                        .split(',')
                        .all(|pid| pid.parse::<u32>().is_ok_and(|pid| pid > 0)))
        }
        "source" => matches!(value, "local_file" | "remote_url" | "unknown"),
        "profile" => matches!(
            value,
            "default" | "cloudflare-doh" | "cloudflare-dot" | "cloudflare-udp"
        ),
        "transport" => matches!(value, "default" | "doh" | "dot" | "udp"),
        "mode" | "configured_mode" | "effective_type" | "effective_mode" => {
            matches!(
                value,
                "tun" | "ebpf" | "local" | "shared" | "hybrid" | "unknown"
            )
        }
        "transition" => matches!(
            value,
            "idle"
                | "prepared"
                | "target-written"
                | "preflight"
                | "candidate-prepared"
                | "stopping-old"
                | "old-stopped"
                | "candidate-starting"
                | "verified"
                | "rolling-back"
                | "old-restored"
        ),
        "status" | "phase" | "process_state" | "lifecycle" | "capability" | "local_cgroup"
        | "shared_tc" | "secondary_status" | "direct_status" | "action_status" => {
            matches!(
                value,
                "unknown"
                    | "running"
                    | "stopped"
                    | "ready"
                    | "not_ready"
                    | "running_unknown"
                    | "reconfiguring"
                    | "pending"
                    | "online"
                    | "degraded"
                    | "offline"
                    | "paused"
                    | "stale"
                    | "ok"
                    | "failed"
                    | "not_run"
                    | "none"
                    | "busy"
                    | "not_required"
                    | "inactive"
                    | "configured"
                    | "attached"
                    | "missing"
                    | "idle"
                    | "prepared"
                    | "stopping"
                    | "applying"
                    | "starting"
                    | "rolling-back"
                    | "rolled-back"
            )
        }
        "reason" | "primary_reason" => matches!(
            value,
            "ok" | "not_checked"
                | "probing"
                | "core_stopped"
                | "core_unknown"
                | "module_disabled"
                | "stop_requested"
                | "no_default_route"
                | "dns_failure"
                | "proxy_refused"
                | "timeout"
                | "tls_failure"
                | "http_error"
                | "probe_unavailable"
                | "probe_invalid"
                | "proxy_unavailable"
                | "endpoint_specific"
                | "upstream_unavailable"
                | "transport_failure"
                | "clock_unavailable"
                | "monitor_overdue"
        ),
        "last_action" => matches!(
            value,
            "none" | "repair" | "refresh" | "restart" | "deferred"
        ),
        _ => false,
    }
}

fn private_key(key: &str) -> bool {
    matches!(
        key,
        "password"
            | "uuid"
            | "secret"
            | "private_key"
            | "public_key"
            | "auth_key"
            | "token"
            | "username"
            | "users"
            | "include_uid"
            | "exclude_uid"
            | "include_android_user"
            | "user_id"
            | "user"
            | "process_name"
            | "process_path"
            | "package_name"
            | "ssid"
            | "bssid"
            | "certificate"
            | "key"
            | "certificate_path"
            | "key_path"
            | "headers"
    )
}

fn known_key(key: &str) -> bool {
    private_key(key)
        || matches!(
            key,
            "log"
                | "level"
                | "disabled"
                | "timestamp"
                | "dns"
                | "servers"
                | "server"
                | "server_port"
                | "address"
                | "port"
                | "type"
                | "tag"
                | "detour"
                | "download_detour"
                | "final"
                | "rules"
                | "rule_set"
                | "rule_set_ip_cidr_match_source"
                | "action"
                | "method"
                | "no_drop"
                | "network"
                | "protocol"
                | "inbound"
                | "outbound"
                | "inbounds"
                | "outbounds"
                | "endpoints"
                | "route"
                | "auto_detect_interface"
                | "default_interface"
                | "default_mark"
                | "default_domain_resolver"
                | "default_network_strategy"
                | "interface_name"
                | "listen"
                | "listen_port"
                | "sniff"
                | "sniff_override_destination"
                | "stack"
                | "mtu"
                | "auto_route"
                | "strict_route"
                | "auto_redirect"
                | "route_address"
                | "route_exclude_address"
                | "include_interface"
                | "exclude_interface"
                | "include_android_user"
                | "dns_mode"
                | "mode"
                | "local"
                | "shared"
                | "interface"
                | "cgroup_path"
                | "enabled"
                | "udp_timeout"
                | "endpoint_independent_nat"
                | "domain"
                | "domain_suffix"
                | "domain_keyword"
                | "domain_regex"
                | "geosite"
                | "geoip"
                | "ip_cidr"
                | "ip_is_private"
                | "ip_version"
                | "source_ip_cidr"
                | "source_port"
                | "port_range"
                | "source_port_range"
                | "invert"
                | "query_type"
                | "strategy"
                | "domain_strategy"
                | "disable_cache"
                | "disable_expire"
                | "independent_cache"
                | "client_subnet"
                | "default"
                | "url"
                | "interval"
                | "tolerance"
                | "idle_timeout"
                | "interrupt_exist_connections"
                | "format"
                | "path"
                | "update_interval"
                | "tls"
                | "insecure"
                | "server_name"
                | "alpn"
                | "min_version"
                | "max_version"
                | "utls"
                | "fingerprint"
                | "reality"
                | "short_id"
                | "multiplex"
                | "padding"
                | "max_connections"
                | "min_streams"
                | "max_streams"
                | "transport"
                | "service_name"
                | "congestion_control"
                | "up_mbps"
                | "down_mbps"
                | "heartbeat"
                | "obfs"
                | "encryption"
                | "flow"
                | "packet_encoding"
                | "udp_fragment"
                | "bind_interface"
                | "routing_mark"
                | "connect_timeout"
                | "tcp_fast_open"
                | "tcp_multi_path"
                | "experimental"
                | "clash_api"
                | "external_controller"
                | "external_ui"
                | "default_mode"
                | "cache_file"
                | "store_fakeip"
                | "store_rdrc"
                | "system_interface"
                | "state_directory"
                | "accept_routes"
                | "exit_node"
                | "exit_node_allow_lan_access"
        )
}

fn public_value(value: &str) -> bool {
    super::SUPPORT_CHAIN_TAGS.contains(&value)
        || matches!(
            value,
            "tun"
                | "ebpf"
                | "mixed"
                | "socks"
                | "http"
                | "direct"
                | "block"
                | "dns"
                | "selector"
                | "urltest"
                | "vless"
                | "vmess"
                | "trojan"
                | "shadowsocks"
                | "hysteria2"
                | "tuic"
                | "anytls"
                | "wireguard"
                | "tailscale"
                | "tcp"
                | "udp"
                | "tcp,udp"
                | "local"
                | "shared"
                | "tun-in"
                | "mixed-in"
                | "dns-in"
                | "magicnet0"
                | "lo"
                | "wlan0"
                | "rmnet_data0"
                | "eth0"
                | "off"
                | "auto"
                | "system"
                | "gvisor"
                | "ipv4_only"
                | "ipv6_only"
                | "prefer_ipv4"
                | "prefer_ipv6"
                | "reject"
                | "route"
                | "sniff"
                | "resolve"
                | "hijack-dns"
                | "route-options"
                | "rule"
                | "global"
                | "and"
                | "or"
                | "logical"
                | "remote"
                | "binary"
                | "source"
                | "debug"
                | "info"
                | "warn"
                | "error"
                | "fatal"
                | "panic"
                | "trace"
                | "silent"
                | "aes-128-gcm"
                | "aes-256-gcm"
                | "chacha20-ietf-poly1305"
                | "quic"
                | "grpc"
                | "ws"
                | "httpupgrade"
                | "http2"
                | "h2"
                | "h3"
                | "http/1.1"
                | "dot"
                | "doh"
                | "tls"
                | "https"
                | "fakeip"
                | "rcode"
                | "success"
                | "refused"
                | "127.0.0.1"
                | "::1"
                | "0.0.0.0"
                | "::"
                | "google.com"
                | "www.google.com"
                | "connectivitycheck.gstatic.com"
        )
}

fn strip_controls(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut escape = false;
    for character in text.chars() {
        if character == '\u{1b}' {
            escape = true;
            continue;
        }
        if escape {
            if character.is_ascii_alphabetic() {
                escape = false;
            }
        } else if !character.is_control() || character == '\t' {
            result.push(character);
        }
    }
    result
}

#[cfg(test)]
#[path = "../tests/internal/diagnostic_export.rs"]
mod tests;
