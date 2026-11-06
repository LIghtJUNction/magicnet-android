use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("magicnet-export-{}-{stamp}", std::process::id()));
        for directory in [
            ".config/sing-box",
            ".config/magicnet",
            ".state/machines",
            ".log",
            "bin",
            "licenses/curl",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(
            root.join("module.prop"),
            "id=MagicNet\nversion=v1.8.5\nversionCode=10805\n",
        )
        .unwrap();
        fs::write(root.join(".config/sing-box/config.json"), r#"{
            "inbounds":[{"type":"tun","tag":"tun-in","mtu":1400,"exclude_uid":[0,10112]}],
            "outbounds":[{"type":"vless","tag":"PRIVATE-NODE-CANARY","server":"hidden.invalid","password":"PASSWORD-CANARY"}],
            "route":{"final":"PRIVATE-NODE-CANARY"}
        }"#).unwrap();
        fs::write(
            root.join(".config/magicnet/dns.conf"),
            "MAGICNET_DNS_PROFILE=cloudflare-doh\n",
        )
        .unwrap();
        fs::write(root.join(".config/magicnet/mcp.conf"), "MAGICNET_MCP_ENABLED=0\nMAGICNET_MCP_BIND=127.0.0.1\nMAGICNET_MCP_PORT=8766\nMAGICNET_MCP_SECRET=MCP-SECRET-CANARY\n").unwrap();
        fs::write(
            root.join(".state/machines/service.state"),
            "schema=1\ndomain=service\nstate=stale\n",
        )
        .unwrap();
        fs::write(root.join(".state/machines/connectivity.state"), "schema=1\ndomain=connectivity\nphase=offline\nreason=dns_failure\nboot=PRIVATE-BOOT-CANARY\n").unwrap();
        fs::write(root.join(".log/sing-box.log"), "ERROR outbound/vless[PRIVATE-NODE-CANARY] dial hidden.invalid failed password=PASSWORD-CANARY\nERROR Authorization: Bearer PRIVATE-HEADER-CANARY extra-secret\n").unwrap();
        fs::write(root.join(".log/supervisors.log"), "ERROR magicnet_supervisors_start: timed out after 180000ms\nERROR Authorization: Bearer SUPERVISOR-SECRET-CANARY\n").unwrap();
        fs::write(
            root.join(".log/connectivity-watchdog.log"),
            "ERROR watchdog: worker failed to enter loop\n",
        )
        .unwrap();
        let core = root.join("bin/sing-box");
        fs::write(&core, "#!/bin/sh\ncase \"$1\" in version) echo 'sing-box version simulated' ;; check) echo 'ERROR configuration invalid password=PASSWORD-CANARY' >&2; exit 2 ;; *) exit 1 ;; esac\n").unwrap();
        fs::set_permissions(core, fs::Permissions::from_mode(0o755)).unwrap();
        let curl = root.join("bin/curl");
        fs::write(&curl, r#"#!/bin/sh
case "$*" in
  '-q --version')
    printf '%s\n' 'curl 8.22.0 (aarch64-unknown-linux-android) libcurl/8.22.0 OpenSSL/3.5.8 zlib/1.3.2' 'Protocols: http https' 'Features: SSL libz IPv6'
    ;;
  *https://*) : >"${0%/bin/curl}/unexpected-network-request"; exit 95 ;;
  *) exit 7 ;;
esac
"#).unwrap();
        fs::set_permissions(curl, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(root.join("licenses/curl/build-provenance.json"), serde_json::json!({
            "schema":1, "scope":"production-android-curl",
            "target":{"os":"android", "abi":"arm64-v8a", "api":21},
            "versions":{"curl":"8.22.0", "openssl":"3.5.8", "zlib":"1.3.2"},
            "ca":{"mode":"embedded", "version":"2026-09-25", "sha256":"a".repeat(64),
                "bytes":188900, "cert_count":121, "runtime_bundle":false, "system_store":false},
            "curl_sha256":"b".repeat(64), "curl_bytes":4000000,
            "sources":{"curl":{"url":"https://private.invalid/?token=CURL-SOURCE-SECRET-CANARY"}},
            "PRIVATE-CURL-BUILD-KEY":"CURL-BUILD-SECRET-CANARY", "runtime_capability":"not_tested"
        }).to_string()).unwrap();
        Self(root)
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_magicnet-cli"))
            .args(args)
            .env("MODDIR", &self.0)
            .env("MAGICNET_API", "http://127.0.0.1:1")
            .output()
            .unwrap()
    }

    fn canonical_snapshot(&self) -> Vec<(PathBuf, Vec<u8>, u64, SystemTime)> {
        let mut snapshot = fs::read_dir(self.0.join(".state/machines"))
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let metadata = fs::metadata(&path).unwrap();
                (
                    path.clone(),
                    fs::read(path).unwrap(),
                    metadata.ino(),
                    metadata.modified().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        snapshot
    }
}

fn section<'a>(report: &'a str, title: &str) -> &'a str {
    report
        .split_once(&format!("\n[{title}]\n"))
        .unwrap_or_else(|| panic!("missing {title}"))
        .1
        .split("\n[")
        .next()
        .unwrap()
        .trim()
}

fn machine_capture(text: &str) -> serde_json::Value {
    let (status, payload) = text.split_once('\n').expect("capture metadata and JSON");
    assert!(status.starts_with("status=ok "), "{status}");
    serde_json::Deserializer::from_str(payload)
        .into_iter::<serde_json::Value>()
        .next()
        .expect("one machine JSON value")
        .expect("valid diagnostic machine JSON")
}

fn assert_status_evidence(fixture: &Fixture, report: &str) {
    let service = machine_capture(section(report, "service status"));
    let expected: serde_json::Value =
        serde_json::from_slice(&fixture.run(&["--json", "service", "status"]).stdout).unwrap();
    for key in ["schema", "ok", "command"] {
        assert_eq!(service[key], expected[key], "service envelope {key}");
    }
    for key in [
        "core",
        "lifecycle",
        "readiness",
        "supervisors",
        "transparent",
        "subscription",
        "connectivity",
    ] {
        assert_eq!(
            service["data"][key], expected["data"][key],
            "service data {key}"
        );
    }
    assert_eq!(
        service["data"]["api"]["ready"],
        expected["data"]["api"]["ready"]
    );
    assert!(service["data"]["api"].get("url").is_some());
    assert_ne!(
        service["data"]["api"]["url"],
        expected["data"]["api"]["url"]
    );

    let transparent = machine_capture(section(report, "transparent TUN and eBPF observation"));
    let expected: serde_json::Value =
        serde_json::from_slice(&fixture.run(&["--json", "transparent", "status"]).stdout).unwrap();
    assert_eq!(transparent, expected);

    let combined = section(report, "dns api and mcp");
    let (dns, mcp) = combined
        .strip_prefix("--- dns ---\n")
        .unwrap()
        .split_once("\n--- mcp ---\n")
        .unwrap();
    let dns = machine_capture(dns);
    assert_eq!(dns["schema"], 1);
    assert_eq!(dns["ok"], true);
    assert_eq!(dns["command"], "dns.status");
    assert_eq!(dns["data"]["profile"], "cloudflare-doh");
    assert_eq!(dns["data"]["transport"], "doh");
    assert!(dns["data"].get("primary").is_some());
    assert!(dns["data"].get("secondary").is_some());
    assert!(!dns.to_string().contains("https://"));
    assert!(mcp.starts_with("status=ok "), "{mcp}");
    for field in ["enabled=0", "port=8766", "secret_set=1", "pid=stopped"] {
        assert!(
            mcp.lines().any(|line| line == field),
            "missing {field}: {mcp}"
        );
    }
    assert!(!mcp.contains("unsupported"));
    assert!(!report.contains("MCP-SECRET-CANARY"));

    let curl = section(report, "curl executor");
    assert!(curl.starts_with("selection=module_bin available=true\nnetwork_request=not_run\n"));
    let (version, build) = curl.split_once("\n--- build provenance ---\n").unwrap();
    let version = machine_capture(version.split_once("--- version ---\n").unwrap().1);
    assert_eq!(version["curl_version"], "8.22.0");
    assert_eq!(version["tls_version"], "3.5.8");
    assert_eq!(
        version["capabilities"],
        serde_json::json!({"https":true,"tls":true,"gzip":true})
    );
    let build: serde_json::Value = serde_json::from_str(build).unwrap();
    assert_eq!(build["status"], "available");
    assert_eq!(build["ca"]["mode"], "embedded");
    assert_eq!(build["ca"]["bytes"], 188900);
    assert_eq!(build["runtime_capability"], "not_tested");
    assert_eq!(build["binary_digest_verification"], "not_run");
    assert!(!report.contains("CURL-SOURCE-SECRET-CANARY"));
    assert!(!report.contains("CURL-BUILD-SECRET-CANARY"));
    assert!(!report.contains("PRIVATE-CURL-BUILD-KEY"));
    assert!(!fixture.0.join("unexpected-network-request").exists());
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn machine_export_creates_one_complete_file_and_keeps_service_state_unchanged() {
    let fixture = Fixture::new();
    let before = fixture.canonical_snapshot();
    let started = Instant::now();
    let output = fixture.run(&["--json", "support", "export"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema"], 1);
    assert_eq!(envelope["command"], "support.export");
    assert_eq!(envelope["ok"], true);
    let path = PathBuf::from(envelope["data"]["path"].as_str().unwrap());
    assert_eq!(
        path,
        fixture
            .0
            .join(".state/diagnostics/MagicNet-diagnostics.txt")
    );
    let report = fs::read_to_string(&path).unwrap();
    assert_status_evidence(&fixture, &report);
    assert_eq!(
        fixture.canonical_snapshot(),
        before,
        "canonical bytes, inode and mtime must stay unchanged"
    );
    assert_eq!(
        envelope["data"]["bytes"].as_u64().unwrap(),
        report.len() as u64
    );
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for heading in [
        "platform and versions",
        "system resources",
        "subscription lifecycle",
        "configuration: route",
        "configuration: inbounds",
        "connectivity history",
        "curl executor",
        "core resources",
        "health",
        "sing-box configuration check",
        "routes: ipv4 rules",
        "routes: ipv6 routes",
        "firewall: iptables-save",
        "transparent TUN and eBPF observation",
        "recent logs: sing-box",
        "recent logs: supervisors",
        "recent logs: connectivity-watchdog",
        "collection summary",
    ] {
        assert!(
            report.contains(&format!("[{heading}]")),
            "missing {heading}"
        );
    }
    for private in [
        "PRIVATE-NODE-CANARY",
        "PASSWORD-CANARY",
        "hidden.invalid",
        "PRIVATE-HEADER-CANARY",
        "extra-secret",
        "PRIVATE-BOOT-CANARY",
        "SUPERVISOR-SECRET-CANARY",
        "10112",
    ] {
        assert!(!report.contains(private), "leaked {private}");
    }
    assert!(report.contains("exit_code=2"));
    assert!(report.contains("timed out after 180000ms"));
    assert!(report.contains("worker failed to enter loop"));
    assert!(report.contains("external_network_probes=not_run"));
    assert!(report.ends_with("end_of_report=true\n"));
    assert!(report.len() <= 512 * 1024);
    assert!(started.elapsed().as_secs() < 35);
    assert_eq!(
        fs::read_to_string(fixture.0.join(".state/machines/service.state")).unwrap(),
        "schema=1\ndomain=service\nstate=stale\n"
    );
    assert_eq!(
        fs::read_dir(fixture.0.join(".state/machines"))
            .unwrap()
            .count(),
        2
    );
    assert_eq!(
        fs::read_dir(fixture.0.join(".state/diagnostics"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn bundle_observation_never_creates_an_export_or_reconciles_canonical_state() {
    let fixture = Fixture::new();
    let before = fixture.canonical_snapshot();
    let state_modified = fs::metadata(fixture.0.join(".state"))
        .unwrap()
        .modified()
        .unwrap();
    let output = fixture.run(&["support", "bundle"]);
    assert!(output.status.success());
    assert_status_evidence(&fixture, &String::from_utf8_lossy(&output.stdout));
    assert_eq!(fixture.canonical_snapshot(), before);
    assert_eq!(
        fs::metadata(fixture.0.join(".state"))
            .unwrap()
            .modified()
            .unwrap(),
        state_modified
    );
    assert!(!fixture.0.join(".state/diagnostics").exists());
    assert_eq!(
        fs::read_dir(fixture.0.join(".state/machines"))
            .unwrap()
            .count(),
        2
    );
    assert_eq!(
        fs::read_to_string(fixture.0.join(".state/machines/service.state")).unwrap(),
        "schema=1\ndomain=service\nstate=stale\n"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("end_of_report=true"));
}

#[test]
fn machine_export_failure_returns_one_complete_redacted_error_envelope() {
    let fixture = Fixture::new();
    let blocked_directory = fixture.0.join(".state/diagnostics");
    fs::write(&blocked_directory, "EXPORT-BLOCKER-PASSWORD-CANARY").unwrap();

    let output = fixture.run(&["--json", "support", "export"]);
    assert!(!output.status.success());
    // from_slice also rejects a banner or a second JSON value on stdout.
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        envelope,
        serde_json::json!({
            "schema": 1,
            "ok": false,
            "command": "machine.error",
            "error": {
                "code": "support.export_failed",
                "message": "unable to export the diagnostic file"
            }
        })
    );
    assert!(envelope.get("data").is_none());
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        for private in [
            "EXPORT-BLOCKER-PASSWORD-CANARY",
            "PRIVATE-NODE-CANARY",
            "PASSWORD-CANARY",
            "hidden.invalid",
            "PRIVATE-HEADER-CANARY",
            "extra-secret",
            "PRIVATE-BOOT-CANARY",
        ] {
            assert!(!text.contains(private), "leaked {private}");
        }
    }
    assert_eq!(
        fs::read_to_string(&blocked_directory).unwrap(),
        "EXPORT-BLOCKER-PASSWORD-CANARY"
    );
    assert_eq!(
        fs::read_to_string(fixture.0.join(".state/machines/service.state")).unwrap(),
        "schema=1\ndomain=service\nstate=stale\n"
    );
    assert_eq!(
        fs::read_dir(fixture.0.join(".state/machines"))
            .unwrap()
            .count(),
        2
    );
}
