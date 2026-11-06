use std::fs;
use std::os::unix::fs::PermissionsExt;
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
        for directory in [".config/sing-box", ".state/machines", ".log", "bin"] {
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
            root.join(".state/machines/service.state"),
            "schema=1\ndomain=service\nstate=stale\n",
        )
        .unwrap();
        fs::write(root.join(".state/machines/connectivity.state"), "schema=1\ndomain=connectivity\nphase=offline\nreason=dns_failure\nboot=PRIVATE-BOOT-CANARY\n").unwrap();
        fs::write(root.join(".log/sing-box.log"), "ERROR outbound/vless[PRIVATE-NODE-CANARY] dial hidden.invalid failed password=PASSWORD-CANARY\nERROR Authorization: Bearer PRIVATE-HEADER-CANARY extra-secret\n").unwrap();
        let core = root.join("bin/sing-box");
        fs::write(&core, "#!/bin/sh\ncase \"$1\" in version) echo 'sing-box version simulated' ;; check) echo 'ERROR configuration invalid password=PASSWORD-CANARY' >&2; exit 2 ;; *) exit 1 ;; esac\n").unwrap();
        fs::set_permissions(core, fs::Permissions::from_mode(0o755)).unwrap();
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn machine_export_creates_one_complete_file_and_keeps_service_state_unchanged() {
    let fixture = Fixture::new();
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
        "core resources",
        "health",
        "sing-box configuration check",
        "routes: ipv4 rules",
        "routes: ipv6 routes",
        "firewall: iptables-save",
        "transparent TUN and eBPF observation",
        "recent logs: sing-box",
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
        "10112",
    ] {
        assert!(!report.contains(private), "leaked {private}");
    }
    assert!(report.contains("exit_code=2"));
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
    let output = fixture.run(&["support", "bundle"]);
    assert!(output.status.success());
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
