//! Host-side observations use temporary files and read-only kernel command
//! doubles. No fixture changes host interfaces, routes or firewall rules.
#![cfg(all(unix, not(target_os = "android")))]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

const CONFIG: &str = ".config/sing-box/config.json";
const INVENTORY: &str = ".state/hotspot/tun-rules.list";
const OWNER: &str = ".state/hotspot/tether-offload.previous";
const CANARY: &str = "HOTSPOT-PRIVATE-CANARY";
const DEFAULT_ROUTES: &str = include_str!("fixtures/tun_default_routes_ipv4.txt");
const RULES: &str =
    "8999: from all iif wlan1 lookup 2022\n8998: from all to 172.20.0.2 lookup main\n";
const FORWARD: &str = "-A FORWARD -i wlan1 -o magicnet0 -m comment --comment magicnet-hotspot -j ACCEPT\n-A FORWARD -i magicnet0 -o wlan1 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment magicnet-hotspot -j ACCEPT\n";

fn config() -> Value {
    json!({
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "interface_name": "magicnet0",
            "address": ["172.20.0.1/30"],
            "auto_route": true, "auto_redirect": true, "strict_route": true
        }],
        "experimental": {"clash_api": {
            "external_controller": "127.0.0.1:1", "secret": CANARY
        }},
        "outbounds": [{"type": "direct", "tag": CANARY}]
    })
}

fn excluded_config() -> Value {
    let mut value = config();
    value["inbounds"][0]["route_exclude_address"] = json!([
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "fd7a:115c:a1e0::/48"
    ]);
    value
}

struct Fixture(PathBuf);

impl Fixture {
    fn new(value: Option<&Value>, routes: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "magicnet-hotspot-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create unique fixture");
        let fixture = Self(root);
        for directory in [
            "bin",
            ".fixture",
            ".config/sing-box",
            ".config/magicnet",
            ".state/hotspot",
        ] {
            fs::create_dir_all(fixture.0.join(directory)).unwrap();
        }
        if let Some(value) = value {
            fixture.write(CONFIG, &value.to_string());
        }
        fixture.write(
            ".config/magicnet/transparent-mode.conf",
            "MAGICNET_TRANSPARENT_MODE=tun\n",
        );
        fixture.write(
            ".config/magicnet/selector-selections.json",
            &json!({"hotspot": "proxy", "proxy": CANARY}).to_string(),
        );
        fixture.write(
            ".config/sing-box/subscription.url",
            &format!("https://invalid.example/subscription?token={CANARY}\n"),
        );
        fixture.write(OWNER, "value=0\n");
        fixture.write(INVENTORY, "8999|wlan1\nreturn4|8998|172.20.0.2/32\n");
        fixture.write(".fixture/routes", routes);
        fixture.write(".fixture/rules", RULES);
        fixture.write(".fixture/forward", FORWARD);
        fixture.write(
            ".fixture/selected",
            "172.20.0.2 from 172.20.0.1 dev magicnet0 uid 0\n    cache\n",
        );
        fixture.executable(
            "ip",
            r#"#!/bin/sh
emit() {
    while IFS= read -r line || [ -n "$line" ]; do
        printf '%s\n' "$line"
    done < "$MODDIR/.fixture/$1"
}
printf 'ip' >> "$MODDIR/.fixture/reads.log"
printf ' <%s>' "$@" >> "$MODDIR/.fixture/reads.log"
printf '\n' >> "$MODDIR/.fixture/reads.log"
case "$*" in
    '-4 rule show') emit rules ;;
    '-4 route show table 2022'|'-4 route show table  2022')
        if [ -f "$MODDIR/.fixture/fail-routes" ]; then
            printf 'HOTSPOT-PRIVATE-CANARY kernel query failed\n' >&2
            exit 2
        fi
        emit routes ;;
    '-4 -o addr show dev magicnet0')
        printf '7: magicnet0 inet 172.20.0.1/30 scope global magicnet0\n' ;;
    '-4 route show table main dev magicnet0 scope link')
        printf '172.20.0.0/30 proto kernel src 172.20.0.1\n' ;;
    '-4 route get 172.20.0.2 from 172.20.0.1 uid 0') emit selected ;;
    *)
        printf 'ip: %s\n' "$*" >> "$MODDIR/.fixture/unexpected.log"
        exit 90 ;;
esac
"#,
        );
        fixture.executable(
            "iptables",
            r#"#!/bin/sh
printf 'iptables <%s>\n' "$*" >> "$MODDIR/.fixture/reads.log"
if [ "$#" -eq 2 ] && [ "$1" = '-S' ] && [ "$2" = FORWARD ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        printf '%s\n' "$line"
    done < "$MODDIR/.fixture/forward"
else
    printf 'iptables: %s\n' "$*" >> "$MODDIR/.fixture/unexpected.log"
    exit 90
fi
"#,
        );
        // Reconciliation also observes processes; pidof's "not found" exit is 1.
        fixture.executable("pidof", "#!/bin/sh\nexit 1\n");
        fixture
    }

    fn write(&self, path: &str, value: &str) {
        fs::write(self.0.join(path), value).unwrap();
    }

    fn executable(&self, name: &str, script: &str) {
        let path = self.0.join("bin").join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        // Private PATH prevents fallback to the host's network management tools.
        Command::new(env!("CARGO_BIN_EXE_magicnet-cli"))
            .env_clear()
            .env("MODDIR", &self.0)
            .env("MAGICNET_API", "http://127.0.0.1:1")
            .env("PATH", self.0.join("bin"))
            .args(args)
            .output()
            .expect("run CLI observer")
    }

    fn assert_state(&self, expected: &str) {
        let before = self.snapshot("");
        let protected = (self.snapshot(".config"), self.snapshot(".state/hotspot"));
        let output = self.run(&["--json", "hotspot", "status"]);
        assert!(
            output.status.success(),
            "status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.assert_no_unexpected_command();
        assert_eq!(self.snapshot(""), before, "read-only status changed files");
        assert_private(&output.stdout);
        assert_private(&output.stderr);
        let envelope: Value = serde_json::from_slice(&output.stdout)
            .expect("stdout must contain exactly one JSON response");
        assert_eq!(envelope["schema"], 1);
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["command"], "hotspot.status");
        assert_eq!(envelope["data"]["configured"]["enabled"], true);
        assert_eq!(envelope["data"]["configured"]["outbound"], "proxy");
        assert_eq!(
            envelope["data"]["effective"]["route_state"], expected,
            "machine response: {envelope}"
        );
        assert_eq!(envelope["data"]["effective"]["offload_owned"], true);
        assert_eq!(envelope["data"]["effective"]["tun_rule_count"], 1);

        let output = self.run(&["state", "reconcile"]);
        assert!(
            output.status.success(),
            "reconcile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.assert_no_unexpected_command();
        assert_private(&output.stdout);
        assert_private(&output.stderr);
        assert_eq!(
            (self.snapshot(".config"), self.snapshot(".state/hotspot")),
            protected,
            "reconciliation changed intent or recovery ownership"
        );
        let canonical = fs::read(self.0.join(".state/machines/hotspot.state")).unwrap();
        assert_private(&canonical);
        let canonical = String::from_utf8(canonical).unwrap();
        assert!(canonical.lines().any(|line| line == "schema=1"));
        assert!(canonical.lines().any(|line| line == "domain=hotspot"));
        assert!(
            canonical
                .lines()
                .any(|line| line == format!("state={expected}")),
            "canonical disagrees with machine status: {canonical}"
        );
        assert!(canonical.lines().any(|line| line == "offload_owned=1"));
        assert!(canonical.lines().any(|line| line == "tun_rule_count=1"));
    }

    fn assert_no_unexpected_command(&self) {
        let path = self.0.join(".fixture/unexpected.log");
        assert!(
            !path.exists(),
            "unexpected kernel command: {}",
            fs::read_to_string(path).unwrap_or_default()
        );
    }

    fn snapshot(&self, path: &str) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_owned();
                if matches!(
                    relative.to_str(),
                    Some(".fixture/reads.log" | ".fixture/unexpected.log")
                ) {
                    continue;
                }
                if entry.file_type().unwrap().is_dir() {
                    entries.insert(relative, None);
                    visit(root, &path, entries);
                } else {
                    entries.insert(relative, Some(fs::read(path).unwrap()));
                }
            }
        }
        let mut entries = BTreeMap::new();
        visit(&self.0, &self.0.join(path), &mut entries);
        entries
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn assert_private(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for value in [CANARY, "invalid.example", "wlan1", "172.20.0.2"] {
        assert!(!text.contains(value), "observer disclosed {value}: {text}");
    }
}

#[test]
fn fragmented_fib_respects_the_effective_private_address_exclusions() {
    Fixture::new(Some(&excluded_config()), DEFAULT_ROUTES).assert_state("active");
}

#[test]
fn known_missing_required_routes_remain_pending() {
    let missing = DEFAULT_ROUTES
        .lines()
        .filter(|line| !line.starts_with("11.0.0.0/8 "))
        .collect::<Vec<_>>()
        .join("\n");
    Fixture::new(Some(&excluded_config()), &missing).assert_state("pending");
    for routes in ["", "0.0.0.0/1 dev magicnet0 scope link\n"] {
        Fixture::new(Some(&config()), routes).assert_state("pending");
    }
}

#[test]
fn matching_conditionals_are_unknown_without_claiming_full_forwarding() {
    for selector in [
        "tos 0x10",
        "dsfield 16",
        "tos lowdelay",
        "tos invalid",
        "tos",
        "from 192.0.2.0/24",
        "nexthop via 192.0.2.1",
    ] {
        let routes = format!("default dev magicnet0 {selector}\n");
        Fixture::new(Some(&config()), &routes).assert_state("unknown");
    }
}

#[test]
fn zero_selectors_and_split_default_routes_preserve_healthy_controls() {
    for routes in [
        "default dev magicnet0 tos 0\n",
        "default dev magicnet0 dsfield 0x00\n",
        "0.0.0.0/1 dev magicnet0\n128.0.0.0/1 dev magicnet0\n",
    ] {
        Fixture::new(Some(&config()), routes).assert_state("active");
    }
}

#[test]
fn required_conflicts_stay_unknown_and_linkdown_stays_pending() {
    for competitor in [
        "blackhole 198.51.100.0/24",
        "198.51.100.0/24 dev wlan9",
        "default dev wlan9 metric 20",
    ] {
        let routes = format!("default dev magicnet0\n{competitor}\n");
        Fixture::new(Some(&config()), &routes).assert_state("unknown");
    }
    Fixture::new(Some(&config()), "default dev magicnet0 linkdown\n").assert_state("pending");
}

#[test]
fn irrelevant_conditional_routes_do_not_hide_valid_or_missing_coverage() {
    let irrelevant = "10.0.0.0/8 dev magicnet0 tos 0x10\n";
    Fixture::new(
        Some(&excluded_config()),
        &format!("{DEFAULT_ROUTES}{irrelevant}"),
    )
    .assert_state("active");

    let missing = DEFAULT_ROUTES
        .lines()
        .filter(|line| !line.starts_with("11.0.0.0/8 "))
        .collect::<Vec<_>>()
        .join("\n");
    Fixture::new(
        Some(&excluded_config()),
        &format!("{missing}\n{irrelevant}"),
    )
    .assert_state("pending");
}

#[test]
fn absent_ambiguous_or_invalid_effective_configuration_stays_unknown() {
    Fixture::new(None, "default dev magicnet0\n").assert_state("unknown");
    let malformed = Fixture::new(Some(&config()), "default dev magicnet0\n");
    malformed.write(CONFIG, &format!("invalid-json-{CANARY}"));
    malformed.assert_state("unknown");

    let mut duplicate = config();
    let inbound = duplicate["inbounds"][0].clone();
    duplicate["inbounds"].as_array_mut().unwrap().push(inbound);
    let mut invalid_ranges = config();
    invalid_ranges["inbounds"][0]["route_address"] = json!(["not-a-prefix"]);
    let mut dynamic_ranges = config();
    dynamic_ranges["inbounds"][0]["auto_redirect"] = json!(false);
    dynamic_ranges["inbounds"][0]["route_address_set"] = json!([CANARY]);
    let mut foreign_table = config();
    foreign_table["inbounds"][0]["iproute2_table_index"] = json!(2023);
    let mut foreign_interface = config();
    foreign_interface["inbounds"][0]["interface_name"] = json!("other0");
    let mut not_tun = config();
    not_tun["inbounds"][0]["type"] = json!("ebpf");
    for value in [
        json!({}),
        duplicate,
        invalid_ranges,
        dynamic_ranges,
        foreign_table,
        foreign_interface,
        not_tun,
    ] {
        Fixture::new(Some(&value), "default dev magicnet0\n").assert_state("unknown");
    }
}

#[test]
fn missing_forwarding_or_return_evidence_cannot_be_masked_by_a_route() {
    let missing_rule = Fixture::new(Some(&config()), "default dev magicnet0 tos 0x10\n");
    missing_rule.write(
        ".fixture/rules",
        "8998: from all to 172.20.0.2 lookup main\n",
    );
    missing_rule.assert_state("pending");

    let missing_forward = Fixture::new(Some(&config()), "default dev magicnet0\n");
    missing_forward.write(".fixture/forward", "");
    missing_forward.assert_state("pending");

    let wrong_return = Fixture::new(Some(&config()), "default dev magicnet0\n");
    wrong_return.write(
        ".fixture/selected",
        "172.20.0.2 from 172.20.0.1 via 192.0.2.1 dev wlan0 uid 0\n",
    );
    wrong_return.assert_state("pending");
}

#[test]
fn failed_kernel_observation_is_unknown_and_diagnostics_are_private() {
    let fixture = Fixture::new(Some(&config()), "default dev magicnet0\n");
    fixture.write(".fixture/fail-routes", "1\n");
    fixture.assert_state("unknown");
}
