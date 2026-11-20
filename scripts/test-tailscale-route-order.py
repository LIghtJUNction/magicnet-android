#!/usr/bin/env python3
"""Run the real Tailscale, app and domain-policy materializers together.

Only Android package-to-UID lookup is stubbed. This proves configuration
ordering/idempotence, not live tailnet connectivity or Android acceptance.
"""
import copy
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "src/MagicNet/lib/magicnet"
TAILNETS = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
SHELLS = [("sh", [shutil.which("sh")])]
if shutil.which("busybox"):
    SHELLS.append(("ash", [shutil.which("busybox"), "ash"]))
T = "magicnet_tailscale_apply_unlocked"
A = "magicnet_singbox_apply_app_policy"
R = "magicnet_route_apply_singbox"
B = "magicnet_block_apply_singbox"
APP_MARKERS = {"__magicnet_app_direct__", "__magicnet_app_proxy__"}
DOMAIN_MARKERS = {"__magicnet_route__", "__magicnet_ad_allow__", "__magicnet_block__"}


def managed(rule):
    return bool(APP_MARKERS.intersection(rule.get("package_name", []))
                or DOMAIN_MARKERS.intersection(rule.get("domain_suffix", []) + rule.get("domain", [])))


class TailscaleRouteOrder(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="magicnet-tailnet-")
        self.addCleanup(self.temp.cleanup)
        self.module = Path(self.temp.name) / "module with spaces"
        (self.module / "bin").mkdir(parents=True)
        jq = shutil.which("jq")
        if jq is None:
            self.fail("missing required test tool: jq")
        (self.module / "bin/jq").symlink_to(jq)
        self.config = self.module / ".config/sing-box/config.json"
        self.config.parent.mkdir(parents=True)
        self.policy = self.module / ".config/magicnet"
        self.policy.mkdir()
        self.base = {
            "inbounds": [{"type": "tun", "tag": "tun-in",
                          "route_exclude_address": [*TAILNETS, "192.168.0.0/16"]}],
            "outbounds": [{"type": "direct", "tag": "direct"},
                          {"type": "selector", "tag": "lan", "outbounds": ["direct"]},
                          {"type": "selector", "tag": "proxy", "outbounds": ["direct"]}],
            "dns": {"servers": [{"type": "local", "tag": "local"}], "rules": []},
            "route": {"rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_cidr": ["10.0.0.0/8", *TAILNETS], "outbound": "lan"},
                {"domain_suffix": ["example.com"], "outbound": "proxy"},
            ]},
        }

    def reset(self, tag=None, apps=True):
        config = copy.deepcopy(self.base)
        if tag is not None:
            config["endpoints"] = [{"type": "tailscale", "tag": tag, "system_interface": False}]
        self.config.write_text(json.dumps(config), encoding="utf-8")
        for kind in ("proxy", "direct", "bypass"):
            text = f"org.example.{kind}\n" if apps and kind != "bypass" else ""
            (self.policy / f"app-{kind}.list").write_text(text, encoding="utf-8")
        return config

    def apply(self, shell, operations, mode="blacklist"):
        script = '''. "$1/primitives.sh"
. "$1/singbox_subscribe/bootstrap.sh"
. "$1/runtime_config.sh"
. "$1/apps.sh"
. "$1/routes.sh"
. "$1/blocklist.sh"
. "$1/singbox_route_rules.sh"
magicnet_conf_value() { return 1; }
magicnet_package_uids() { if [ -s "$1" ]; then printf '10123\\n'; fi; }
'''
        script += "\n".join(f"{operation} || exit $?" for operation in operations)
        result = subprocess.run(
            [*shell, "-c", script, "tailnet-test", str(LIB)],
            env={**os.environ, "MODDIR": str(self.module), "MAGICNET_APP_MODE": mode},
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(self.config.read_text())

    def assert_routes(self, config, tag):
        rules = config["route"]["rules"]
        lan = next(i for i, rule in enumerate(rules) if rule.get("outbound") == "lan")
        mesh = [(i, rule) for i, rule in enumerate(rules) if rule.get("outbound") == tag]
        self.assertEqual(len(mesh), 2)
        self.assertTrue(all(i < lan for i, _ in mesh), rules)
        self.assertTrue(all(rule.get("action") == "route" for _, rule in mesh))
        ip_rule = next(rule for _, rule in mesh if "ip_cidr" in rule)
        self.assertEqual(ip_rule["ip_cidr"], TAILNETS)
        self.assertEqual(ip_rule["preferred_by"], [tag])
        self.assertEqual(rules[lan], self.base["route"]["rules"][2])
        self.assertEqual(rules[:2], self.base["route"]["rules"][:2])
        self.assertEqual(config["inbounds"][0]["route_exclude_address"], ["192.168.0.0/16"])
        for i, rule in enumerate(rules):
            if "package_name" in rule:
                self.assertGreater(i, lan)
        dns = [server for server in config["dns"]["servers"] if server["type"] == "tailscale"]
        self.assertEqual(len(dns), 1)
        self.assertEqual(dns[0]["endpoint"], tag)

    def test_default_and_custom_tags_survive_app_reordering(self):
        for name, shell in SHELLS:
            for tag in ("tailscale", "office-mesh"):
                for mode in ("blacklist", "whitelist"):
                    with self.subTest(shell=name, tag=tag, mode=mode):
                        self.reset(tag)
                        self.assert_routes(self.apply(shell, [T, A], mode), tag)

    def test_both_materialization_orders_are_idempotent(self):
        for name, shell in SHELLS:
            for operations in ([T, A], [A, T]):
                with self.subTest(shell=name, order=operations):
                    self.reset("office-mesh")
                    first = self.apply(shell, operations)
                    second = self.apply(shell, operations)
                    self.assertEqual(first, second)
                    self.assert_routes(second, "office-mesh")
                    self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_no_endpoint_keeps_carrier_and_lan_policy(self):
        for name, shell in SHELLS:
            with self.subTest(shell=name):
                original = self.reset()
                result = self.apply(shell, [T])
                self.assertEqual(result, original)

    def test_no_app_overrides(self):
        for name, shell in SHELLS:
            with self.subTest(shell=name):
                self.reset("office-mesh", apps=False)
                self.assert_routes(self.apply(shell, [T, A]), "office-mesh")

    def test_legacy_managed_rules_are_upgraded_without_duplicates(self):
        for name, shell in SHELLS:
            with self.subTest(shell=name):
                config = self.reset("office-mesh")
                config["route"]["rules"] += [
                    {"ip_cidr": TAILNETS, "preferred_by": ["tailscale"], "outbound": "office-mesh"},
                    {"domain_suffix": ["ts.net"], "outbound": "office-mesh"},
                ]
                self.config.write_text(json.dumps(config), encoding="utf-8")
                self.assert_routes(self.apply(shell, [T, A, T, A]), "office-mesh")

    def protected_fixture(self):
        config = self.reset("office-mesh")
        config["outbounds"] += [
            {"type": "block", "tag": "block"},
            {"type": "selector", "tag": "final", "outbounds": ["proxy"]},
            {"type": "selector", "tag": "ad-block", "outbounds": ["block", "direct", "proxy"]},
        ]
        guards = [
            {"port": 53, "action": "hijack-dns"},
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"protocol": "icmp", "outbound": "block"},
            {"ip_cidr": ["0.0.0.0/8"], "outbound": "block"},
            {"domain": ["flash.sec.miui.com", "fraud-detection.engine.miui.com",
                        "eps.caict.ac.cn", "gateway-papa.cloud.weizhi.com"], "action": "reject"},
            {"domain": ["dm.wo.com.cn"], "port": 18080, "action": "reject"},
            {"clash_mode": "Direct", "outbound": "direct"},
            {"clash_mode": "Global", "outbound": "proxy"},
            {"ip_cidr": TAILNETS, "preferred_by": ["office-mesh"],
             "action": "route", "outbound": "office-mesh"},
            {"domain_suffix": ["ts.net"], "action": "route", "outbound": "office-mesh"},
            {"ip_is_private": True, "outbound": "lan"},
        ]
        # Both app directions overlap an opposite business choice. The last
        # pair also overlaps for unrelated apps, so promoting action:route
        # would change their first matching outbound from direct to proxy.
        business = [
            {"package_name": ["org.example.direct"], "domain_suffix": ["example.org"],
             "action": "route", "outbound": "proxy"},
            {"package_name": ["org.example.proxy"], "domain_suffix": ["example.org"],
             "outbound": "direct"},
            {"domain_suffix": ["example.org"], "outbound": "direct"},
            {"domain_suffix": ["example.org"], "action": "route", "outbound": "proxy"},
        ]
        config["route"]["rules"] = guards + business
        self.config.write_text(json.dumps(config), encoding="utf-8")
        return config, guards, business

    def test_app_choices_precede_explicit_and_implicit_business_routes(self):
        for name, shell in SHELLS:
            for mode in ("blacklist", "whitelist"):
                with self.subTest(shell=name, mode=mode):
                    original, guards, business = self.protected_fixture()
                    first = self.apply(shell, [A], mode)
                    self.assertEqual(first, self.apply(shell, [A], mode))
                    rules = first["route"]["rules"]
                    self.assertEqual(rules[:len(guards)], guards)
                    self.assertEqual(rules[len(guards):len(guards) + 2], [
                        {"package_name": ["__magicnet_app_direct__", "org.example.direct"],
                         "outbound": "direct"},
                        {"package_name": ["__magicnet_app_proxy__", "org.example.proxy"],
                         "outbound": "proxy"},
                    ])
                    self.assertEqual(rules[len(guards) + 2:], business)
                    self.assertEqual(first["dns"], original["dns"])
                    for kind in ("direct", "proxy"):
                        (self.policy / f"app-{kind}.list").write_text("")
                    self.assertEqual(self.apply(shell, [A], mode)["route"], original["route"])

    def test_route_families_have_stable_priority_in_every_apply_order(self):
        for name, shell in SHELLS:
            for operations in itertools.permutations((A, R, B)):
                with self.subTest(shell=name, order=operations):
                    original, guards, business = self.protected_fixture()
                    (self.policy / "route-direct-domain-suffix.list").write_text("example.org\n")
                    (self.policy / "block-domain-suffix.list").write_text("ads.example.org\n")
                    (self.policy / "block-allow-rules.list").write_text("DOMAIN-SUFFIX,allowed.example.org\n")
                    first = self.apply(shell, operations)
                    self.assertEqual(first, self.apply(shell, operations))
                    rules = first["route"]["rules"]
                    self.assertEqual(rules[:len(guards)], guards)
                    self.assertEqual([rule for rule in rules if not managed(rule)], guards + business)
                    markers = [value for rule in rules
                               for value in (rule.get("package_name", []) + rule.get("domain_suffix", [])
                                             + rule.get("domain", []))
                               if value in APP_MARKERS | DOMAIN_MARKERS]
                    self.assertEqual(markers, ["__magicnet_app_direct__", "__magicnet_app_proxy__",
                                               "__magicnet_route__", "__magicnet_ad_allow__",
                                               "__magicnet_block__"])
                    self.assertEqual(rules[len(guards) + 5:], business)
                    self.assertEqual(first["dns"], original["dns"])
                    self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_no_guard_does_not_promote_an_explicit_business_route(self):
        for name, shell in SHELLS:
            with self.subTest(shell=name):
                original, _, business = self.protected_fixture()
                original["route"]["rules"] = business
                self.config.write_text(json.dumps(original), encoding="utf-8")
                result = self.apply(shell, [A])
                self.assertEqual(result["route"]["rules"][2:], business)
                self.assertTrue(all(managed(rule) for rule in result["route"]["rules"][:2]))

    def test_nonfinal_route_preparation_precedes_managed_terminal_rules(self):
        actions = [
            {"domain_suffix": ["example.org"], "action": "resolve",
             "server": "local", "strategy": "ipv4_only"},
            {"domain_suffix": ["example.org"], "action": "route-options", "override_port": 8443},
        ]
        for preparations in ([actions[0]], [actions[1]], actions):
            for name, shell in SHELLS:
                for operations in itertools.permutations((A, R, B)):
                    with self.subTest(shell=name, order=operations, preparations=preparations):
                        original, guards, business = self.protected_fixture()
                        # A matching managed route before either preparation would
                        # terminate matching and lose the explicit DNS or port.
                        original["route"]["rules"] = guards + preparations + business
                        self.config.write_text(json.dumps(original), encoding="utf-8")
                        (self.policy / "route-direct-domain-suffix.list").write_text("example.org\n")
                        (self.policy / "block-domain-suffix.list").write_text("ads.example.org\n")
                        result = self.apply(shell, operations)
                        rules = result["route"]["rules"]
                        self.assertEqual(rules[:len(guards) + len(preparations)], guards + preparations)
                        self.assertEqual([rule for rule in rules if not managed(rule)], original["route"]["rules"])
                        self.assertEqual(rules[-len(business):], business)
                        self.assertEqual(result, self.apply(shell, operations))

    def test_tailnet_domain_guard_does_not_depend_on_a_later_lan_rule(self):
        for name, shell in SHELLS:
            for operation in (A, R, B):
                with self.subTest(shell=name, operation=operation):
                    original, guards, business = self.protected_fixture()
                    # There is no LAN or preferred_by rule to incidentally
                    # protect this custom-tag MagicDNS route.
                    guards = [rule for rule in guards
                              if rule.get("outbound") != "lan" and "preferred_by" not in rule]
                    original["route"]["rules"] = guards + business
                    self.config.write_text(json.dumps(original), encoding="utf-8")
                    (self.policy / "route-direct-domain-suffix.list").write_text("ts.net\n")
                    (self.policy / "block-domain-suffix.list").write_text("ts.net\n")
                    result = self.apply(shell, [operation])
                    self.assertEqual(result["route"]["rules"][:len(guards)], guards)
                    self.assertTrue(managed(result["route"]["rules"][len(guards)]))

    def test_domain_rules_preserve_interleaved_original_business(self):
        for name, shell in SHELLS:
            with self.subTest(shell=name):
                original, guards, business = self.protected_fixture()
                original["route"]["rules"] = guards[:2] + business[:1] + guards[2:] + business[1:]
                self.config.write_text(json.dumps(original), encoding="utf-8")
                (self.policy / "route-direct-domain-suffix.list").write_text("example.org\n")
                (self.policy / "block-domain-suffix.list").write_text("ads.example.org\n")
                result = self.apply(shell, [R, B])
                rules = result["route"]["rules"]
                self.assertEqual([rule for rule in rules if not managed(rule)], original["route"]["rules"])
                self.assertEqual(rules[:len(guards) + 1], original["route"]["rules"][:len(guards) + 1])
                self.assertTrue(managed(rules[len(guards) + 1]))
                self.assertEqual(result, self.apply(shell, [R, B]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
