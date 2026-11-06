import assert from "node:assert/strict";
import { buildDnsProfilePlan, formatDnsProfilePlanReport } from "./src/components/pages/dnsProfilePlan.ts";

const plan = buildDnsProfilePlan("cloudflare-udp", "default");
assert.equal(plan.profile, "default");
assert.equal(plan.primary, "doh-cloudflare");
assert.equal(plan.transport, "default");
assert.equal(plan.restart, true);
assert.match(formatDnsProfilePlanReport(plan), /primary=doh-cloudflare/);
for (const [profile, transport] of [["udp", "udp"], ["dot", "dot"], ["doh", "doh"]]) {
  const explicit = buildDnsProfilePlan("default", profile);
  assert.equal(explicit.transport, transport);
  assert.ok(explicit.secondary);
}
