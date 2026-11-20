import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
const app = readFileSync(new URL("./src/App.vue", import.meta.url), "utf8");
const css = readFileSync(new URL("./src/styles.css", import.meta.url), "utf8");

test("run-page layout is scoped and short viewports retain scrolling menus", () => {
  assert.match(app, /class="page-surface" :data-page="activeTab"/);
  const control = readFileSync(
    new URL("./src/components/pages/ControlPage.vue", import.meta.url),
    "utf8",
  );
  assert.match(
    control,
    /<style scoped>[\s\S]*\.mn-control/,
    "run-page styling stays local to its component",
  );
  assert.match(
    css,
    /\.mn-utility-sheet\s*\{[^}]*max-height:[^}]*100%[^}]*overflow-y: auto/s,
  );
  assert.match(app, /v-if="showUtilityMenu" class="mn-sheet-layer" :style="viewportStyle"/);
});
