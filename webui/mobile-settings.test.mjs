import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { runInNewContext } from "node:vm";
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

test("switching workspace keeps its destination and tapping the current one opens its pages", () => {
  const selected = [];
  const scope = {
    setTab: (tab) => selected.push(tab),
    activeWorkspace: { value: { key: "other" } },
    mobilePagesTrigger: { value: null },
    showMobilePages: { value: false },
    HTMLElement: class HTMLElement {},
    lastTabByWorkspace: {
      value: {
        configure: "config",
        run: "about",
        route: "chain",
        diagnose: "output",
      },
    },
  };
  const source = app
    .match(
      /function setWorkspace\([^)]*\): void \{[\s\S]*?\n\}/,
    )[0]
    .replace(": WorkspaceKey", "")
    .replace(": MouseEvent", "")
    .replace(": void", "");
  runInNewContext(source, scope);
  for (const workspace of ["configure", "run", "route", "diagnose"])
    scope.setWorkspace(workspace);
  assert.deepEqual(selected, ["subs", "about", "chain", "output"]);
  const trigger = new scope.HTMLElement();
  scope.activeWorkspace.value.key = "route";
  scope.setWorkspace("route", { currentTarget: trigger });
  assert.equal(scope.showMobilePages.value, true);
  assert.equal(scope.mobilePagesTrigger.value, trigger);
  assert.deepEqual(selected, ["subs", "about", "chain", "output"]);
});
