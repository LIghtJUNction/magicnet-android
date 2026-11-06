import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";
import { useActionLock } from "./src/composables/useActionLock.ts";
import { decodeMachineData, machineErrorCode } from "./src/composables/machineStatus.ts";
import { parseSupportExport } from "./src/composables/connectivityStatus.ts";

// Execute the shipped Vue action; only the native command transport is replaced.
const source = ts.createSourceFile("DiagnosticsPage.ts", readFileSync(new URL(
  "./src/components/pages/DiagnosticsPage.vue", import.meta.url), "utf8")
  .split('<script setup lang="ts">')[1].split("</script>")[0], ts.ScriptTarget.Latest, true);
const action = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === "exportDiagnostics");
const code = ts.transpileModule(action.getText(source), {
  compilerOptions: { target: ts.ScriptTarget.ES2022 },
}).outputText;
const ok = (command, data) => ({ok:true,stdout:JSON.stringify({schema:1,ok:true,command,data})});
const capability = ok("machine.capabilities", {commands:["support.export"],mutation_commands:["support.export"]});
const metadata = {path:"/sdcard/Download/MagicNet/MagicNet-diagnostics.txt",bytes:12800};

function fixture(responder) {
  const commands = [];
  const context = vm.createContext({
    ...useActionLock(), parseSupportExport, decodeMachineData, machineErrorCode,
    t: value => value, state: {notice:"",phase:"idle"},
    exportedBundle:{value:null}, exportError:{value:""}, exportPathCopied:{value:false},
    runMachineCli: async command => {commands.push(command); return responder(command);},
  });
  vm.runInContext(code, context);
  return {context,commands};
}

test("one-click export negotiates capabilities and deduplicates simultaneous clicks", async () => {
  let complete;
  const pending = new Promise(resolve => { complete = resolve; });
  const {context,commands} = fixture(command => command.endsWith("capabilities") ? capability : pending);
  const first = context.exportDiagnostics();
  const duplicate = context.exportDiagnostics();
  await Promise.resolve();
  complete(ok("support.export", metadata));
  await Promise.all([first,duplicate]);
  assert.deepEqual(commands,["--json capabilities","--json support export"]);
  assert.deepEqual(context.exportedBundle.value,metadata);
  assert.equal(context.state.phase,"done");
});

test("unsupported or malformed capabilities do not write a diagnostic file", async () => {
  for (const response of [ok("machine.capabilities",{commands:[],mutation_commands:[]}),
    ok("machine.capabilities",{commands:["support.export"]}), {ok:true,stdout:"broken"}]) {
    const {context,commands} = fixture(() => response);
    await context.exportDiagnostics();
    assert.deepEqual(commands,["--json capabilities"]);
    assert.equal(context.exportedBundle.value,null);
    assert.equal(context.state.phase,"error");
  }
});

test("failed export clears previous success and exposes only a normalized error", async () => {
  const {context,commands} = fixture(command => command.endsWith("capabilities") ? capability : {
    ok:false,stdout:JSON.stringify({schema:1,ok:false,command:"support.export",error:{
      code:"support.export_failed",message:"PRIVATE-ERROR-CANARY"}}),
  });
  context.exportedBundle.value = metadata;
  context.exportPathCopied.value = true;
  await context.exportDiagnostics();
  assert.equal(context.exportedBundle.value,null);
  assert.equal(context.exportPathCopied.value,false);
  assert.equal(context.exportError.value,"support.export_failed");
  assert.equal(context.state.phase,"error");
  assert.equal(JSON.stringify(context.state).includes("PRIVATE-ERROR-CANARY"),false);
  assert.deepEqual(commands,["--json capabilities","--json support export"]);
});

test("wrong command, partial JSON and nonzero completion cannot confirm a file", async () => {
  for (const response of [ok("support.bundle",metadata), {ok:true,stdout:'{"schema":1'},
    {...ok("support.export",metadata),ok:false}]) {
    const {context} = fixture(command => command.endsWith("capabilities") ? capability : response);
    await context.exportDiagnostics();
    assert.equal(context.exportedBundle.value,null);
    assert.equal(context.state.phase,"error");
  }
});
