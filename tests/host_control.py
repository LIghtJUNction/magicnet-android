#!/usr/bin/env python3
"""New implementation integration: real CLI, core check, MCP and private payload."""
from pathlib import Path
import base64, hashlib, http.client, json, os, shutil, socket, subprocess, tempfile, time

ROOT=Path(__file__).resolve().parents[1]
CANARY="PRIVATE_SYNTHETIC_CANARY_37439"

def main():
    results=[]
    def record(name,fn):
        started=time.monotonic()
        try:
            fn(); row={"case":name,"result":"PASS"}
        except Exception as e:
            row={"case":name,"result":"FAIL","error":str(e)}
        row["elapsed_seconds"]=round(time.monotonic()-started,3)
        results.append(row); print(json.dumps(row),flush=True)
    with tempfile.TemporaryDirectory(prefix="magicnet-control-") as td:
        root=Path(td); (root/"bin").mkdir()
        for name in ("magicnet-cli","sing-box"):
            shutil.copy2(ROOT/"assets/bin/linux-amd64"/name,root/"bin"/name)
        shutil.copytree(ROOT/"assets/rules",root/".config/sing-box/rules")
        (root/"module.prop").write_text("id=MagicNet\nversion=v0.3.1\nversionCode=1\n")
        env=dict(os.environ,MAGICNET_ROOT=str(root),MAGICNET_API="http://127.0.0.1:9")
        cli=root/"bin/magicnet-cli"
        def run(*args,expected=0):
            p=subprocess.run([str(cli),*args],env=env,capture_output=True,timeout=90)
            assert p.returncode==expected,(args,p.returncode,p.stdout.decode()[:1000],p.stderr.decode()[:1000])
            return p
        def machine(*args):
            p=run("--json",*args); x=json.loads(p.stdout)
            assert x["schema"]==1 and x["ok"] and isinstance(x["data"],dict)
            return x["data"]
        record("default_config_real_core_check",lambda:run("__install"))
        record("capabilities_and_read_only_status",lambda:[machine("capabilities"),machine("service","status"),machine("sub","status")])
        def rejected_write():
            before=(root/".config/sing-box/config.json").read_bytes()
            p=run("service","stop","--json",expected=1)
            assert json.loads(p.stdout)["error"]["code"]=="machine.command_unsupported"
            assert (root/".config/sing-box/config.json").read_bytes()==before
        record("machine_write_rejection_zero_mutation",rejected_write)
        def local_import():
            node={"type":"vless","tag":CANARY,"server":"example.invalid","server_port":443,"uuid":"b7b9861c-31e6-4676-a735-3c63ed4128bf","encryption":"none"}
            data=json.dumps({"outbounds":[node]}).encode()
            p=run("webui","payload","create","subscription","host-test.txt")
            assert p.stdout.decode().strip()==str(root/".state/private/payload/subscription/host-test.txt")
            run("webui","payload","append","subscription","host-test.txt",base64.b64encode(data).decode())
            receipt=json.loads(run("webui","payload","apply-subscription-source","host-test.txt").stdout)
            assert receipt["accepted"] and receipt["generation_id"] and receipt["operation_id"]
            status=machine("sub","status")
            assert status["source"]["configured_count"]==1 and status["source"]["mode"]=="local_file"
            assert status["last"]["batch"]["outcome"]=="committed"
            assert CANARY not in json.dumps(status)
            assert not (root/".state/private/payload/subscription/host-test.txt").exists()
            service=machine("service","status")
            assert service["process"]["state"]=="stopped"
            for p in (root/".state/machines").glob("*.state"):
                assert CANARY not in p.read_text()
        record("private_local_source_core_check_transaction_receipt",local_import)
        def failed_payload():
            before=(root/".config/sing-box/config.json").read_bytes()
            run("webui","payload","create","subscription","bad.txt")
            run("webui","payload","append","subscription","bad.txt",base64.b64encode(b"not a valid source\x00").decode())
            run("webui","payload","apply-subscription-source","bad.txt",expected=1)
            assert not (root/".state/private/payload/subscription/bad.txt").exists()
            assert (root/".config/sing-box/config.json").read_bytes()==before
        record("consumed_invalid_payload_preserves_effective_config",failed_payload)
        def schedule_owner_repair():
            owner_file=root/".state/owners/fswatch.json"
            try:
                run("sub","schedule","set","12")
                first=json.loads(owner_file.read_text())
                waiting=machine("sub","status")["schedule"]
                assert waiting["enabled"] and waiting["running"] and waiting["owner_valid"]
                assert waiting["refreshing"] is False and waiting["next_due_epoch"]>int(time.time())
                run("sub","schedule","set","12")
                assert json.loads(owner_file.read_text())==first
                run("supervisor","stop","fswatch")
                assert machine("sub","status")["schedule"]["running"] is False
                run("sub","schedule","set","12")
                repaired=json.loads(owner_file.read_text())
                assert (repaired["pid"],repaired["start"])!=(first["pid"],first["start"])
                assert machine("sub","status")["schedule"]["owner_valid"] is True
                run("sub","schedule","set","off")
                off=machine("sub","status")["schedule"]
                assert off["enabled"] is False and off["interval_hours"]=="off"
                assert json.loads((root/".config/magicnet/subscription-schedule.json").read_text())["interval_hours"]=="off"
                assert machine("service","status")["process"]["state"]=="stopped"
            finally:
                run("supervisor","stop","fswatch")
        record("compiled_scheduler_waiting_repeat_repair_disable",schedule_owner_repair)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0)); port=sock.getsockname()[1]
        def mcp_enable():
            run("mcp","enable","127.0.0.1",str(port))
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                try:
                    c=socket.create_connection(("127.0.0.1",port),timeout=.2);c.close();return
                except OSError:time.sleep(.05)
            raise AssertionError("MCP did not start")
        record("mcp_explicit_enable_real_daemon",mcp_enable)
        secret=json.loads((root/".config/magicnet/mcp.json").read_text())["secret"]
        def rpc(body,auth=True):
            conn=http.client.HTTPConnection("127.0.0.1",port,timeout=10)
            headers={"Content-Type":"application/json"}
            if auth:headers["Authorization"]="Bearer "+secret
            conn.request("POST","/mcp",json.dumps(body),headers)
            response=conn.getresponse(); data=response.read(); status=response.status;conn.close()
            return status,json.loads(data) if status==200 else data
        def authentication():
            status,_=rpc({"jsonrpc":"2.0","id":1,"method":"tools/list"},False);assert status==401
            status,x=rpc({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}})
            assert status==200 and x["result"]["protocolVersion"]=="2025-06-18"
            _,x=rpc({"jsonrpc":"2.0","id":3,"method":"tools/list"})
            assert len(x["result"]["tools"])==85
        record("mcp_auth_initialize_catalog",authentication)
        def private_boundary():
            _,x=rpc({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"magicnet_cli","arguments":{"args":["sub","inspect"]}}})
            assert x["result"]["isError"] and CANARY not in json.dumps(x)
            _,x=rpc({"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"magicnet://status/subscription"}})
            assert CANARY not in json.dumps(x)
            _,x=rpc({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"magicnet_status","arguments":{"unknown":1}}})
            assert x["error"]["code"]==-32602
            intent=root/".config/magicnet/service-intent"
            before=intent.read_bytes() if intent.exists() else None
            status,_=rpc({"jsonrpc":"2.0","method":"tools/call","params":{"name":"magicnet_service_control","arguments":{"action":"stop"}}})
            assert status==202 and (intent.read_bytes() if intent.exists() else None)==before
        record("mcp_private_boundary_unknown_fields_notification_noop",private_boundary)
        record("mcp_owned_stop",lambda:run("mcp","stop"))
        def backup_roundtrip():
            before=(root/".config/sing-box/config.json").read_bytes()
            exported=run("backup","export","synthetic-password").stdout.strip().decode()
            assert CANARY not in exported
            run("backup","restore","wrong",exported,expected=1)
            run("backup","restore","synthetic-password",exported)
            assert (root/".config/sing-box/config.json").read_bytes()==before
        record("private_encrypted_backup_restore_real_core_check",backup_roundtrip)
    dest=ROOT/"test-results/host-control.json";dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps({"scope":"Host integration, synthetic stopped core configuration; no Android/network readiness claim","results":results},indent=2)+"\n")
    return 0 if all(r["result"]=="PASS" for r in results) else 1

if __name__=="__main__":raise SystemExit(main())
