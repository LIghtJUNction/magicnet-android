#!/usr/bin/env python3
"""Developer regressions after the coordinator disclosed three acceptance defects.

Only isolated new-code fixtures are used. The update cases never accept a worker,
fetch a release or invoke a manager. The policy provider is a synthetic process.
"""
from pathlib import Path
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'assets/bin/linux-amd64/magicnet-cli'

PROVIDER = r'''#!/usr/bin/python3
import json,sys
from pathlib import Path
root=Path(__file__).resolve().parent.parent
path=root/'provider.json';s=json.loads(path.read_text());args=sys.argv[4:]
def save():path.write_text(json.dumps(s))
def record(uid):
 return {'uid':int(uid),'user':int(uid)//100000,'policy':s['policies'][str(uid)],'packages':s.get('packages',{}).get(str(uid),['com.example.fixture'+str(uid)])}
def fail(message):
 save();print(json.dumps({'ok':False,'error':message}));sys.exit(7)
action=args[0]
if action=='network-inspect':out={'provider':'aosp','records':[record(uid) for uid in sorted(s['policies']) if s['policies'][uid]&1]}
elif action=='network-get':
 if s.get('fail_get_once_uid')==args[1]:
  s.pop('fail_get_once_uid');fail('lost_readback')
 out=record(args[1])
elif action=='network-set':
 uid=args[1];desired=int(args[2]);s.setdefault('set_attempts',[]).append([uid,desired])
 inject=s.get('failure',{});match=inject.get('remaining',0)>0 and inject.get('uid')==uid and inject.get('desired')==desired
 if match:inject['remaining']-=1
 if match and inject.get('timing')=='before':fail('before_set')
 if not (match and inject.get('timing')=='ignored'):s['policies'][uid]=desired
 save()
 if match and inject.get('timing')=='after':fail('lost_setter_response')
 if match and inject.get('timing')=='readback':s['fail_get_once_uid']=uid;save()
 out={'written':True}
else:fail('unsupported_test_action')
print(json.dumps({'ok':True,'data':out}))
'''


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded(value))
    path.chmod(0o600)


def run(root, *args, expected=0):
    p = subprocess.run([str(CLI), '--json', *args], env=dict(os.environ, MAGICNET_ROOT=str(root)), capture_output=True, text=True, timeout=20)
    value = json.loads(p.stdout)
    assert p.returncode == expected, (args, p.returncode, value, p.stderr)
    assert value['schema'] == 1 and value['ok'] is (expected == 0), value
    return value['data'] if expected == 0 else value['error']['code']


def update_fixture(root):
    root.mkdir(parents=True)
    (root / 'module.prop').write_text('id=MagicNet\nversion=v1.8.1\nversionCode=10609\n')
    request_id = 'repair-replay-001'
    intent = {'action': 'install', 'expected_installed': 'v1.8.1', 'expected_latest': 'v1.8.2'}
    fingerprint = base64.urlsafe_b64encode(hashlib.sha256(encoded(intent)).digest()[:16]).decode().rstrip('=')
    receipt = dict(intent, request_id=request_id, baseline='v1.8.1', phase='reboot_required', error_code='none', recovery_required=False)
    ledger = {'used': {request_id: fingerprint}, 'results': {request_id: receipt}, 'order': [request_id]}
    write(root / '.state/module-update/ledger.json', ledger)
    return request_id, intent, receipt, ledger


def update_args(request_id, intent):
    return ['module-update', 'install', '--request-id', request_id, '--expected-installed', intent['expected_installed'], '--expected-latest', intent['expected_latest']]


def update_snapshot(root):
    return {p: (root / p).read_bytes() if (root / p).exists() else None for p in ['.state/module-update/ledger.json', '.config/magicnet/module-update.conf', '.state/module-update/record-journal.json', '.state/owners/module-update.json']}


def blocked_update(root, kind):
    request_id, intent, receipt, ledger = update_fixture(root)
    if kind in ('disable', 'update', 'remove'):
        (root / kind).touch()
    elif kind == 'pending_manager':
        (root.parent.parent / 'modules_update/MagicNet').mkdir(parents=True)
    elif kind == 'unreadable_journal':
        (root / '.state/module-update/record-journal.json').write_text('{invalid')
    elif kind == 'invalid_journal_candidate':
        write(root / '.state/module-update/record-journal.json', {'schema': 1, 'files': [{'path': '.state/module-update/ledger.json', 'before': hashlib.sha256(encoded(ledger)).hexdigest(), 'after': base64.b64encode(b'{invalid').decode()}, {'path': '.config/magicnet/module-update.conf', 'before': hashlib.sha256(b'').hexdigest(), 'after': base64.b64encode(encoded(receipt)).decode()}]})
    elif kind in ('recovery_required', 'interrupted_install'):
        current = dict(receipt, request_id='another-request', phase='installing' if kind == 'interrupted_install' else 'failed', recovery_required=kind == 'recovery_required')
        write(root / '.config/magicnet/module-update.conf', current)
    elif kind == 'unknown_owner':
        write(root / '.state/owners/module-update.json', {'pid': os.getpid(), 'start': 'unproved'})
    else:
        raise AssertionError(kind)
    for name in (request_id, 'brand-new-request'):
        before = update_snapshot(root)
        error = run(root, *update_args(name, intent), expected=1)
        assert error in ('module-update.pending', 'module-update.record_pending', 'module-update.recovery_required', 'module-update.ownership_unknown'), error
        assert update_snapshot(root) == before, (kind, 'blocked request mutated evidence')


def healthy_replay(root):
    request_id, intent, receipt, ledger = update_fixture(root)
    before = update_snapshot(root)
    data = run(root, *update_args(request_id, intent))
    assert data['replayed'] and data['phase'] == 'reboot_required'
    assert update_snapshot(root) == before
    assert run(root, *update_args(request_id, dict(intent, expected_latest='v1.9.0')), expected=1) == 'module-update.conflict'
    ledger['results'].clear();write(root / '.state/module-update/ledger.json', ledger)
    before = update_snapshot(root)
    assert run(root, *update_args(request_id, intent), expected=1) == 'module-update.receipt_expired'
    assert update_snapshot(root) == before


def exhausted_ids(root):
    _, intent, _, ledger = update_fixture(root)
    ledger = {'used': {f'old-{i:05}': 'fixed-intent' for i in range(4096)}, 'results': {}, 'order': []}
    write(root / '.state/module-update/ledger.json', ledger);before = update_snapshot(root)
    assert run(root, *update_args('brand-new-request', intent), expected=1) == 'module-update.id_budget_exhausted'
    assert update_snapshot(root) == before


def update_publication_recovery(root, prefix):
    request_id, intent, receipt, ledger = update_fixture(root)
    before_ledger = encoded({'used': {}, 'results': {}, 'order': []})
    (root / '.state/module-update/ledger.json').write_bytes(before_ledger)
    files = [('.state/module-update/ledger.json', before_ledger, encoded(ledger)), ('.config/magicnet/module-update.conf', b'', encoded(receipt))]
    journal = {'schema': 1, 'files': [{'path': p, 'before': hashlib.sha256(before).hexdigest(), 'after': base64.b64encode(after).decode()} for p, before, after in files]}
    write(root / '.state/module-update/record-journal.json', journal)
    for p, _, after in files[:prefix]:
        (root / p).parent.mkdir(parents=True, exist_ok=True);(root / p).write_bytes(after)
    data = run(root, *update_args(request_id, intent))
    assert data['replayed'] and data['phase'] == 'reboot_required'
    for p, _, after in files:assert (root / p).read_bytes() == after
    assert not (root / '.state/module-update/record-journal.json').exists()
    assert (root / '.state/machines/module-update.state').is_file()
    assert not (root / '.state/owners/module-update.json').exists()


class PolicyFixture:
    def __init__(self, root):
        self.root = root; (root / 'bin').mkdir(parents=True)
        helper = root / 'bin/app_process';helper.write_text(PROVIDER);helper.chmod(0o700)
        (root / 'bin/magicnet-bridge.jar').write_bytes(b'synthetic-provider-presence')
        self.path = root / 'provider.json';self.journal = root / '.state/network-access/journal.json'
        self.set({'policies': {'10001': 1, '10002': 1}})
    def get(self):return json.loads(self.path.read_text())
    def set(self, state):write(self.path, state)
    def inject(self, uid, desired, timing):
        state = self.get();state['failure'] = {'uid': str(uid), 'desired': desired, 'timing': timing, 'remaining': 1};self.set(state)
    def action(self, action, expected=0):
        inspect = run(self.root, 'network-access', 'inspect')
        return run(self.root, 'network-access', action, inspect['candidate'], '--confirm', expected=expected)
    def original(self):assert self.get()['policies']['10001'] == self.get()['policies']['10002'] == 1
    def complete_baseline(self):
        records = json.loads(self.journal.read_text())['records']
        assert [(r['uid'], r['policy']) for r in records] == [(10001, 1), (10002, 1)]


def policy_partial(f, uid='10002', timing='before'):
    f.inject(uid, 0, timing)
    assert f.action('repair', 1) in ('network-access.write_failed', 'network-access.readback_failed')
    f.complete_baseline()
    assert f.action('repair')['phase'] == 'applied';f.complete_baseline()
    assert f.get()['policies'] == {'10001': 0, '10002': 0}
    assert f.action('rollback')['phase'] == 'rolled_back';f.original()
    attempts = len(f.get()['set_attempts'])
    assert f.action('rollback')['phase'] == 'rolled_back'
    assert len(f.get()['set_attempts']) == attempts


def policy_external(f, identity=False):
    f.inject('10002', 0, 'before');f.action('repair', 1)
    state = f.get()
    if identity:state['packages'] = {'10001': ['com.example.changed.shared']}
    else:state['policies']['10001'] = 2
    f.set(state);before = f.journal.read_bytes()
    for action in ('repair', 'rollback'):
        assert f.action(action, 1) == 'network-access.conflict'
        assert f.journal.read_bytes() == before
        assert f.get()['policies'] == state['policies']
    state = f.get();state['policies']['10001'] = 0;state.pop('packages', None);f.set(state)
    f.action('rollback');f.original()


def policy_rollback_interruption(f, timing):
    f.action('repair');f.inject('10002', 1, timing)
    assert f.action('rollback', 1) in ('network-access.write_failed', 'network-access.readback_failed')
    before = f.journal.read_bytes();f.complete_baseline()
    assert f.action('repair', 1) == 'network-access.recovery_pending'
    assert f.journal.read_bytes() == before
    f.action('rollback');f.original()


def policy_new_identity(f):
    f.inject('10002', 0, 'before');f.action('repair', 1)
    state = f.get();state['policies']['10003'] = 1;f.set(state);before = f.journal.read_bytes()
    assert f.action('repair', 1) == 'network-access.recovery_pending'
    assert f.journal.read_bytes() == before
    f.action('rollback');f.original();assert f.get()['policies']['10003'] == 1


def policy_reapply(f):
    f.action('repair');state = f.get();state['policies']['10001'] = 1;f.set(state)
    assert f.action('repair', 1) == 'network-access.reapply_required'
    f.action('reapply');f.complete_baseline();f.action('rollback');f.original()


def policy_legacy(f):
    f.inject('10002', 0, 'before');f.action('repair', 1)
    j = json.loads(f.journal.read_text());j.pop('schema')
    for r in j['records']:r.pop('progress')
    write(f.journal, j)
    f.action('repair');f.complete_baseline();f.action('rollback');f.original()


def policy_terminal_external(f):
    f.action('repair');f.action('rollback');state = f.get();state['policies']['10001'] = 0;f.set(state)
    before = f.journal.read_bytes()
    assert f.action('rollback', 1) == 'network-access.conflict'
    assert f.journal.read_bytes() == before and f.get()['policies']['10001'] == 0


def main():
    results = []
    def case(name, callback):
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix='repair-acceptance-', dir=ROOT / '.tools') as temporary:
            root = Path(temporary) / 'modules/MagicNet'
            try:
                callback(root);result = {'case': name, 'result': 'PASS'}
            except Exception as error:
                result = {'case': name, 'result': 'FAIL', 'error': repr(error)}
        result['elapsed_seconds'] = round(time.monotonic()-started, 3);results.append(result);print(json.dumps(result), flush=True)
    case('update healthy replay, conflict and expired receipt', healthy_replay)
    for kind in ('disable', 'update', 'remove', 'pending_manager', 'unreadable_journal', 'invalid_journal_candidate', 'recovery_required', 'interrupted_install', 'unknown_owner'):
        case('update old and new request blocked: '+kind, lambda root, kind=kind: blocked_update(root, kind))
    case('update bounded used-ID history', exhausted_ids)
    for prefix in (0, 1, 2):
        case('update publication recovery after '+str(prefix)+' private files', lambda root, prefix=prefix: update_publication_recovery(root, prefix))
    for uid, timing in (('10002', 'before'), ('10001', 'after'), ('10002', 'after'), ('10001', 'readback'), ('10001', 'ignored')):
        case('policy partial '+uid+' '+timing, lambda root, uid=uid, timing=timing: policy_partial(PolicyFixture(root), uid, timing))
    case('policy external additional bit preserves evidence', lambda root: policy_external(PolicyFixture(root)))
    case('policy changed shared-package identity preserves evidence', lambda root: policy_external(PolicyFixture(root), True))
    for timing in ('before', 'after', 'readback'):
        case('policy interrupted rollback '+timing, lambda root, timing=timing: policy_rollback_interruption(PolicyFixture(root), timing))
    case('policy additional identity cannot replace baseline', lambda root: policy_new_identity(PolicyFixture(root)))
    case('policy explicit reapply retains full original baseline', lambda root: policy_reapply(PolicyFixture(root)))
    case('policy legacy complete journal preserves original identities', lambda root: policy_legacy(PolicyFixture(root)))
    case('policy completed rollback does not own later changes', lambda root: policy_terminal_external(PolicyFixture(root)))
    report = {'schema': 1, 'scope': 'Developer regression of now-disclosed P1-B/P1-C; compiled CLI, synthetic provider and temporary files only; no network request, root manager or Android device', 'cli_sha256': hashlib.sha256(CLI.read_bytes()).hexdigest(), 'results': results, 'passed': all(r['result']=='PASS' for r in results)}
    (ROOT / 'test-results/repair-acceptance.json').write_text(json.dumps(report, indent=2)+'\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':raise SystemExit(main())
