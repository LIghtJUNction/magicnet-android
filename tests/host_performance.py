#!/usr/bin/env python3
"""Bounded stopped-host measurements; never Android startup or traffic claims."""
import hashlib
import json
import os
import pathlib
import platform
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]

def main():
    cli = ROOT / 'assets/bin/linux-amd64/magicnet-cli'
    core = ROOT / 'assets/bin/linux-amd64/sing-box'
    measure = ROOT / '.tools/measure'
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', str(ROOT/'tests/measure.c'), '-o', str(measure)], check=True)
    report = {
        'schema': 1,
        'scope': 'Warm filesystem, stopped host module; process launch plus command; no Android dataplane, public network, or soak',
        'observer': 'Python perf_counter around a tiny C fork/exec/wait4 helper and CLI; output capture; per-child peak RSS excludes Python parent image; observer overhead not subtracted',
        'host': {'system': platform.system(), 'machine': platform.machine(), 'kernel': platform.release()},
        'cli_sha256': hashlib.sha256(cli.read_bytes()).hexdigest(),
        'core_sha256': hashlib.sha256(core.read_bytes()).hexdigest(),
        'budget': 'unknown; no accepted target was supplied',
        'samples': [],
    }
    for name in ('memory.max', 'cpu.max'):
        p = pathlib.Path('/sys/fs/cgroup') / name
        if p.is_file():
            report['host'][name] = p.read_text().strip()
    with tempfile.TemporaryDirectory(prefix='magicnet-perf-') as d:
        r = pathlib.Path(d)
        (r / 'bin').mkdir()
        shutil.copy2(cli, r / 'bin/magicnet-cli')
        shutil.copy2(core, r / 'bin/sing-box')
        shutil.copytree(ROOT / 'assets/rules', r / '.config/sing-box/rules')
        env = dict(os.environ, MAGICNET_ROOT=str(r))
        subprocess.run([str(r / 'bin/magicnet-cli'), '__install'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=60)
        config = r / '.config/sing-box/config.json'
        report['configuration_sha256'] = hashlib.sha256(config.read_bytes()).hexdigest()
        for args in (['--json', 'capabilities'], ['--json', 'service', 'status'], ['--json', 'sub', 'status']):
            durations, rss, failures = [], [], 0
            for _ in range(30):
                start = time.perf_counter()
                p = subprocess.run([str(measure), str(r / 'bin/magicnet-cli'), *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
                durations.append((time.perf_counter() - start) * 1000)
                try:
                    value = json.loads(p.stdout)
                    resource = json.loads(p.stderr)
                    assert p.returncode == 0 and value['schema'] == 1 and value['ok'] is True
                    rss.append(resource['rss_kib'])
                except (ValueError, AssertionError, KeyError):
                    failures += 1
            report['samples'].append({'command': args, 'n': 30, 'result': 'PASS' if not failures else 'FAIL', 'failures': failures, 'median_ms': round(statistics.median(durations), 3), 'min_ms': round(min(durations), 3), 'max_ms': round(max(durations), 3), 'median_max_rss_kib': statistics.median(rss) if rss else None, 'max_rss_kib': max(rss) if rss else None})
    path = ROOT / 'test-results/host-performance.json'
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return any(s['failures'] for s in report['samples'])

if __name__ == '__main__':
    raise SystemExit(main())
