#!/usr/bin/env python3
"""Measure the pinned host core and CLI with bounded, reproducible workloads.

Loopback traffic is local HTTP through the real mixed inbound, with the same
payload served directly as a baseline. It does not exercise Android TUN/eBPF.
--google-once permits exactly one public HTTPS request, with no retry/redirect.
Temporary configuration may contain an environment proxy; it is never reported.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import platform
import signal
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
GOOGLE = 'https://www.google.com/generate_204'
PROXY_KEYS = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
              'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')


def clean_environment():
    return {key: value for key, value in os.environ.items() if key not in PROXY_KEYS}


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def number_summary(values):
    ordered = sorted(values)
    return {'samples': len(values), 'min': round(ordered[0], 4),
            'median': round(statistics.median(values), 4),
            'p95_nearest_rank': round(ordered[math.ceil(len(values) * 0.95) - 1], 4),
            'max': round(ordered[-1], 4)}


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def config_for(port):
    return {
        'log': {'level': 'warn', 'output': '/dev/null'},
        'inbounds': [{'type': 'mixed', 'tag': 'host-probe',
                      'listen': '127.0.0.1', 'listen_port': port}],
        'outbounds': [{'type': 'direct', 'tag': 'loopback'}],
        'route': {'rules': [
            {'ip_cidr': ['127.0.0.0/8'], 'action': 'route', 'outbound': 'loopback'},
            {'action': 'reject'}], 'final': 'loopback'},
    }


@contextmanager
def running_core(core, config, evidence=None):
    with tempfile.TemporaryDirectory(prefix='magicnet-host-core-') as temporary:
        path = Path(temporary) / 'config.json'
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        environment = clean_environment()
        checked = subprocess.run([str(core), 'check', '-c', str(path)],
                                 env=environment, capture_output=True, timeout=15)
        if checked.returncode:
            raise RuntimeError('core_configuration_rejected')
        if evidence is not None:
            evidence['configuration_check'] = 'passed'
        with tempfile.TemporaryFile() as errors, subprocess.Popen(
                [str(core), 'run', '-c', str(path)], env=environment,
                stdout=subprocess.DEVNULL, stderr=errors) as process:
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        errors.seek(0)
                        if b'create netlink socket: operation not permitted' in errors.read(8192).lower():
                            raise RuntimeError('host_netlink_socket_denied')
                        raise RuntimeError('core_start_failed')
                    try:
                        with socket.create_connection(('127.0.0.1', config['inbounds'][0]['listen_port']), 0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError('core_start_timeout')
                yield process
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


def process_sample(pid):
    directory = Path('/proc') / str(pid)
    fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in (directory / 'status').read_text().splitlines())
    sample = {'elapsed_monotonic': time.monotonic(),
              'cpu_ticks': int(fields[11]) + int(fields[12]),
              'rss_kib': int(status['VmRSS'].split()[0]),
              'peak_rss_kib': int(status['VmHWM'].split()[0]),
              'threads': int(status['Threads'])}
    try:
        rollup = dict(line.split(':', 1) for line in (directory / 'smaps_rollup').read_text().splitlines()
                      if ':' in line)
        sample['pss_kib'] = int(rollup['Pss'].split()[0])
    except (OSError, KeyError):
        sample['pss_kib'] = None
    return sample


def usage_between(first, last):
    seconds = last['elapsed_monotonic'] - first['elapsed_monotonic']
    cpu = (last['cpu_ticks'] - first['cpu_ticks']) / os.sysconf('SC_CLK_TCK')
    return {'elapsed_seconds': round(seconds, 4), 'cpu_seconds': round(cpu, 4),
            'cpu_percent_one_core': round(cpu / seconds * 100, 4),
            'rss_start_kib': first['rss_kib'], 'rss_end_kib': last['rss_kib'],
            'peak_rss_kib': last['peak_rss_kib']}


def request(port, target, expected):
    connection = HTTPConnection('127.0.0.1', port, timeout=10)
    started = time.perf_counter()
    try:
        connection.request('GET', target, headers={'Connection': 'close', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        received = response.read(len(expected) + 1)
        elapsed = time.perf_counter() - started
        if response.status != 200 or received != expected:
            raise RuntimeError('loopback_response_mismatch')
        return elapsed
    finally:
        connection.close()


def measure_loopback(core, idle_seconds, evidence):
    payloads = {'/latency': b'MagicNet loopback latency\n',
                '/throughput': (b'MagicNet payload\n' * 262144)[:4 * 1024 * 1024]}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def setup(self):
            super().setup()
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def do_GET(self):
            payload = payloads.get(self.path)
            self.send_response(200 if payload is not None else 404)
            self.send_header('Content-Length', str(len(payload or b'')))
            self.send_header('Connection', 'close')
            self.end_headers()
            if payload is not None:
                self.wfile.write(payload)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        proxy_port = free_port()
        server_port = server.server_address[1]
        with running_core(core, config_for(proxy_port), evidence) as process:
            # A single warm-up request precedes the idle observation.
            request(proxy_port, f'http://127.0.0.1:{server_port}/latency', payloads['/latency'])
            samples = [process_sample(process.pid)]
            for _ in range(idle_seconds):
                time.sleep(1)
                samples.append(process_sample(process.pid))
            idle = usage_between(samples[0], samples[-1])
            idle['rss_kib'] = number_summary([sample['rss_kib'] for sample in samples])
            idle['pss_kib'] = number_summary([sample['pss_kib'] for sample in samples
                                             if sample['pss_kib'] is not None]) if any(
                                                 sample['pss_kib'] is not None for sample in samples) else None
            idle['maximum_threads'] = max(sample['threads'] for sample in samples)
            load_start = process_sample(process.pid)
            workloads = {}
            for path, count in (('/latency', 30), ('/throughput', 8)):
                elapsed = {'direct': [], 'proxy': []}
                for index in range(count):
                    # Pair and alternate order so drift is not assigned to one path.
                    for mode in (('direct', 'proxy') if index % 2 == 0 else ('proxy', 'direct')):
                        port = server_port if mode == 'direct' else proxy_port
                        target = path if mode == 'direct' else f'http://127.0.0.1:{server_port}{path}'
                        elapsed[mode].append(request(port, target, payloads[path]))
                workloads[path[1:]] = {
                    'payload_bytes': len(payloads[path]), 'samples_per_path': count,
                    'connection_mode': 'new_http_connection_per_request',
                    'payload_verified_each_request': True,
                    **{mode: {
                        'elapsed_ms': number_summary([value * 1000 for value in values]),
                        'throughput_mbps': number_summary([len(payloads[path]) * 8 / value / 1e6
                                                           for value in values]),
                        'elapsed_ms_samples': [round(value * 1000, 5) for value in values],
                    } for mode, values in elapsed.items()},
                }
            after = process_sample(process.pid)
            return {'status': 'passed', 'transport': 'http_over_ipv4_loopback_mixed_proxy',
                    'external_requests': 0, 'request_count': 77, 'idle': idle,
                    'core_during_load': usage_between(load_start, after), 'workloads': workloads,
                    'proxy_added_median_latency_ms': round(
                        workloads['latency']['proxy']['elapsed_ms']['median'] -
                        workloads['latency']['direct']['elapsed_ms']['median'], 4),
                    'proxy_to_direct_median_throughput_ratio': round(
                        workloads['throughput']['proxy']['throughput_mbps']['median'] /
                        workloads['throughput']['direct']['throughput_mbps']['median'], 4)}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def google_once(core):
    # Only this opt-in section reads the host proxy, without logging its endpoint.
    raw_proxy = next((os.environ[key] for key in ('https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY')
                      if os.environ.get(key)), '')
    proxy_port = free_port()
    config = config_for(proxy_port)
    outbound = {'type': 'direct', 'tag': 'google'}
    if raw_proxy:
        parsed = urlsplit(raw_proxy)
        if parsed.scheme not in ('http', 'https', 'socks5', 'socks5h') or not parsed.hostname:
            return {'status': 'unavailable', 'reason': 'unsupported_environment_proxy', 'requests': 0}
        outbound = {'type': 'http' if parsed.scheme in ('http', 'https') else 'socks', 'tag': 'google',
                    'server': parsed.hostname,
                    'server_port': parsed.port or (443 if parsed.scheme == 'https' else 1080
                                                  if parsed.scheme.startswith('socks') else 80)}
        if parsed.username is not None:
            outbound['username'] = unquote(parsed.username)
        if parsed.password is not None:
            outbound['password'] = unquote(parsed.password)
        if parsed.scheme == 'https':
            outbound['tls'] = {'enabled': True, 'server_name': parsed.hostname}
    config['dns'] = {'servers': [{'type': 'local', 'tag': 'local'}]}
    config['route']['default_domain_resolver'] = 'local'
    config['outbounds'].append(outbound)
    config['route']['rules'].insert(0, {'domain': ['www.google.com'], 'action': 'route', 'outbound': 'google'})
    with running_core(core, config), tempfile.TemporaryDirectory(prefix='magicnet-google-') as temporary:
        body = Path(temporary) / 'body'
        result = subprocess.run([
            'curl', '--disable', '--silent', '--output', str(body), '--write-out', '%{json}',
            '--proxy', f'http://127.0.0.1:{proxy_port}', '--noproxy', '',
            '--connect-timeout', '5', '--max-time', '15', '--retry', '0',
            '--max-redirs', '0', '--max-filesize', '4096', '--proto', '=https', '--url', GOOGLE,
        ], env=clean_environment(), capture_output=True, text=True, timeout=20)
        try:
            value = json.loads(result.stdout)
        except ValueError:
            value = {}
        count = body.stat().st_size if body.exists() else 0
        passed = result.returncode == 0 and value.get('http_code') == 204 and count == 0
        return {'status': 'passed' if passed else 'failed', 'target': GOOGLE, 'requests': 1,
                'via_real_singbox': True, 'environment_proxy_used': bool(raw_proxy),
                'curl_exit': result.returncode, 'http_status': value.get('http_code'),
                'tls_verify_result': value.get('ssl_verify_result'), 'received_bytes': count,
                'elapsed_seconds': value.get('time_total'), 'redirects_followed': 0,
                'tls_verification_disabled': False}


@contextmanager
def measurement_helper():
    # A Python parent can donate its pre-exec high-water RSS to a direct child.
    # Fork from this small native helper so it does not inflate CLI measurements.
    source = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 3) return 64;
    struct timespec start, end;
    struct rusage usage;
    int status;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 70;
    pid_t child = fork();
    if (child < 0) return 71;
    if (!child) { execvp(argv[2], argv + 2); _exit(127); }
    while (wait4(child, &status, 0, &usage) < 0) { if (errno != EINTR) return 72; }
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return 73;
    FILE *metrics = fopen(argv[1], "w");
    if (!metrics) return 74;
    double elapsed = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
    double cpu = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000.0 +
                 (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000.0;
    fprintf(metrics, "{\"elapsed_ms\":%.6f,\"peak_process_rss_kib\":%ld,\"cpu_ms\":%.6f}\n",
            elapsed, usage.ru_maxrss, cpu);
    if (fclose(metrics)) return 75;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
'''
    with tempfile.TemporaryDirectory(prefix='magicnet-resource-helper-') as temporary:
        directory = Path(temporary)
        code, binary = directory / 'measure.c', directory / 'measure'
        code.write_text(source)
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', str(code), '-o', str(binary)],
                       check=True, capture_output=True, timeout=30, env=clean_environment())
        yield binary


def run_measured(helper, command, environment, timeout):
    """Native wait4 measures each invocation; the driver is outside the timer."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr, \
            tempfile.TemporaryDirectory(prefix='magicnet-command-usage-') as temporary:
        metrics = Path(temporary) / 'usage.json'
        process = subprocess.Popen([str(helper), str(metrics), *command], env=environment,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise TimeoutError('command_timeout') from error
        if process.returncode:
            raise RuntimeError('cli_command_failed')
        stdout.seek(0)
        return json.loads(metrics.read_text()), stdout.read(65536)


def measure_cli(cli, core):
    with measurement_helper() as helper, tempfile.TemporaryDirectory(prefix='magicnet-cli-resource-') as temporary:
        module = Path(temporary)
        for name in ('.config/sing-box', '.config/magicnet', '.state/machines', '.log', 'bin'):
            (module / name).mkdir(parents=True, exist_ok=True)
        (module / 'module.prop').write_text('id=MagicNet\nversion=host-simulation\n')
        (module / 'bin/magicnet-cli').symlink_to(cli)
        if core:
            (module / 'bin/sing-box').symlink_to(core)
        (module / '.config/sing-box/config.json').write_text(json.dumps(config_for(free_port())))
        (module / '.config/magicnet/transparent-mode.conf').write_text('MAGICNET_TRANSPARENT_MODE=tun\n')
        (module / '.log/connectivity.log').write_text('phase=offline reason=timeout action=none\n' * 1024)
        uptime = int(time.clock_gettime(time.CLOCK_BOOTTIME))
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        state = module / '.state/machines/connectivity.state'
        state.write_text(f'schema=1\ndomain=connectivity\nboot={boot}\nphase=online\nreason=ok\n'
                         f'checked_at={int(time.time())}\nchecked_uptime={uptime}\n'
                         f'next_uptime={uptime + 600}\nfailures=0\nprobes=1\n')
        original = state.read_bytes()
        environment = clean_environment() | {'MODDIR': str(module),
                                             'MAGICNET_API': f'http://127.0.0.1:{free_port()}'}
        result = {'binary_sha256': digest(cli), 'fixture': 'isolated_host_module_future_probe_deadline',
                  'measurement': 'native fork/exec wall time and wait4 CPU; excludes Python driver',
                  'peak_rss_scope': 'maximum individual process including waited descendants; not concurrent tree total or persistent memory'}
        for name, command in (('status', ['--json', 'connectivity', 'status']),
                              ('tick_not_due', ['connectivity', 'tick'])):
            samples = []
            for _ in range(20):
                usage, output = run_measured(helper, [str(cli), *command], environment, 10)
                if name == 'status' and json.loads(output).get('ok') is not True:
                    raise RuntimeError('cli_status_not_ok')
                samples.append(usage)
            result[name] = {key: number_summary([sample[key] for sample in samples])
                            for key in samples[0]}
        if state.read_bytes() != original:
            raise RuntimeError('no_op_changed_probe_state')
        result['no_op_preserved_probe_state'] = True
        usage, output = run_measured(helper, [str(cli), '--json', 'support', 'export'], environment, 40)
        response = json.loads(output)
        if response.get('ok') is not True:
            raise RuntimeError('cli_export_not_ok')
        exported = Path(response['data']['path'])
        if exported.parent != module / '.state/diagnostics' or not exported.is_file():
            raise RuntimeError('cli_export_path_mismatch')
        result['export'] = usage | {'file_bytes': exported.stat().st_size,
                                    'reported_bytes': response['data']['bytes'], 'samples': 1}
        result['acceptance'] = 'passed'
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, help='host core built by scripts/build-sing-box.sh')
    parser.add_argument('--cli', type=Path, help='optional native host magicnet-cli')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--idle-seconds', type=int, default=20, choices=range(15, 31))
    parser.add_argument('--google-once', action='store_true')
    args = parser.parse_args()
    if not args.core and not args.cli:
        parser.error('at least one of --core or --cli is required')
    if args.google_once and not args.core:
        parser.error('--google-once requires --core')
    args.core = args.core.resolve() if args.core else None
    args.cli = args.cli.resolve() if args.cli else None
    report = {'schema': 1, 'captured_at_utc': datetime.now(timezone.utc).isoformat(),
              'scope': 'Linux host simulation; Android TUN/eBPF and radio not exercised',
              'source_commit': git('rev-parse', 'HEAD'),
              'environment': {'os': platform.system(), 'release': platform.release(),
                              'architecture': platform.machine(), 'cpus': os.cpu_count(),
                              'python': platform.python_version(), 'load_average': os.getloadavg(),
                              'cpu_tick_hz': os.sysconf('SC_CLK_TCK')},
              'google_once': {'status': 'pending' if args.google_once else 'not_requested', 'requests': 0}}
    failed = False

    def failure(error):
        # Do not leak a command, proxy endpoint, environment, or credential.
        return {'status': 'blocked' if str(error) == 'host_netlink_socket_denied' else 'failed',
                'type': type(error).__name__,
                'reason': str(error) if isinstance(error, (RuntimeError, TimeoutError))
                else 'host_operation_failed', 'errno': getattr(error, 'errno', None)}

    errors = (OSError, RuntimeError, ValueError, TimeoutError, subprocess.SubprocessError)
    if args.core:
        try:
            selected = git('ls-tree', 'HEAD', '--', 'sing-box').split()
            revision = git('-C', str(ROOT / 'sing-box'), 'rev-parse', 'HEAD')
            if len(selected) != 4 or selected[:2] != ['160000', 'commit'] or selected[2] != revision:
                raise RuntimeError('core_source_differs_from_pinned_gitlink')
            version = subprocess.check_output([str(args.core), 'version'], text=True, timeout=10)
            if f'+LIghtJUNction.{revision[:12]}' not in version:
                raise RuntimeError('core_version_differs_from_pinned_source')
            expected_tags = (ROOT / 'sing-box/release/DEFAULT_BUILD_TAGS_OTHERS').read_text().strip()
            actual_tags = next((line.removeprefix('Tags: ').strip() for line in version.splitlines()
                                if line.startswith('Tags: ')), '')
            if set(actual_tags.split(',')) != set(expected_tags.split(',')):
                raise RuntimeError('core_build_tags_differ_from_production')
            report['core'] = {'source_revision': revision, 'binary_sha256': digest(args.core),
                              'binary_bytes': args.core.stat().st_size, 'version': version.strip(),
                              'config': 'mixed_loopback_only_no_tun_no_ebpf', 'log_level': 'warn',
                              'production_build_tags_verified': True}
            report['loopback'] = measure_loopback(args.core, args.idle_seconds, report['core'])
        except errors as error:
            failed = True
            report['loopback'] = failure(error)
            if args.google_once and report['google_once']['status'] == 'pending':
                report['google_once'] = {'status': 'unavailable', 'requests': 0,
                                         'reason': report['loopback']['reason']}
        if args.google_once and report.get('loopback', {}).get('status') == 'passed':
            try:
                report['google_once'] = google_once(args.core)
            except errors as error:
                report['google_once'] = failure(error) | {'requests': None, 'max_requests': 1}
    if args.cli:
        try:
            report['cli'] = measure_cli(args.cli, args.core)
        except errors as error:
            failed = True
            report['cli'] = failure(error)
    blocked_only = (report.get('loopback', {}).get('status') == 'blocked'
                    and (not args.cli or report.get('cli', {}).get('acceptance') == 'passed'))
    report['local_acceptance'] = 'blocked' if blocked_only else 'failed' if failed else 'passed'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'local_acceptance': report['local_acceptance'],
                      'google_status': report['google_once']['status'], 'output': str(args.output)}))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
