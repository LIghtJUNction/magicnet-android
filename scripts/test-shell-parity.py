#!/usr/bin/env python3
"""Compare shipped shell contracts with an immutable checkout under each shell."""
from __future__ import annotations

import argparse
import difflib
import json
import os
from pathlib import Path
import shlex
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
LIB = Path('src/MagicNet/lib/magicnet')


def quote(value: str) -> str:
    return shlex.quote(value)


def cases() -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    text_values = [
        '', 'plain', ' 中文 / 日本語 / русский ', '"quoted" \\ slash',
        'a\nb\r\tc', '\n\n', ' a \\n b ', '* [abc] ? literal',
        ''.join(chr(c) for c in range(1, 32)) + chr(127),
    ]
    text_values.extend(f'node-{i} 雪\\"\t{i}' for i in range(10))
    for index, value in enumerate(text_values):
        result.append((f'escape-{index}', f'magicnet_json_escape {quote(value)}'))
    for index, value in enumerate(['', ',', 'a,b', ' a , b ,, ', '中文,雪', '"a",\\b', 'a\nb, c', 'a,a,b', '*', '\x01,\x7f']):
        result.append((f'csv-{index}', f'magicnet_json_array_csv {quote(value)}'))
    for index, value in enumerate(['', 'one', 'one\ntwo\none', ' direct \ndirect\nblock', '中文\n"a"\n\\b', ' \n\t\n\x01', '*\n?\n[abc]']):
        result.append((f'selectors-{index}', f'magicnet_selector_tags_json {quote(value)} fallback'))
    for index, value in enumerate(['', 'ipv4_only', 'prefer_ipv4', 'prefer_ipv6', 'compat', 'disabled', 'ipv4-only', 'prefer-ipv6', 'dual', 'auto', 'bad']):
        result.append((f'ipv6-{index}', f'MAGICNET_IPV6_MODE={quote(value)} magicnet_ipv6_mode'))
    for index, value in enumerate(['', '1m', '3m', '5m', '10m', '15m', '30m', '12m', '0']):
        result.append((f'udp-{index}', f'MAGICNET_UDP_TIMEOUT={quote(value)} magicnet_udp_timeout'))
    for index, value in enumerate(['', '0', '1279', '1280', '1400', '1500', '1501', 'bad']):
        result.append((f'mtu-{index}', f'MAGICNET_TUN_MTU={quote(value)} magicnet_tun_mtu'))
    for index, value in enumerate(['', '0', '01', '53', '1053', '65535', '65536', '99999999', 'bad']):
        result.append((f'dns-port-{index}', f'MAGICNET_DNS_CAPTURE_PORT={quote(value)} magicnet_dns_capture_policy_port'))
    for index, value in enumerate(['', 'default', 'cloudflare', 'doh', 'dot', 'udp', '1.1.1.1', 'cloudflare-doh', 'bad']):
        result.append((f'dns-profile-{index}', f'MAGICNET_DNS_PROFILE={quote(value)} magicnet_dns_profile'))
    for mode in ['ipv4_only', 'prefer_ipv4', 'prefer_ipv6', 'prefer-ipv6', 'bad']:
        for available in [0, 1]:
            result.append((f'bootstrap-{mode}-{available}',
                           f'ip() {{ [ {available} = 1 ] && echo "default via fe80::1"; }}\n'
                           f'MAGICNET_IPV6_MODE={quote(mode)} magicnet_dns_bootstrap_server'))
    for kind in ['cmdline', 'comm', 'stat', 'start', 'state']:
        fn = {'cmdline': 'cmdline_lines', 'stat': 'stat_identity'}.get(kind, kind)
        for reader_rc in [0, 1, 2]:
            result.append((f'proc-{kind}-{reader_rc}', f'''
magicnet_proc_reader_test_hook() {{
    if [ {reader_rc} -ne 0 ]; then return {reader_rc}; fi
    case "$1" in cmdline) printf 'sing-box\\nrun\\n' ;; comm) echo sing-box ;; stat) echo 'S 234' ;; esac
}}
magicnet_proc_{fn} 101 "$PROC_FIXTURE"
'''))
        result.append((f'proc-missing-{kind}', f'magicnet_proc_{fn} 999 "$PROC_FIXTURE"'))
    steps = {
        'hotspot-offload': 'magicnet_hotspot_offload_prepare',
        'subscription': 'magicnet_prepare_singbox_nodes_unlocked',
        'chain': 'magicnet_singbox_chain_apply',
        'transparent': 'magicnet_singbox_apply_transparent_mode',
        'hotspot': 'magicnet_singbox_apply_hotspot_policy',
        'dns': 'magicnet_dns_apply_unlocked',
        'tailscale': 'magicnet_tailscale_apply_unlocked',
        'apps': 'magicnet_app_policy_apply_unlocked',
        'warp': 'magicnet_warp_apply_unlocked',
        'panel': 'magicnet_singbox_apply_zashboard',
        'auth': 'magicnet_tailscale_inject_auth_key',
        'config-check': 'magicnet_validate_singbox_transparent_config',
        'route-baseline': 'magicnet_kernel_route_state_begin',
        'core-launch': 'singbox_start',
    }
    setup = '''
import() { :; }
magicnet_warn() { printf 'warn:%s\\n' "$*"; }
magicnet_module_disabled() { return 1; }
magicnet_cmd_exists() { return 0; }
is_singbox_running() { return 1; }
magicnet_tailscale_scrub_auth_key() { echo scrub; }
magicnet_singbox_runtime_memory_limit() { echo 256MiB; }
magicnet_singbox_running_has_nodes() { return 0; }
magicnet_kernel_route_report_result() { printf 'route-result:%s\\n' "$1"; }
'''
    setup += '\n'.join(f'{fn}() {{ echo {label}; }}' for label, fn in steps.items())
    result.append(('start-success', setup + '\nmagicnet_start_singbox_unlocked'))
    result.append(('candidate-success', setup + '\nmagicnet_prepare_singbox_candidate_unlocked'))
    result.append(('start-running', setup + '\nis_singbox_running() { return 0; }\nmagicnet_start_singbox_unlocked'))
    result.append(('start-unknown', setup + '\nis_singbox_running() { return 2; }\nmagicnet_start_singbox_unlocked'))
    result.append(('start-snapshot', setup + '\nMAGICNET_TRANSPARENT_RESTORED_CONFIG=1 magicnet_start_singbox_unlocked'))
    for label, fn in steps.items():
        for rc in [1, 2]:
            result.append((f'start-failure-{label}-{rc}', setup + f'\n{fn}() {{ echo {label}; return {rc}; }}\nmagicnet_start_singbox_unlocked'))
    for port in ['', '0', '01', '53', '9090', '65535', '65536', 'invalid']:
        result.append((f'api-port-{port}', f'magicnet_singbox_api_endpoint() {{ echo "127.0.0.1:{port}"; }}\nmagicnet_singbox_api_port'))
    for index, listener in enumerate([
        '', 'LISTEN 0 128 127.0.0.1:9090 0.0.0.0:* users:(("sing-box",pid=42,fd=3))',
        'LISTEN 0 128 [::1]:9090 [::]:* users:(("sing-box",pid=42,fd=3))',
        'LISTEN 0 128 127.0.0.1:19090 0.0.0.0:* users:(("sing-box",pid=42,fd=3))',
        'LISTEN 0 128 127.0.0.1:9090 0.0.0.0:* users:(("other",pid=142,fd=3))',
    ]):
        setup = f'magicnet_singbox_api_endpoint() {{ echo 127.0.0.1:9090; }}\nss() {{ printf "%s\\n" {quote(listener)}; }}\n'
        result.append((f'api-listener-{index}', setup + 'magicnet_singbox_api_listener_exists'))
        result.append((f'api-owned-{index}', setup + 'magicnet_singbox_listener_owned 42'))
    setup = '''
cp "$MODDIR/fixture.json" "$MODDIR/.config/sing-box/config.json"
rm -f "$MODDIR/.config/magicnet/"*list "$MODDIR/.config/magicnet/block.conf"
magicnet_warn() { printf 'warn:%s\\n' "$*"; }
'''
    policies = [
        ('empty', '', '', ''),
        ('suffix', 'news.invalid\nchat.invalid\nnews.invalid', '', ''),
        ('escaped', '雪.invalid\nquote"name.invalid\nback\\slash.invalid', '', ''),
        ('typed', '', 'DOMAIN,ad.invalid\nDOMAIN-SUFFIX,ads.invalid\nDOMAIN-KEYWORD,sponsor', ''),
        ('allow', '', 'DOMAIN,ad.invalid\nDOMAIN-SUFFIX,ads.invalid', 'DOMAIN,ad.invalid'),
        ('normalize', '', 'DOMAIN-SUFFIX,ads.invalid', 'DOMAIN-SUFFIX,https://Forum.Example.invalid.:443/path?source=test'),
        ('unsupported', '', 'PROCESS-NAME,unused\nDOMAIN-KEYWORD,sponsor', 'PROCESS-NAME,keep'),
        ('mixed', 'manual.invalid', 'DOMAIN,ad.invalid\nDOMAIN-SUFFIX,blocked.invalid', 'DOMAIN-SUFFIX,allowed.invalid'),
    ]
    for name, manual, community, allowed in policies:
        prepare = setup + f'''
printf '%s\\n' {quote(manual)} >"$MODDIR/.config/magicnet/block-domain-suffix.list"
printf '%s\\n' {quote(community)} >"$MODDIR/.config/magicnet/community-ban-rules.list"
printf '%s\\n' {quote(allowed)} >"$MODDIR/.config/magicnet/block-allow-rules.list"
'''
        for enabled in [0, 1]:
            conf = f'MAGICNET_BLOCK_ENABLED={enabled}\nMAGICNET_BLOCK_COMMUNITY_ENABLED=1\nMAGICNET_BLOCK_URL=https://example.invalid/rules\n'
            result.append((f'block-{name}-{enabled}', prepare + f'''
printf '%s' {quote(conf)} >"$MODDIR/.config/magicnet/block.conf"
magicnet_block_apply_singbox
printf 'apply_rc=%s\\n' "$?"
jq -cS . "$MODDIR/.config/sing-box/config.json"
magicnet_block_apply_singbox
printf 'repeat_rc=%s\\n' "$?"
jq -cS . "$MODDIR/.config/sing-box/config.json"
'''))
    for index, domains in enumerate(['', 'example.invalid', ' a.invalid \nb.invalid\na.invalid', '雪.invalid\nquote".invalid\nback\\slash.invalid']):
        for target in ['proxy', 'direct', 'block', 'warp']:
            result.append((f'route-{target}-{index}', setup + f'''
printf '%s\\n' {quote(domains)} >"$MODDIR/.config/magicnet/route-{target}-domain-suffix.list"
magicnet_route_apply_singbox
printf 'apply_rc=%s\\n' "$?"
jq -cS . "$MODDIR/.config/sing-box/config.json"
magicnet_route_apply_singbox
printf 'repeat_rc=%s\\n' "$?"
jq -cS . "$MODDIR/.config/sing-box/config.json"
'''))
    return result


def prepare_module(base: Path, checkout: Path) -> tuple[Path, Path]:
    module = base / 'module'
    (module / 'lib').mkdir(parents=True)
    (module / 'lib/magicnet').symlink_to(checkout / LIB, target_is_directory=True)
    (module / 'bin').mkdir()
    (module / 'bin/jq').symlink_to(shutil.which('jq') or '/usr/bin/jq')
    policy = module / '.config/magicnet'
    policy.mkdir(parents=True)
    (policy / 'network-policy.conf').write_text('''# fixture
MAGICNET_IPV6_MODE=prefer_ipv4
MAGICNET_DNS_CAPTURE_PORT=not a token
MAGICNET_DNS_CAPTURE_PORT= 5353
MAGICNET_UDP_TIMEOUT=15m
MAGICNET_TUN_MTU=1420
''')
    (module / '.state').mkdir()
    (module / '.config/sing-box').mkdir()
    (module / 'fixture.json').write_text(json.dumps({
        'outbounds': [{'type': 'selector', 'tag': 'ad-block', 'outbounds': ['direct'], 'default': 'direct'},
                      {'type': 'direct', 'tag': 'direct'}, {'type': 'block', 'tag': 'block'}],
        'route': {'rules': [{'action': 'sniff'},
                            {'domain': ['__magicnet_block__'], 'outbound': 'ad-block'},
                            {'domain': ['__magicnet_ad_allow__'], 'outbound': 'ad-allow'},
                            {'domain_suffix': ['__magicnet_route__', 'old.invalid'], 'outbound': 'proxy-rule'},
                            {'domain_suffix': ['lan'], 'outbound': 'lan'},
                            {'domain_keyword': ['adservice'], 'outbound': 'ad-block'}]},
    }, indent=2) + '\n')
    proc = base / 'proc'
    (proc / '101').mkdir(parents=True)
    return module, proc


def script_for(test_cases: list[tuple[str, str]]) -> str:
    source = '''
. "$MODDIR/lib/magicnet/primitives.sh"
. "$MODDIR/lib/magicnet/singbox_subscribe/common.sh"
. "$MODDIR/lib/magicnet/transparent_dns.sh"
. "$MODDIR/lib/magicnet/dns.sh"
. "$MODDIR/lib/magicnet/core.sh"
. "$MODDIR/lib/magicnet/api.sh"
. "$MODDIR/lib/magicnet/subscribe_bootstrap.sh"
. "$MODDIR/lib/magicnet/blocklist.sh"
. "$MODDIR/lib/magicnet/routes.sh"
'''
    for label, code in test_cases:
        source += f'\nprintf "CASE %s\\n" {quote(label)}\n(\n{code}\n) 2>&1\nprintf "\\nSTATUS %s\\n" "$?"\n'
    return source


def run(shell: list[str], script: str, checkout: Path, timeout: int = 90, *, compact: bool = False) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory(prefix='magicnet-shell-parity-') as name:
        base = Path(name)
        module, proc = prepare_module(base, checkout)
        if compact:
            fixture = module / 'fixture.json'
            fixture.write_text(json.dumps(json.loads(fixture.read_text()), separators=(',', ':')))
        cwd = base / 'empty'
        cwd.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(('MAGICNET_', 'MAGIC_', 'KAM_'))}
        env.update(MODDIR=str(module), PROC_FIXTURE=str(proc), LC_ALL='C')
        return subprocess.run(shell + ['-s'], input=script.encode(), cwd=cwd, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=True)


def benchmark(shell: list[str], checkout: Path, iterations: int) -> list[float]:
    # Selector rendering used to fork twice per node; use identical 128-node
    # UTF-8 inputs, shell, loop count and machine for both implementations.
    tags = '\n'.join(f'node-{i} 中继' for i in range(128))
    script = script_for([]) + f'\nvalue={quote(tags)}\nfor_test=0\nwhile [ "$for_test" -lt {iterations} ]; do\n magicnet_selector_tags_json "$value" fallback >/dev/null\n for_test=$((for_test + 1))\ndone\n'
    timings = []
    for _ in range(3):
        started = time.perf_counter()
        run(shell, script, checkout, timeout=180)
        timings.append((time.perf_counter() - started) * 1000)
    return timings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--benchmark', type=int, default=0, metavar='ITERATIONS')
    args = parser.parse_args()
    baseline = args.baseline.resolve()
    shells = {name: [shutil.which(name)] for name in ['bash', 'sh', 'mksh'] if shutil.which(name)}
    if shutil.which('busybox'):
        shells['busybox-ash'] = [shutil.which('busybox'), 'sh']
    test_cases = cases()
    script = script_for(test_cases)
    result = {'schema': 1, 'baseline': str(baseline), 'candidate': str(ROOT), 'cases_per_shell': len(test_cases), 'shells': {}}
    for name, command in shells.items():
        old = run(command, script, baseline)
        new = run(command, script, ROOT)
        if old.stdout != new.stdout or old.stderr != new.stderr:
            diff = ''.join(difflib.unified_diff(old.stdout.decode(errors='replace').splitlines(True),
                                                new.stdout.decode(errors='replace').splitlines(True),
                                                fromfile='baseline', tofile='candidate'))
            raise AssertionError(f'{name} behavior changed:\n{diff}\nstderr: {old.stderr!r} / {new.stderr!r}')
        compact = run(command, script, ROOT, compact=True)
        if compact.stdout != new.stdout or compact.stderr != new.stderr:
            raise AssertionError(f'{name} compact JSON changed policy behavior')
        entry = {'cases_passed': len(test_cases)}
        entry['compact_json_cases_passed'] = 32
        if args.benchmark:
            before = benchmark(command, baseline, args.benchmark)
            after = benchmark(command, ROOT, args.benchmark)
            entry['selector_128_nodes'] = {
                'iterations': args.benchmark, 'runs': 3,
                'baseline_ms': before, 'candidate_ms': after,
                'baseline_median_ms': statistics.median(before),
                'candidate_median_ms': statistics.median(after),
            }
        result['shells'][name] = entry
        print(f'{name}: {len(test_cases)} original-vs-rewrite cases passed')
    if args.report:
        args.report.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')


if __name__ == '__main__':
    main()
