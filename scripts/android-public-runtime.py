#!/usr/bin/env python3
"""Prepare and attest a disposable AVD after the offline uninstall test.

The handoff is a host CI report, not a second device state interface. The
prepared consumer checks current facts; a saved successful report is not proof.
"""
from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile
import zipfile

SPEC = importlib.util.spec_from_file_location(
    'public_runtime_simulation', Path(__file__).with_name('android-device-simulation.py'))
SIM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIM)
SCOPE = 'disposable-x86_64-public-runtime'
SHA = re.compile(r'[0-9a-f]{64}')
MAX_REPORT_BYTES = 1024 * 1024
PUBLIC_PROVENANCE = '.ci-public-fixture.json'
CURL_SCOPE = 'production-android-curl'


def public_curl():
    """Use the same pinned production build/ABI verifier as offline acceptance."""
    return SIM.verified_curl_build(Path(os.environ['MAGICNET_PUBLIC_CURL_DIR']))


def augment_public_archive(base, destination, curl, addon):
    """Keep the production curl and offline marker intact; add only public attestation."""
    marker = (json.dumps(addon, sort_keys=True) + '\n').encode()
    require(len(marker) <= MAX_REPORT_BYTES, 'curl_marker_budget')
    temporary = destination.with_name(destination.name + '.partial')
    try:
        with zipfile.ZipFile(base) as source, zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as output:
            names = source.namelist()
            require(len(names) == len(set(names))
                    and PUBLIC_PROVENANCE not in names, 'curl_fixture_collision')
            require(names.count('bin/curl') == 1, 'production_curl_missing')
            entry = source.getinfo('bin/curl')
            require(stat.S_ISREG(entry.external_attr >> 16)
                    and stat.S_IMODE(entry.external_attr >> 16) == 0o755
                    and entry.file_size == curl.stat().st_size
                    and hashlib.sha256(source.read(entry)).hexdigest() == SIM.digest(curl),
                    'production_curl_identity_mismatch')
            for original in source.infolist():
                output.writestr(copy.copy(original), source.read(original))
            entry = zipfile.ZipInfo(PUBLIC_PROVENANCE)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            output.writestr(entry, marker)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(marker).hexdigest()


def verify_curl_capabilities(device):
    spec = importlib.util.spec_from_file_location(
        'public_curl_proof', Path(__file__).with_name('android-public-curl-proof.py'))
    proof = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proof)
    result = proof.verify(device)
    require(isinstance(result, dict) and type(result.get('schema')) is int
            and result['schema'] == 1 and result.get('status') == 'verified'
            and all(result.get(name) is True for name in
                    ('https', 'ssl', 'resolve', 'gzip', 'tls_positive',
                     'hostname_reject', 'default_trust_reject', 'embedded_ca_identity', 'cleanup')),
            'curl_capability_unknown')
    return result


def require(value, code):
    if not value:
        raise RuntimeError(code)


def read_json(path):
    require(path.is_file() and path.stat().st_size <= MAX_REPORT_BYTES, 'report_unavailable')
    return json.loads(path.read_text(), object_pairs_hook=SIM.unique_keys)


def atomic_report(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    require(len(data) <= MAX_REPORT_BYTES, 'report_budget')
    fd, name = tempfile.mkstemp(prefix='.prepared-runtime-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def inputs():
    source_sha = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch(r'[0-9a-f]{40}', source_sha) is not None, 'source_unknown')
    source = Path(os.environ.get('MAGICNET_MODULE_ZIP', str(SIM.ROOT / 'dist/MagicNet.zip')))
    replacements = {
        'bin/magicnet-cli': Path(os.environ['MAGICNET_X86_CLI']),
        'bin/sing-box': Path(os.environ['MAGICNET_X86_SINGBOX']),
    }
    tools = Path(os.environ['MAGICNET_X86_TOOLS'])
    replacements.update({f'bin/{name}': tools / name for name in ('jq', 'yq')})
    with zipfile.ZipFile(source) as archive:
        replacements.update({name: tools / Path(name).name for name in SIM.OPTIONAL_PAYLOADS
                             if name in archive.namelist()})
    curl, curl_metadata, curl_build = public_curl()
    replacements['bin/curl'] = curl
    return source, replacements, source_sha, curl_metadata, curl_build


def current_archive(work):
    source, replacements, source_sha, curl_metadata, curl_build = inputs()
    baseline = work / 'MagicNet-base-x86_64.zip'
    archive = work / 'MagicNet-public-x86_64.zip'
    provenance = SIM.prepare_archive(source, baseline, replacements, curl_metadata=curl_metadata)
    curl = replacements['bin/curl']
    with zipfile.ZipFile(baseline) as stream:
        marker_sha = hashlib.sha256(stream.read(SIM.PROVENANCE)).hexdigest()
    addon = {'schema': 1, 'scope': CURL_SCOPE, 'source_sha': source_sha,
             'base_marker_sha256': marker_sha, 'curl_build': curl_build}
    public_marker_sha = augment_public_archive(baseline, archive, curl, addon)
    with zipfile.ZipFile(archive) as stream:
        required = {'module.prop', 'service.sh', 'boot-completed.sh'}
        require(required <= set(stream.namelist()), 'module_identity_missing')
        static_files = {}
        for entry in stream.infolist():
            if entry.filename in required or (entry.filename.startswith('lib/')
                                               and not entry.is_dir()):
                require(stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG),
                        'module_identity_ambiguous')
                static_files[entry.filename] = hashlib.sha256(stream.read(entry)).hexdigest()
        require(3 <= len(static_files) <= 2048, 'module_identity_budget')
        marker_sha = hashlib.sha256(stream.read(SIM.PROVENANCE)).hexdigest()
    expected = {
        'source_sha': source_sha,
        'production_zip_sha256': provenance['production_zip_sha256'],
        'base_fixture_zip_sha256': provenance['fixture_zip_sha256'],
        'fixture_zip_sha256': SIM.digest(archive),
        'payload_sha256': provenance['payload_sha256'],
        'extra_payload_sha256': {},
        'metadata_sha256': provenance['metadata_sha256'],
        'curl_build': curl_build,
        'static_files_sha256': static_files,
        'marker_sha256': marker_sha,
        'public_marker_sha256': public_marker_sha,
        'ksud_sha256': SIM.digest(Path(os.environ['MAGICNET_KSUD_HOST'])),
        'probe_apk_sha256': SIM.digest(Path(os.environ['MAGICNET_NETWORK_PROBE_APK'])),
    }
    return archive, expected


def manifest_for_current():
    with tempfile.TemporaryDirectory(prefix='magicnet-public-identity-') as directory:
        return current_archive(Path(directory))[1]


def validate_offline(path, expected):
    report = read_json(path)
    require(isinstance(report, dict) and type(report.get('schema')) is int
            and report['schema'] == 1 and report.get('status') == 'passed', 'offline_not_passed')
    cases = report.get('cases')
    require(isinstance(cases, list) and len(cases) == len(SIM.PHASES)
            and {case.get('name') for case in cases if isinstance(case, dict)} == set(SIM.PHASES)
            and all(isinstance(case, dict) and case.get('status') == 'passed' for case in cases),
            'offline_incomplete')
    provenance = report.get('provenance', {})
    require(isinstance(provenance, dict)
            and all(provenance.get(key) == expected[key] for key in
                    ('source_sha', 'production_zip_sha256', 'payload_sha256', 'metadata_sha256')),
            'offline_source_mismatch')
    require(provenance.get('kernelsu', {}).get('mode') == 'pinned-kernel-userspace-late-load',
            'offline_kernel_unknown')


def read_hashes(device, paths, *, privileged):
    require(len(paths) == len(set(paths)) and len(paths) <= 4096, 'hash_budget')
    result = {}
    for start in range(0, len(paths), 24):
        batch = paths[start:start + 24]
        command = '/system/bin/sha256sum ' + ' '.join(shlex.quote(path) for path in batch)
        cp = (device.kshell if privileged else device.shell)(command, timeout=15, check=False)
        require(cp.returncode == 0, 'hash_unavailable')
        for line in cp.stdout.splitlines():
            parts = line.split(maxsplit=1)
            require(len(parts) == 2 and SHA.fullmatch(parts[0]) is not None, 'hash_unknown')
            path = parts[1].lstrip('*')
            require(path in batch and path not in result, 'hash_ambiguous')
            result[path] = parts[0]
        require(set(batch) <= set(result), 'hash_incomplete')
    return result


def guard_environment(device, *, installed):
    # No verified=True until every read-only identity fact has been checked.
    device.wait_boot()
    require(device.shell('getprop ro.kernel.qemu').stdout.strip() == '1', 'physical_device')
    require(device.shell('getprop ro.product.cpu.abi').stdout.strip() == 'x86_64', 'abi_mismatch')
    require(device.shell('getenforce').stdout.strip() == 'Enforcing', 'selinux_unknown')
    require(device.shell('id -u').stdout.strip() == '0', 'adbd_not_root')
    actual = read_hashes(device, [SIM.KSUD], privileged=False)[SIM.KSUD]
    require(actual == SIM.digest(Path(os.environ['MAGICNET_KSUD_HOST'])), 'ksud_identity_mismatch')
    version = device.shell(SIM.KSUD + ' debug version', check=False)
    require(version.returncode == 0
            and re.fullmatch(r'Kernel Version: [1-9][0-9]*', version.stdout.strip()) is not None,
            'native_kernel_unknown')
    device.verified = True
    require(device.kshell('id -Z').stdout.strip() == SIM.KSU_DOMAIN, 'ksu_domain_unknown')
    require(device.kshell('getenforce').stdout.strip() == 'Enforcing', 'selinux_unknown')
    if installed:
        device.kshell(f'test -d {SIM.MOD} && test ! -e {SIM.STAGED} && '
                      f'test ! -e {SIM.MOD}/disable && test ! -e {SIM.MOD}/remove')
    else:
        device.kshell(f'test ! -e {SIM.MOD} && test ! -e {SIM.STAGED}')


def generation(device):
    pids = device.kshell(SIM.BB + ' pidof sing-box', check=False)
    words = pids.stdout.split()
    require(pids.returncode == 0 and len(words) == 1
            and re.fullmatch(r'[1-9][0-9]{0,9}', words[0]) is not None
            and int(words[0]) <= 2147483647, 'core_identity_unknown')
    pid = words[0]
    record = device.kshell(f'cat /proc/{pid}/stat').stdout
    closing = record.rfind(')')
    tail = record[closing + 1:].split()
    require(record.startswith(pid + ' (') and closing > len(pid) + 1 and len(tail) >= 20
            and re.fullmatch(r'[0-9]+', tail[19]) is not None, 'core_generation_unknown')
    boot = device.shell('cat /proc/sys/kernel/random/boot_id').stdout.strip()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot) is not None,
            'boot_identity_unknown')
    return pid, tail[19], boot


def observe_runtime(device, expected):
    paths = {SIM.MOD + '/' + key: value for section in
             ('payload_sha256', 'extra_payload_sha256', 'metadata_sha256', 'static_files_sha256')
             for key, value in expected[section].items()}
    paths[SIM.MOD + '/' + SIM.PROVENANCE] = expected['marker_sha256']
    paths[SIM.MOD + '/' + PUBLIC_PROVENANCE] = expected['public_marker_sha256']
    curl = SIM.MOD + '/bin/curl'
    device.kshell(f'test -f {curl} && test ! -L {curl} && test -x {curl}')
    device.kshell('test -z "${CURL_CA_BUNDLE+x}" && test -z "${SSL_CERT_FILE+x}" && '
                  'test -z "${SSL_CERT_DIR+x}"')
    require(read_hashes(device, list(paths), privileged=True) == paths, 'module_identity_mismatch')
    require(device.kshell('readlink ' + SIM.MOD + '/cli').stdout.strip() == 'bin/magicnet-cli',
            'cli_alias_mismatch')
    first = generation(device)
    pid = first[0]
    require(device.kshell(f'readlink /proc/{pid}/exe').stdout.strip() == SIM.MOD + '/bin/sing-box',
            'core_executable_unknown')
    domain = device.kshell(f'cat /proc/{pid}/attr/current').stdout.removesuffix('\n').removesuffix('\r')
    require(domain in (SIM.KSU_DOMAIN, SIM.KSU_DOMAIN + '\x00'), 'core_domain_unknown')
    device.kshell(f'{SIM.BB} test /proc/{pid}/exe -ef {SIM.MOD}/bin/sing-box')
    require(read_hashes(device, [f'/proc/{pid}/exe'], privileged=True)[f'/proc/{pid}/exe']
            == expected['payload_sha256']['bin/sing-box'], 'core_payload_mismatch')
    status = device.kshell(SIM.MOD + '/cli --json service status').stdout
    require(SIM.is_ready(status), 'runtime_not_ready')
    data = SIM.decode_status(status, 'service.status')
    transparent = data.get('transparent', {})
    require(data.get('core', {}).get('selected') == 'sing-box'
            and transparent.get('configured_mode') == 'tun'
            and transparent.get('effective_mode') == 'tun'
            and transparent.get('effective_type') == 'tun'
            and transparent.get('transition') == 'idle', 'runtime_mode_unknown')
    device.kshell('ip link show magicnet0')
    apk = device.shell('pm path best.lmm.magicnet.probe').stdout.strip()
    require(re.fullmatch(r'package:/data/app/[^\s]+/base\.apk', apk) is not None,
            'probe_identity_unknown')
    apk_path = apk.removeprefix('package:')
    require(read_hashes(device, [apk_path], privileged=False)[apk_path] == expected['probe_apk_sha256'],
            'probe_payload_mismatch')
    package = device.shell('cmd package list packages -U best.lmm.magicnet.probe').stdout.strip()
    require(re.fullmatch(r'package:best\.lmm\.magicnet\.probe uid:[1-9][0-9]{4,9}', package) is not None,
            'probe_uid_unknown')
    capabilities = verify_curl_capabilities(device)
    require(generation(device) == first, 'core_generation_changed')
    # No PID, boot ID, argv or raw command output is retained in the handoff.
    token = hashlib.sha256(':'.join(first).encode()).hexdigest()
    return {'generation_sha256': token, 'ready': True, 'identity_verified': True,
            'curl_capabilities': capabilities}


def prepare(device, archive, expected, work):
    device.identify()  # Real disposable AVD checks precede root and mutation.
    guard_environment(device, installed=False)
    device.late_load_on_reboot = True
    device.shell('mkdir -p ' + SIM.REMOTE)
    device.run('push', str(archive), SIM.REMOTE + '/module.zip', timeout=120)
    device.kshell(f'MAGICNET_NONINTERACTIVE=1 {SIM.KSUD} module install {SIM.REMOTE}/module.zip', timeout=180)
    target = device.kshell(f'if [ -d {SIM.STAGED} ]; then echo {SIM.STAGED}; else echo {SIM.MOD}; fi').stdout.strip()
    require(target in (SIM.STAGED, SIM.MOD), 'install_destination_unknown')
    staged = {target + '/' + key: value for section in ('payload_sha256', 'extra_payload_sha256', 'metadata_sha256')
              for key, value in expected[section].items()}
    device.kshell(f'test -f {target}/bin/curl && test ! -L {target}/bin/curl && test -x {target}/bin/curl')
    require(read_hashes(device, list(staged), privileged=True) == staged, 'staged_payload_mismatch')
    config = work / 'offline-config.json'
    config.write_text(json.dumps(SIM.fixture_config()) + '\n')
    config.chmod(0o600)
    device.run('push', str(config), SIM.REMOTE + '/config.json')
    device.kshell(f'cp {SIM.REMOTE}/config.json {target}/.config/sing-box/config.json && '
                  f'chmod 0600 {target}/.config/sing-box/config.json && '
                  f'printf "validated\\n" >{target}/.config/sing-box/standalone-config && '
                  f'{target}/bin/sing-box check -c {target}/.config/sing-box/config.json')
    device.reboot()  # Native KernelSU userspace lifecycle owns activation.
    device.ready()
    guard_environment(device, installed=True)
    observation = observe_runtime(device, expected)
    device.kshell('rm -f ' + SIM.REMOTE + '/module.zip ' + SIM.REMOTE + '/config.json')
    return observation


def verify_with_expected(output, expected, *, strict_generation):
    report = read_json(output / 'prepared-runtime.json')
    require(isinstance(report, dict) and type(report.get('schema')) is int
            and report['schema'] == 1 and report.get('scope') == SCOPE
            and report.get('status') == 'READY'
            and report.get('expected') == expected, 'handoff_mismatch')
    previous = report.get('observation')
    require(isinstance(previous, dict) and previous.get('ready') is True
            and previous.get('identity_verified') is True
            and isinstance(previous.get('generation_sha256'), str)
            and SHA.fullmatch(previous['generation_sha256']) is not None, 'handoff_unknown')
    device = SIM.Device()
    guard_environment(device, installed=True)
    observation = observe_runtime(device, expected)
    if strict_generation:
        require(previous == observation, 'handoff_generation_changed')
    return device, expected, observation


def verify_prepared(output, *, strict_generation=True):
    """Attest a current runtime, explicitly allowing a config-induced restart.

    The benchmark's live mode still checks current bytes/inode/domain/readiness
    and a stable process generation. It never treats an old handoff as readiness.
    """
    require(output.is_dir(), 'report_unavailable')
    with (output / '.prepared-runtime.lock').open('a') as lock:
        os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('output_busy') from None
        expected = manifest_for_current()
        return verify_with_expected(output, expected, strict_generation=strict_generation)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'verify', 'verify-live'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--simulation-report', type=Path)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.chmod(0o700)
    # Never unlink the lock inode. A second process must not reset its owner's report.
    with (args.output / '.prepared-runtime.lock').open('a') as lock:
        os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('[public-runtime] error=output_busy')
            return 2
        report_path = args.output / 'prepared-runtime.json'
        if args.operation == 'prepare':
            atomic_report(report_path, {'schema': 1, 'scope': SCOPE,
                                       'status': 'INCOMPLETE', 'reason': 'preparation_pending'})
        try:
            with tempfile.TemporaryDirectory(prefix='magicnet-public-runtime-') as directory:
                work = Path(directory)
                archive, expected = current_archive(work)
                if args.operation == 'prepare':
                    require(args.simulation_report is not None, 'offline_report_required')
                    validate_offline(args.simulation_report, expected)
                    observation = prepare(SIM.Device(), archive, expected, work)
                    atomic_report(report_path, {'schema': 1, 'scope': SCOPE, 'status': 'READY',
                                               'expected': expected, 'observation': observation})
                else:
                    verify_with_expected(args.output, expected,
                                         strict_generation=args.operation == 'verify')
            print('[public-runtime] status=verified')
            return 0
        except (Exception, KeyboardInterrupt) as error:
            code = str(error) if isinstance(error, RuntimeError) else 'observation_unknown'
            if re.fullmatch(r'[a-z_]{1,64}', code) is None:
                code = 'observation_unknown'
            if args.operation == 'prepare':
                atomic_report(report_path, {'schema': 1, 'scope': SCOPE, 'status': 'FAIL', 'reason': code})
            print('[public-runtime] error=' + code)
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
