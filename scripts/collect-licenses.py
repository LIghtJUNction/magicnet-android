#!/usr/bin/env python3
"""Copy original license/notice texts for the locked Go module graphs.

Run scripts/download-license-sources.py first. This command uses the existing
module cache offline and never executes downloaded module code.
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DESTINATION = ROOT / 'assets/licenses/dependencies'
GO = ROOT / '.tools/go/bin/go'

def objects(text):
    decoder = json.JSONDecoder()
    while text.strip():
        text = text.lstrip()
        value, end = decoder.raw_decode(text)
        yield value
        text = text[end:]

def notices(directory):
    name_pattern = re.compile(r'^(?:LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT|PATENTS|AUTHORS)(?:[._-].*)?$', re.IGNORECASE)
    source_suffixes = {'.go', '.rs', '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.js', '.ts', '.jsx', '.tsx', '.py', '.sh', '.java', '.kt', '.m', '.mm', '.s', '.asm', '.cs', '.swift', '.rb', '.php', '.sql', '.ex', '.erl', '.dart', '.wasm', '.zip', '.png', '.svg', '.jpg', '.pdf'}
    result = []
    for file in directory.rglob('*'):
        if file.is_file() and not file.is_symlink() and file.suffix.lower() not in source_suffixes and (name_pattern.fullmatch(file.name) or any(part.upper() in {'LICENSES', 'LICENCES'} for part in file.relative_to(directory).parts[:-1])):
            result.append(file)
    return sorted(result)

def main():
    env = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', GOMODCACHE=str(ROOT / '.tools/gomodcache'), GOCACHE=str(ROOT / '.tools/gocache'))
    modules = {}
    linked = set()
    for target in ['linux-amd64', 'android-arm64']:
        for name in ['magicnet-cli', 'magicnet-installer', 'sing-box']:
            text = subprocess.check_output([str(GO), 'version', '-m', str(ROOT / 'assets/bin' / target / name)], text=True)
            for line in text.splitlines():
                fields = line.split()
                if len(fields) >= 3 and fields[0] == 'dep':
                    linked.add((fields[1], fields[2]))
    for owner, directory in [('control', ROOT), ('core', ROOT / 'third_party/sing-box')]:
        text = subprocess.check_output([str(GO), 'list', '-m', '-json', 'all'], cwd=directory, env=env, text=True)
        for item in objects(text):
            if item.get('Main'):
                continue
            replacement = item.get('Replace')
            actual = replacement or item
            cache_path = actual.get('Dir')
            if not cache_path and actual.get('Version'):
                escaped = ''.join('!' + char.lower() if 'A' <= char <= 'Z' else char for char in actual['Path'] + '@' + actual['Version'])
                candidate = ROOT / '.tools/gomodcache' / escaped
                if candidate.is_dir():
                    cache_path = str(candidate)
            key = item['Path'] + '@' + item.get('Version', '')
            if replacement:
                key += '=>' + actual['Path'] + '@' + actual.get('Version', 'tracked-core-tree')
            if key not in modules:
                modules[key] = {
                    'module': item['Path'], 'version': item.get('Version'),
                    'replacement': actual['Path'] if replacement else None,
                    'replacement_version': actual.get('Version') if replacement else None,
                    'directory': cache_path, 'owners': [],
                }
            modules[key]['owners'].append(owner)
    records, missing, absent_nonruntime = [], [], []
    with tempfile.TemporaryDirectory(prefix='licenses-', dir=ROOT / '.tools') as temporary:
        stage = pathlib.Path(temporary)
        for identity, item in sorted(modules.items()):
            if not item['directory']:
                missing.append(identity + ': source not downloaded')
                continue
            directory = pathlib.Path(item['directory'])
            sources = notices(directory)
            if not sources:
                if (item['module'], item['version']) in linked:
                    missing.append(identity + ': linked runtime has no license or notice text')
                else:
                    record = {key: value for key, value in item.items() if key != 'directory'}
                    record.update(identity=identity, files=[], linked_runtime=False, notice_status='No notice in pinned module archive; not linked in any inspected distributed Go binary; module source is not bundled in the runtime package')
                    records.append(record)
                    absent_nonruntime.append(identity)
                continue
            slug = hashlib.sha256(identity.encode()).hexdigest()[:20]
            files = []
            for file in sources:
                data = file.read_bytes()
                assert 0 < len(data) <= 4 * 1024 * 1024
                relative = file.relative_to(directory)
                assert b'\0' not in data, 'A notice candidate is not a text document'
                # Preserve the original text and source path, while ensuring a
                # notice directory can never become an executable source package.
                delivered = relative if relative.suffix.lower() == '.txt' else relative.with_name(relative.name + '.txt')
                target = stage / slug / delivered
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                files.append({'path': slug + '/' + delivered.as_posix(), 'source_path': relative.as_posix(), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
            record = {key: value for key, value in item.items() if key != 'directory'}
            record['identity'] = identity
            record['linked_runtime'] = (item['module'], item['version']) in linked
            record['files'] = files
            records.append(record)
        if missing:
            print(json.dumps({'missing': missing}, indent=2))
            raise SystemExit('License collection incomplete; no existing distribution notices were replaced.')
        index = {'schema': 1, 'scope': 'Union of controller and approved fixed-core Go module graphs; original texts, including transitive and optional module notices; file paths preserve notice scope', 'linked_runtime_notices_complete': True, 'nonruntime_without_notice': absent_nonruntime, 'modules': records}
        (stage / 'index.json').write_text(json.dumps(index, indent=2) + '\n')
        DESTINATION.parent.mkdir(parents=True, exist_ok=True)
        if DESTINATION.exists():
            shutil.rmtree(DESTINATION)
        shutil.copytree(stage, DESTINATION)
    print(json.dumps({'modules': len(records), 'notice_files': sum(len(item['files']) for item in records), 'bytes': sum(f['bytes'] for item in records for f in item['files']), 'nonruntime_without_notice': absent_nonruntime}))

if __name__ == '__main__':
    main()
