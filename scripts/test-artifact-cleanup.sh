#!/bin/bash
set -Eeuo pipefail
handle_error() {
    local status="$1"
    local line="$2"
    printf 'artifact cleanup test failed at line %s (exit %s)\n' "$line" "$status" >&2
    exit "$status"
}
trap 'handle_error "$?" "$LINENO"' ERR

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
export KAM_PROJECT_ROOT="$test_root/project"
export KAM_HOOKS_ROOT="$test_root/hooks"
mkdir -p "$KAM_PROJECT_ROOT/dist" "$KAM_PROJECT_ROOT/scripts" "$KAM_HOOKS_ROOT/lib" \
    "$test_root/source/lib/kamfw" "$test_root/source/.config/sing-box"
printf '[prop]\nid = "MagicNet"\n' > "$KAM_PROJECT_ROOT/kam.toml"
printf '{}\n' > "$test_root/source/.config/sing-box/.dns-test.json"

removed_entries=(
    '.git/config'
    '.gitignore'
    '.gitattributes'
    '.gitmodules'
    '.github/workflows/development.yml'
    '.DS_Store'
    'Thumbs.db'
    'lib/kamfw/.git'
    'lib/kamfw/.gitignore'
    '.config/sing-box/.github/workflows/update.yml'
    '.config/sing-box/__pycache__/helper.cpython-313.pyc'
    '.config/sing-box/helper.pyc'
    '.config/sing-box/helper.pyo'
    '.config/sing-box/rules/sukka-chatgpt-voice.json'
    '.local/state/chatgpt-voice/upstream-revision'
    '.state/chatgpt-voice/upstream-revision'
    '.pytest_cache/state'
    '.mypy_cache/state'
    '.ruff_cache/state'
    'tests/test_module.py'
    '.config/sing-box/tests/test_rules.py'
    '.config/sing-box/test/data.json'
    'lib/kamfw/tests/shell/fixture.sh'
    'lib/kamfw/fixtures/input.json'
    'lib/kamfw/fixture/input.json'
    'webroot/__tests__/panel.test.js'
    'webroot/__fixtures__/state.json'
    'webroot/__snapshots__/panel.snap'
    'lib/bench/runner.sh'
    'lib/benches/runner.sh'
    'lib/benchmark/runner.sh'
    'lib/benchmarks/runner.sh'
    'coverage/report.json'
    'htmlcov/index.html'
    'webroot/node_modules/runtime/index.js'
)
preserved_entries=(
    'module.prop'
    '.envrc'
    '.config/kamfw/.envrc'
    'lib/kamfw/.envrc'
    'lib/kamfw/.kamfwrc'
    'lib/kamfw/__singbox__.sh'
    'lib/kamfw/__runtime__.sh'
    'LICENSE'
    'lib/kamfw/LICENSE'
    '.config/sing-box/config.json'
    '.config/sing-box/rules/custom.json'
    '.config/sing-box/rules/meta-openai.srs'
    '.state/machines/network.state'
    '.state/chatgpt-voice-custom/upstream-revision'
    '.local/state/chatgpt-voice-custom/upstream-revision'
    'customize.sh'
    'service.sh'
    'webroot/index.html'
    'bin/magicnet-cli'
    'bin/sing-box'
    'bin/curl'
    'licenses/curl/build-provenance.json'
    'licenses/curl/curl-COPYING.txt'
    'licenses/curl/OpenSSL-LICENSE.txt'
    'licenses/curl/zlib-README.txt'
    'licenses/curl/Mozilla-CA-NOTICE.txt'
    'bin/test'
    '.config/sing-box/rules/test.srs'
    'lib/kamfw/test-support.sh'
    'webroot/contest.js'
)
for entry in "${removed_entries[@]}" "${preserved_entries[@]}"; do
    mkdir -p "$(dirname "$test_root/source/$entry")"
    printf 'fixture: %s\n' "$entry" > "$test_root/source/$entry"
done
mkdir -p "$test_root/source/lib/kamfw/empty/tests"
printf 'id=MagicNet\nversion=v1.0.0\nversionCode=1\n' > "$test_root/source/module.prop"
printf '#!/system/bin/sh\nimport rich\n' > "$test_root/source/customize.sh"
# This exact shape used to trigger an archive-time kamfw source rewrite. The
# sanitizer may remove unwanted entries, but must never patch dependency code.
cat > "$test_root/source/lib/kamfw/__singbox__.sh" <<'FIXTURE'
awk '
    {
            if (current ~ /^[[:space:]]*"interrupt_exist_connections"[[:space:]]*:/) {
                sub(/:[[:space:]]*(true|false)/, ": true", current)
            }
    }
'
FIXTURE
cat > "$KAM_HOOKS_ROOT/lib/utils.sh" <<'FIXTURE'
log_info() { :; }
require_command() { command -v "$1" >/dev/null; }
FIXTURE
printf '#!/bin/bash\nexit 0\n' > "$KAM_PROJECT_ROOT/scripts/package-smoke.sh"
chmod +x "$KAM_PROJECT_ROOT/scripts/package-smoke.sh"
artifact="$KAM_PROJECT_ROOT/dist/MagicNet.zip"
sanitize_hooks=("$repo_root"/hooks/post-build/*.sanitize_zip.sh)
test "${#sanitize_hooks[@]}" -eq 1
sanitize_hook="${sanitize_hooks[0]}"

make_archive() {
    rm -f "$artifact"
    (cd "$test_root/source" && zip -qr "$artifact" .)
}
make_archive
bash "$sanitize_hook"
if unzip -Z1 "$artifact" | grep -Fq '.dns-test.json'; then
    echo 'Archive cleanup did not remove its fixture' >&2
    exit 1
fi

# Cleanup removes development data without changing runtime, dependency, or license bytes.
unzip -Z1 "$artifact" > "$test_root/archive-entries"
for entry in "${removed_entries[@]}"; do
    if grep -Fxq "$entry" "$test_root/archive-entries"; then
        printf 'Development file survived archive cleanup: %s\n' "$entry" >&2
        exit 1
    fi
done
if grep -Eq '(^|/)(tests?|__tests__|fixtures?|__fixtures__|__snapshots__|bench|benches|benchmarks?|coverage|htmlcov|node_modules)/' "$test_root/archive-entries"; then
    echo 'Development directory survived archive cleanup' >&2
    exit 1
fi
if grep -Eq '^(\.state|\.local/state)/chatgpt-voice(/|$)' "$test_root/archive-entries"; then
    echo 'Retired ChatGPT Voice state directory survived archive cleanup' >&2
    exit 1
fi
for entry in "${preserved_entries[@]}"; do
    unzip -p "$artifact" "$entry" > "$test_root/preserved-entry"
    cmp "$test_root/source/$entry" "$test_root/preserved-entry"
done
# A second pass must preserve the sanitized archive byte for byte.
cp "$artifact" "$test_root/clean.zip"
bash "$sanitize_hook"
cmp "$artifact" "$test_root/clean.zip"

# Exercise the release sequence on the sanitized ZIP. Binary/helper payloads
# are inert fixtures: this checks the actual archive transforms, not Android.
printf 'inert component helper fixture\n' > "$test_root/component-helper"
python3 "$repo_root/scripts/package-components.py" "$artifact" \
    --helper "$test_root/component-helper" --output "$test_root/components"
python3 - "$test_root/source" "$test_root/components" "${preserved_entries[@]}" <<'PY'
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile

source, output = map(Path, sys.argv[1:3])
development = {
    'test', 'tests', '__tests__', 'fixture', 'fixtures', '__fixtures__',
    '__snapshots__', 'bench', 'benches', 'benchmark', 'benchmarks',
    'coverage', 'htmlcov', 'node_modules', '.git', '.github', '__pycache__',
    '.pytest_cache', '.mypy_cache', '.ruff_cache',
}
manifest = json.loads((output / 'components.json').read_text())
archives = list(output.glob('*.zip'))
assert len(archives) == len(manifest['components']) + 4
members = 0
for path in archives:
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None, path
        for info in archive.infolist():
            parts = PurePosixPath(info.filename.rstrip('/')).parts
            directories = parts if info.is_dir() else parts[:-1]
            assert development.isdisjoint(directories), (path.name, info.filename)
            members += 1
with zipfile.ZipFile(output / 'MagicNet-full.zip') as full:
    for name in sys.argv[3:]:
        if name != 'customize.sh':  # The splitter inserts the component bootstrap.
            assert full.read(name) == (source / name).read_bytes(), name
    assert full.read('customize.sh').count(b'# Component bootstrap:') == 1
for component in manifest['components']:
    for item in component['files']:
        assert development.isdisjoint(PurePosixPath(item['path']).parts[:-1]), item['path']
print(f'Final archive inspection passed: {len(archives)} ZIPs, {members} entries')
PY

# Refuse to continue when zip cannot remove an unwanted entry.
make_archive
mkdir -p "$test_root/failing-bin"
printf '#!/bin/sh\nexit 1\n' > "$test_root/failing-bin/zip"
chmod +x "$test_root/failing-bin/zip"
if PATH="$test_root/failing-bin:$PATH" bash "$sanitize_hook" > "$test_root/failure.log" 2>&1; then
    echo 'Archive cleanup ignored a failed deletion' >&2
    exit 1
fi
grep -Fq 'Failed to remove archive entry:' "$test_root/failure.log"
printf 'Artifact cleanup and integrity checks passed\n'
