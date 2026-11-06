#!/bin/bash
# Remove development data and normalize only the owned curl payload modes.
set -euo pipefail
# shellcheck source=hooks/lib/utils.sh
. "$KAM_HOOKS_ROOT/lib/utils.sh"

module_id="$(sed -n 's/^id[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$KAM_PROJECT_ROOT/kam.toml" | head -n1)"
zip_path="${KAM_PROJECT_ROOT}/dist/${module_id}.zip"
[ -f "$zip_path" ] || exit 0
require_command zip "zip not found!"
require_command unzip "unzip not found!"

# Runtime .envrc/.kamfwrc and names such as bin/test or test.srs remain valid.
patterns=(
    '(^|/)\.git($|/)'
    '(^|/)(\.github|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache)(/|$)'
    '(^|/)(\.gitignore|\.gitattributes|\.gitmodules|\.DS_Store|Thumbs\.db)$|\.py[co]$'
    '(^|/)(tests?|__tests__|fixtures?|__fixtures__|__snapshots__|bench|benches|benchmarks?|coverage|htmlcov|node_modules)/'
    '^\.local/subscriptions\.env$'
    '(^|/)(mihomo|__mihomo__)(\.sh)?($|/)'
    '^bin/magicnet-ebpf$'
    '^\.config/sing-box/\.dns-.*\.json$'
    '^\.config/sing-box/rules/sukka-chatgpt-voice\.json$|^(\.state|\.local/state)/chatgpt-voice(/|$)'
)
entries="$(unzip -Z1 "$zip_path")"
pattern="$(IFS='|'; printf '%s' "${patterns[*]}")"
removed="$(printf '%s\n' "$entries" | grep -E "$pattern" || true)"
if [ -n "$removed" ]; then
    log_info "Removing development and retired files from module artifact"
    if ! printf '%s\n' "$removed" | zip -q -d "$zip_path" -@ >/dev/null 2>&1; then
        printf 'Failed to remove archive entry: cleanup batch\n' >&2
        exit 1
    fi
fi
python3 "$KAM_PROJECT_ROOT/scripts/android-curl-artifact.py" normalize-modes "$zip_path"
"${KAM_PROJECT_ROOT}/scripts/package-smoke.sh" "$zip_path"
