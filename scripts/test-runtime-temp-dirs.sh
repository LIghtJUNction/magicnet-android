#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
first='' second=''
cleanup() {
    for pid in "$first" "$second"; do
        [ -n "$pid" ] || continue
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$work"
}
trap cleanup EXIT
export MODDIR="$work/module" KAM_HOME="$work/module"
mkdir -p "$MODDIR/tmp"
. "$root/src/MagicNet/lib/kamfw/init_dirs.sh"
. "$root/src/MagicNet/lib/kamfw/__runtime__.sh"
. "$root/src/MagicNet/lib/magicnet/runtime_dirs.sh"
. "$root/src/MagicNet/.config/kamfw/.envrc"
kam_init_dirs --required
kamfw_init_home
magicnet_prepare_runtime_dirs
[ ! -e "$MODDIR/tmp" ] && [ ! -e "$MODDIR/.tmp" ]
[ "$TMPDIR" = "$MODDIR/.cache" ]
[ "$(stat -c '%a' "$MODDIR/.cache")" = 700 ]
[ "$(stat -c '%a' "$MODDIR/.state")" = 700 ]

# Existing metadata, payloads and dotfiles survive merging both legacy roots.
# Canonical values win conflicts and the old contents remain private recovery data.
mkdir -p "$MODDIR/.local/state/tools" "$MODDIR/.tmp/webui-payload" "$MODDIR/.state/tools"
printf 'old-version' >"$MODDIR/.local/state/tools/yq.version"
printf 'new-version' >"$MODDIR/.state/tools/yq.version"
printf 'rule-digest' >"$MODDIR/.local/state/.rule-hash"
printf 'private-json' >"$MODDIR/.tmp/webui-payload/config.json"
chmod 600 "$MODDIR/.tmp/webui-payload/config.json"
magicnet_migrate_runtime_dirs
[ ! -e "$MODDIR/.local/state" ] && [ ! -e "$MODDIR/.local" ] && [ ! -e "$MODDIR/.tmp" ]
[ "$(cat "$MODDIR/.state/tools/yq.version")" = new-version ]
[ "$(cat "$MODDIR/.state/.rule-hash")" = rule-digest ]
[ "$(cat "$MODDIR/.cache/webui-payload/config.json")" = private-json ]
[ "$(stat -c '%a' "$MODDIR/.cache/webui-payload/config.json")" = 600 ]
[ "$(cat "$MODDIR/.state/directory-migration/local-state/tools/yq.version")" = old-version ]
[ "$(stat -c '%a' "$MODDIR/.state/directory-migration")" = 700 ]
before=$(find "$MODDIR/.state" "$MODDIR/.cache" -type f -exec cksum '{}' \; | sort)
magicnet_migrate_runtime_dirs
[ "$before" = "$(find "$MODDIR/.state" "$MODDIR/.cache" -type f -exec cksum '{}' \; | sort)" ]

# A failed move leaves its source intact; a later invocation completes the merge.
mkdir -p "$MODDIR/.tmp"
printf 'first' >"$MODDIR/.tmp/first"
printf 'second' >"$MODDIR/.tmp/second"
mv() {
    [ "$1" != "$MODDIR/.tmp/second" ] || return 1
    command mv "$@"
}
if magicnet_migrate_runtime_dirs; then exit 1; fi
[ "$(cat "$MODDIR/.tmp/second")" = second ]
[ "$(cat "$MODDIR/.cache/first")" = first ]
unset -f mv
magicnet_migrate_runtime_dirs
[ ! -e "$MODDIR/.tmp" ] && [ "$(cat "$MODDIR/.cache/second")" = second ]

# Neither a legacy link nor a canonical link can move or chmod outside data.
mkdir "$work/outside"
chmod 755 "$work/outside"
printf 'untouched' >"$work/outside/sentinel"
for link in .tmp .local .cache .state; do
    fixture="$work/link-${link#.}"
    mkdir "$fixture"
    ln -s "$work/outside" "$fixture/$link"
    if [ "$link" = .local ]; then mkdir -p "$work/outside/state"; fi
    if magicnet_migrate_runtime_dirs "$fixture"; then exit 1; fi
    [ -L "$fixture/$link" ]
    [ "$(cat "$work/outside/sentinel")" = untouched ]
    [ "$(stat -c '%a' "$work/outside")" = 755 ]
done

# The real framework receives .cache as TMPDIR; cache work does not change
# the config snapshot or reintroduce a second temporary root.
set_i18n() { :; }
. "$root/src/MagicNet/lib/kamfw/fswatch.sh"
mkdir -p "$MODDIR/.config"
printf 'intent' >"$MODDIR/.config/example.conf"
fswatch_changed "$MODDIR/.config" "$MODDIR/.state/config.snapshot"
printf 'temporary' >"$MODDIR/.cache/worker"
if fswatch_changed "$MODDIR/.config" "$MODDIR/.state/config.snapshot"; then exit 1; fi
[ ! -e "$MODDIR/.tmp" ]

# Concurrent runtime entrypoints use the existing config lock around migration.
cat >"$work/migrate.sh" <<'CHILD'
#!/bin/bash
set -eu
import() { :; }
info() { :; }
warn() { printf '%s\n' "$*" >&2; }
. "$1/src/MagicNet/lib/magicnet/common.sh"
. "$1/src/MagicNet/lib/magicnet/runtime_dirs.sh"
migration_fixture=$2
if [ "$3" = first ]; then
    mv() {
        : >"$migration_fixture/paused"
        while [ ! -e "$migration_fixture/resume" ]; do sleep 0.01; done
        command mv "$@"
    }
fi
magicnet_prepare_runtime_dirs
: >"$2/$3.done"
CHILD
export MODDIR="$work/concurrent" KAM_HOME="$work/concurrent"
mkdir -p "$MODDIR/.tmp"
printf 'retained' >"$MODDIR/.tmp/payload"
bash "$work/migrate.sh" "$root" "$work" first &
first=$!
i=0
while [ ! -e "$work/paused" ] && [ "$i" -lt 200 ]; do sleep 0.01; i=$((i + 1)); done
[ -e "$work/paused" ]
bash "$work/migrate.sh" "$root" "$work" second &
second=$!
sleep 0.1
[ ! -e "$work/second.done" ]
: >"$work/resume"
wait "$first"
wait "$second"
first='' second=''
[ -f "$work/first.done" ] && [ -f "$work/second.done" ]
[ ! -e "$MODDIR/.tmp" ] && [ ! -e "$MODDIR/.state/config.lock" ]
[ "$(cat "$MODDIR/.cache/payload")" = retained ]
printf '%s\n' 'runtime directory migration, retry, privacy and concurrency tests passed'
