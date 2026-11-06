#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/magicnet-config-repo-migration.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

MODPATH="$WORK/module"
export MODPATH
REPO_DIR="$MODPATH/.config/magicnet"
REPO_FILE="$REPO_DIR/singbox-config-repo.conf"
mkdir -p "$REPO_DIR"

# shellcheck disable=SC1091
. "$ROOT/src/MagicNet/lib/magicnet/install_config.sh"

DEFAULTS="$ROOT/src/MagicNet/.config/magicnet/singbox-config-repo.conf"
expected_ref="$(sed -n 's/^MAGICNET_SINGBOX_CONFIG_REPO_REF=//p' "$DEFAULTS")"
expected_sha="$(sed -n 's/^MAGICNET_SINGBOX_CONFIG_REPO_SHA256=//p' "$DEFAULTS")"

write_old_default() {
    cat >"$REPO_FILE" <<'EOF'
# Managed by MagicNet; edit through the config repository controls.
MAGICNET_SINGBOX_CONFIG_REPO_URL=https://github.com/LIghtJUNction/MagicSingBox.git
MAGICNET_SINGBOX_CONFIG_REPO_REF=ba67cdbe771dff7e06c06bd754cc67699eeea8c0
MAGICNET_SINGBOX_CONFIG_REPO_PATH=config.json
MAGICNET_SINGBOX_CONFIG_REPO_SHA256=6faa2cfcc44c305e30bc64cec84202b95d0a1592f012ab1f8dd65eae6d489258
EOF
    chmod 600 "$REPO_FILE"
}

write_old_default
magicnet_migrate_install_config_repository

grep -Fqx "MAGICNET_SINGBOX_CONFIG_REPO_REF=$expected_ref" "$REPO_FILE"
grep -Fqx "MAGICNET_SINGBOX_CONFIG_REPO_SHA256=$expected_sha" "$REPO_FILE"
[ "$(stat -c '%a' "$REPO_FILE")" = 600 ] || {
    printf 'migrated config repository file must remain private\n' >&2
    exit 1
}

for previous in \
    a12e472c8152e9a40af48cfa1e2d4c4242f33d50:35d54f908ccc9cc615fabf06b1037bbfc1f6d1d9712c86ba6c9b5252cc98ae03 \
    6da399473a1ab3f99661556886e0b6701581af24:6365ee9b4144974ced6012dc99b9712ceef3f721f58ae9eb0943024373b81d81 \
    b1fa62b6912861292c895db58a88b8c5bdff3451:50585d94942620e569ae0569dd475977a35d45797bfe2bfbd6afc6cb14da2355 \
    dacc776dad4bd2519d5dd0dfbf3839713f9e438c:08996a10e24adc6ffb6a75f96d436a543264734d95f50f9952a7a265bb58213e; do
    printf '%s\n' \
        'MAGICNET_SINGBOX_CONFIG_REPO_URL=https://github.com/LIghtJUNction/MagicSingBox.git' \
        "MAGICNET_SINGBOX_CONFIG_REPO_REF=${previous%%:*}" \
        'MAGICNET_SINGBOX_CONFIG_REPO_PATH=config.json' \
        "MAGICNET_SINGBOX_CONFIG_REPO_SHA256=${previous#*:}" >"$REPO_FILE"
    magicnet_migrate_install_config_repository
    grep -Fqx "MAGICNET_SINGBOX_CONFIG_REPO_REF=$expected_ref" "$REPO_FILE"
    grep -Fqx "MAGICNET_SINGBOX_CONFIG_REPO_SHA256=$expected_sha" "$REPO_FILE"
    migrated_before="$(cat "$REPO_FILE")"
    magicnet_migrate_install_config_repository
    [ "$(cat "$REPO_FILE")" = "$migrated_before" ]
done

# A familiar repository/ref with an operator-supplied digest is still custom.
cat >"$REPO_FILE" <<'EOF'
MAGICNET_SINGBOX_CONFIG_REPO_URL=https://github.com/LIghtJUNction/MagicSingBox.git
MAGICNET_SINGBOX_CONFIG_REPO_REF=dacc776dad4bd2519d5dd0dfbf3839713f9e438c
MAGICNET_SINGBOX_CONFIG_REPO_PATH=config.json
MAGICNET_SINGBOX_CONFIG_REPO_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
custom_pin_before="$(cat "$REPO_FILE")"
magicnet_migrate_install_config_repository
[ "$(cat "$REPO_FILE")" = "$custom_pin_before" ] || {
    printf 'custom digest on a previous default ref must not be migrated\n' >&2
    exit 1
}

cat >"$REPO_FILE" <<'EOF'
MAGICNET_SINGBOX_CONFIG_REPO_URL=https://github.com/example/custom-config.git
MAGICNET_SINGBOX_CONFIG_REPO_REF=stable
MAGICNET_SINGBOX_CONFIG_REPO_PATH=config.json
MAGICNET_SINGBOX_CONFIG_REPO_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
custom_before="$(cat "$REPO_FILE")"
magicnet_migrate_install_config_repository
[ "$(cat "$REPO_FILE")" = "$custom_before" ] || {
    printf 'custom config repository must not be migrated\n' >&2
    exit 1
}

write_old_default
printf '%s\n' 'MAGICNET_SINGBOX_CONFIG_REPO_REF=operator-pinned' >>"$REPO_FILE"
customized_before="$(cat "$REPO_FILE")"
magicnet_migrate_install_config_repository
[ "$(cat "$REPO_FILE")" = "$customized_before" ] || {
    printf 'ambiguous or customized repository settings must not be migrated\n' >&2
    exit 1
}

rm -f "$REPO_FILE"
outside="$WORK/outside.conf"
printf '%s\n' 'preserve me' >"$outside"
ln -s "$outside" "$REPO_FILE"
if magicnet_migrate_install_config_repository; then
    printf 'repository migration must reject file symlinks\n' >&2
    exit 1
fi
[ "$(cat "$outside")" = 'preserve me' ] || {
    printf 'repository migration followed an unsafe file symlink\n' >&2
    exit 1
}

rm -f "$REPO_FILE"
rmdir "$REPO_DIR"
outside_dir="$WORK/outside-dir"
mkdir -p "$outside_dir"
printf '%s\n' 'preserve parent' >"$outside_dir/singbox-config-repo.conf"
ln -s "$outside_dir" "$REPO_DIR"
if magicnet_migrate_install_config_repository; then
    printf 'repository migration must reject parent directory symlinks\n' >&2
    exit 1
fi
[ "$(cat "$outside_dir/singbox-config-repo.conf")" = 'preserve parent' ] || {
    printf 'repository migration followed an unsafe parent symlink\n' >&2
    exit 1
}

printf 'Config repository migration test passed\n'
