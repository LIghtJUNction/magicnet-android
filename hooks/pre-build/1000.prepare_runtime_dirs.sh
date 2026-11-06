#!/bin/sh
# shellcheck shell=sh
. "$KAM_MODULE_ROOT/lib/magicnet/runtime_dirs.sh" || exit 1
magicnet_migrate_runtime_dirs "$KAM_MODULE_ROOT"
