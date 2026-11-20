#!/bin/bash

# Reviewed release inputs for reproducible build hooks. Update a lock only after
# independently reviewing the upstream release and its artifact hash.
release_lock_lookup() {
    local component="$1"

    RELEASE_LOCK_REPO=""
    RELEASE_LOCK_TAG=""
    RELEASE_LOCK_ASSET=""
    RELEASE_LOCK_SHA256=""

    case "$component" in
    yq)
        RELEASE_LOCK_REPO="mikefarah/yq"
        RELEASE_LOCK_TAG="v4.54.3"
        RELEASE_LOCK_ASSET="yq_linux_arm64"
        RELEASE_LOCK_SHA256="89f69310b61b68d1245065a1241d1fc843f7a36cd6103ffd77ad987613bd1b67"
        ;;
    jq)
        RELEASE_LOCK_REPO="jqlang/jq"
        RELEASE_LOCK_TAG="jq-1.8.2"
        RELEASE_LOCK_ASSET="jq-linux-arm64"
        RELEASE_LOCK_SHA256="8b85c817833814ddca00a144c33705546355afccf0cf39b188f3cdb48b852309"
        ;;
    ecapture)
        RELEASE_LOCK_REPO="gojue/ecapture"
        RELEASE_LOCK_TAG="v2.11.0"
        RELEASE_LOCK_ASSET="ecapture-v2.11.0-android-arm64.tar.gz"
        RELEASE_LOCK_SHA256="f962faafc0f715ffb016b86ddb841c6844c27bdb4f177b43c3e72d89c260234a"
        ;;
    zashboard)
        RELEASE_LOCK_REPO="Zephyruso/zashboard"
        RELEASE_LOCK_TAG="v3.30.0"
        RELEASE_LOCK_ASSET="dist-no-fonts.zip"
        RELEASE_LOCK_SHA256="ec794e7c4daf4c839ecbc0a1292fdaf7bc7a6e3e4a4ce284db2b32379145c278"
        ;;
    *)
        return 1
        ;;
    esac
}

release_lock_is_valid() {
    [[ "$RELEASE_LOCK_REPO" == */* ]] &&
        [[ -n "$RELEASE_LOCK_TAG" ]] &&
        [[ "$RELEASE_LOCK_ASSET" != */* ]] &&
        [[ "$RELEASE_LOCK_SHA256" =~ ^[0-9a-f]{64}$ ]]
}
