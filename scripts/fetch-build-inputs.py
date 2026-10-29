#!/usr/bin/env python3
"""Acquire explicitly approved inputs at immutable revisions and verified hashes.

This fetches no prior MagicNet implementation or MagicSingBox template. Downloaded
scripts are never executed. Run this on Linux amd64 before scripts/build.sh all.
"""
import argparse
import hashlib
import os
import pathlib
import subprocess
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / '.tools'
CORE = '871b7a3440cd9c850f1b09ef3b4ada9babb4384b'
RULES = 'f3335f9420d07b8c50b26488df2a9492da6bbb44'
TAG = 'rules-20260918-1ade898a44cc7727'

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while data := stream.read(1024 * 1024):
            h.update(data)
    return h.hexdigest()

def fetch(url, name, expected):
    destination = ROOT / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        assert destination.is_file() and not destination.is_symlink() and sha(destination) == expected, name + ' does not match the locked input'
        return destination
    temporary = destination.with_name(destination.name + '.partial')
    request = urllib.request.Request(url, headers={'User-Agent': 'MagicNet-independent-build/1.8.1 (recipe 0.3.1; candidate)'})
    try:
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open('xb') as output:
            total = 0
            while data := response.read(1024 * 1024):
                total += len(data)
                assert total <= 256 * 1024 * 1024, 'download exceeds input limit'
                output.write(data)
        assert sha(temporary) == expected, name + ' checksum mismatch'
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination

def git(*args):
    return subprocess.check_output(['git', *map(str, args)], text=True).strip()

def source(repository, destination, revision, tag=None, checkout=True):
    directory = ROOT / destination
    if not (directory / '.git').exists():
        directory.mkdir(parents=True, exist_ok=True)
        git('init', directory)
        git('-C', directory, 'remote', 'add', 'origin', repository)
    assert git('-C', directory, 'remote', 'get-url', 'origin') == repository
    ref = f'refs/tags/{tag}:refs/tags/{tag}' if tag else revision
    try:
        actual = git('-C', directory, 'rev-parse', (tag + '^{commit}') if tag else 'HEAD')
    except subprocess.CalledProcessError:
        actual = ''
    if actual != revision:
        assert not git('-C', directory, 'status', '--porcelain', '--untracked-files=no'), 'Refusing to replace a changed source tree'
        git('-C', directory, 'fetch', '--depth=1', 'origin', ref)
        if checkout:
            git('-C', directory, 'checkout', '--detach', revision)
    assert git('-C', directory, 'rev-parse', (tag + '^{commit}') if tag else 'HEAD') == revision
    return directory

def unpack(archive, destination, expected_top):
    if (destination / expected_top).exists():
        return
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            name = pathlib.PurePosixPath(member.name)
            assert name.parts and name.parts[0] == expected_top and not name.is_absolute() and '..' not in name.parts
        tar.extractall(destination, filter='data')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--include-core-clients', action='store_true', help='Also fetch the fixed core commit\'s optional Android/Apple/desktop client gitlinks; these are not used by this module build')
    args = parser.parse_args()
    TOOLS.mkdir(exist_ok=True)
    go = fetch('https://go.dev/dl/go1.26.10.linux-amd64.tar.gz', '.tools/go1.26.10.linux-amd64.tar.gz', 'ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5')
    unpack(go, TOOLS, 'go')
    assert subprocess.check_output([str(TOOLS / 'go/bin/go'), 'version'], text=True).strip() == 'go version go1.26.10 linux/amd64'
    jdk = fetch('https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.9%2B10/OpenJDK21U-jdk_x64_linux_hotspot_21.0.9_10.tar.gz', '.tools/jdk.tar.gz', '810d3773df7e0d6c4394e4e244b264c8b30e0b05a0acf542d065fd78a6b65c2f')
    unpack(jdk, TOOLS, 'jdk-21.0.9+10')
    fetch('https://storage.googleapis.com/r8-releases/raw/8.10.21/r8.jar', '.tools/r8-8.10.21.jar', 'bbdf3f6431af895d72a5f4bed6fbdde2b43241ec98b36992c554ce4a6dd7892b')
    core = source('https://github.com/LIghtJUNction/sing-box.git', 'third_party/sing-box', CORE)
    # This replacement is a tracked tree, not one of .gitmodules' GUI clients.
    assert git('-C', core, 'rev-parse', 'HEAD:submodules/wireguard-go') == 'c813a5db524eef79b40a99a1d5d6aa02748c1675'
    assert (core / 'submodules/wireguard-go/go.mod').is_file()
    if args.include_core_clients:
        git('-C', core, 'submodule', 'update', '--init', '--recursive')
    source('https://github.com/LIghtJUNction/MagicNetRules.git', 'third_party/rules-source', RULES, tag=TAG, checkout=False)
    hashes = {
        'magicnet-rules.tar.gz': '1ade898a44cc7727b1d98404e206f796a4a0432b1aa2be98289cc7823b0ae0bf',
        'magicnet-rules-sources.tar.gz': 'b88342e8f1151d0d1d9a6d73543a8eb8ba789a8a43398591d7652c3ac111ba5f',
        'upstream-manifest.json': '2f91f78d6e3b6a93e845d6345afb039f01a9d577717d23a0423a4bac4f801592',
    }
    for name, expected in hashes.items():
        fetch(f'https://github.com/LIghtJUNction/MagicNetRules/releases/download/{TAG}/{name}', 'assets/rules-download/' + name, expected)
    (ROOT / 'assets/rules-download/SHA256SUMS').write_text(''.join(value + '  ' + name + '\n' for name, value in hashes.items()))
    fetch('https://github.com/Zephyruso/zashboard/releases/download/v3.16.0/dist-no-fonts.zip', 'assets/vendor/zashboard.zip', '1d8c7aca69e6ddead5e4fe6e92ceda23a499105f675d053362f7c9b53a9730f9')
    fetch('https://raw.githubusercontent.com/Zephyruso/zashboard/v3.16.0/LICENSE', 'assets/vendor/zashboard-LICENSE', 'ffc390eec51f16b58506b1a42c99fe0cd9ffea1e3081aab443100fd8c20182d9')
    fetch('https://github.com/gojue/ecapture/releases/download/v2.5.2/ecapture-v2.5.2-android-arm64.tar.gz', 'assets/vendor/ecapture.tar.gz', '3531f47f60a45c02662188fb151fa8bbf9c40e5c245ff293e5a50477b99df2d1')
    print('Approved source/toolchain/assets verified. Run bash scripts/build.sh all.')

if __name__ == '__main__':
    main()
