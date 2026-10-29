#!/usr/bin/env python3
"""Import only approved immutable classification assets; never executes upstream code."""
import hashlib
import json
import pathlib
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
REVISION = "f3335f9420d07b8c50b26488df2a9492da6bbb44"
TAG = "rules-20260918-1ade898a44cc7727"
DOWNLOAD = ROOT / "assets/rules-download"
DEST = ROOT / "assets/rules"
APPROVED_ARCHIVES = {
    "magicnet-rules.tar.gz": "1ade898a44cc7727b1d98404e206f796a4a0432b1aa2be98289cc7823b0ae0bf",
    "magicnet-rules-sources.tar.gz": "b88342e8f1151d0d1d9a6d73543a8eb8ba789a8a43398591d7652c3ac111ba5f",
    "upstream-manifest.json": "2f91f78d6e3b6a93e845d6345afb039f01a9d577717d23a0423a4bac4f801592",
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def entries(archive):
    with tarfile.open(archive) as tar:
        result = {}
        total = 0
        for item in tar:
            p = pathlib.PurePosixPath(item.name)
            if p.is_absolute() or ".." in p.parts or item.name in result or not item.isfile():
                raise ValueError("unsafe or duplicate asset archive entry")
            total += item.size
            if item.size > 32 * 1024 * 1024 or total > 128 * 1024 * 1024:
                raise ValueError("asset archive size limit")
            result[item.name] = tar.extractfile(item).read()
        return result

def main():
    actual = subprocess.check_output(["git", "-C", str(ROOT / "third_party/rules-source"),
                                      "rev-parse", TAG + "^{commit}"], text=True).strip()
    if actual != REVISION:
        raise ValueError("release tag does not identify the approved revision")
    checksums = {}
    for line in (DOWNLOAD / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split()
        checksums[name] = expected
        if digest((DOWNLOAD / name).read_bytes()) != expected:
            raise ValueError("release checksum mismatch: " + name)
    if checksums != APPROVED_ARCHIVES:
        raise ValueError("release checksum document does not match the approved immutable snapshot")
    binary = entries(DOWNLOAD / "magicnet-rules.tar.gz")
    source = entries(DOWNLOAD / "magicnet-rules-sources.tar.gz")
    upstream = json.loads(binary["manifest.json"])
    mapping = {
        "lyc-geosite-ads": "geosite-category-ads-all", "lyc-geosite-cn": "geosite-cn",
        "lyc-geoip-cn": "geoip-cn", "lyc-geoip-telegram": "geoip-telegram",
        "metacubex-geosite-cn": "metacubex-geosite-cn", "metacubex-geoip-cn": "metacubex-geoip-cn",
        "metacubex-geosite-geolocation-not-cn": "metacubex-geosite-geolocation-not-cn",
        "hagezi-light": "hagezi-light", "karing-acl4ssr-wechat": "karing-acl4ssr-wechat",
        "service-wechat-dns": "service-wechat-dns", "karing-acl4ssr-china-domain": "karing-acl4ssr-china-domain",
        "karing-acl4ssr-china-ip": "karing-acl4ssr-china-ip", "sukka-chatgpt-voice": "sukka-chatgpt-voice"
    }
    services = "tencent category-doh category-ip-geo-detect connectivity-check speedtest openai google-gemini xai anthropic bing@cn bing category-game-platforms-download win-update apple-update icloud apple microsoft category-scholar-!cn category-ai-!cn category-dev category-media category-games-!cn category-social-media-!cn telegram twitter whatsapp google google-play category-entertainment category-communication github huggingface gitlab docker npmjs notion discord slack reddit spotify netflix youtube".split()
    mapping.update({"meta-" + tag: "metacubex-service-" + tag for tag in services})
    if len(mapping) != 55:
        raise ValueError("expected exactly 55 policy inventory assets")
    DEST.mkdir(parents=True, exist_ok=True)
    files = []
    for tag, upstream_name in mapping.items():
        if tag == "sukka-chatgpt-voice":
            data = source["sources/sukka-chatgpt-voice.json"]
            json.loads(data)
            filename, form = tag + ".json", "source"
        else:
            data = binary[upstream_name + ".srs"]
            if not data.startswith(b"SRS"):
                raise ValueError("invalid rule-set binary header: " + tag)
            expected = upstream.get("rulesets", {}).get(upstream_name, {}).get("sha256_srs")
            if expected and digest(data) != expected:
                raise ValueError("per-rule manifest checksum mismatch: " + tag)
            filename, form = tag + ".srs", "binary"
        (DEST / filename).write_bytes(data)
        files.append({"tag": tag, "path": filename, "sha256": digest(data), "format": form,
                      "size": len(data), "upstream_path": upstream_name + (".json" if form == "source" else ".srs")})
    manifest = {"schema": 1, "revision": REVISION, "release_tag": TAG,
                "repository": "https://github.com/LIghtJUNction/MagicNetRules", "files": files,
                "archives": checksums}
    (DEST / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    licenses = DEST / "licenses"
    licenses.mkdir(exist_ok=True)
    for name, data in source.items():
        if pathlib.PurePosixPath(name).name == "LICENSE" or name.endswith(".LICENSE.txt"):
            (licenses / pathlib.PurePosixPath(name).name).write_bytes(data)
    (DEST / "upstream-manifest.json").write_bytes((DOWNLOAD / "upstream-manifest.json").read_bytes())
    (DEST / "SHA256SUMS").write_text("".join(f["sha256"] + "  " + f["path"] + "\n" for f in files))
    print(json.dumps({"revision": REVISION, "files": len(files), "bytes": sum(f["size"] for f in files)}))

if __name__ == "__main__":
    main()
