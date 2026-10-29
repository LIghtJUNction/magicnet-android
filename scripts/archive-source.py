#!/usr/bin/env python3
"""Archive only the frozen new tree, approved core tree and frozen recipe.

No Git history, product state, build cache or unrelated workspace path is read.
The companion inventory names every included blob and every unused GUI gitlink.
"""
from pathlib import Path, PurePosixPath
import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
from product_metadata import controller_metadata, product_metadata

ROOT = Path(__file__).resolve().parents[1]
CORE = "871b7a3440cd9c850f1b09ef3b4ada9babb4384b"
RECIPE_SHA = "502e160a363ffdc6e60477261ac15b74884b07f37de78af69558b0806f8e717a"
PREFIX = "MagicNet-source/"


def git(directory, *args):
    return subprocess.check_output(["git", "-C", str(directory), *args])


def entries(directory, revision):
    records = []
    for item in git(directory, "ls-tree", "-rz", "--full-tree", revision).split(b"\0"):
        if not item:
            continue
        meta, raw_path = item.split(b"\t", 1)
        mode, kind, object_id = meta.decode().split(" ")
        path = raw_path.decode("utf-8")
        parsed = PurePosixPath(path)
        assert not parsed.is_absolute() and ".." not in parsed.parts
        records.append((path, int(mode, 8), kind, object_id))
    return sorted(records)


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--recipe", type=Path, default=ROOT.parent / "input/BUILD_PROMPT.md")
    args = parser.parse_args()
    assert not git(ROOT, "status", "--porcelain"), "Freeze all new source files in Git first"
    revision = git(ROOT, "rev-parse", "HEAD").decode().strip()
    build = json.loads((ROOT / "assets/BUILD_INPUTS.json").read_text())
    controller = controller_metadata()
    functional = build["implementation_commit"]
    assert re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", functional)
    assert controller["commit"] == functional and build["product"] == product_metadata()
    git(ROOT, "cat-file", "-e", functional + "^{commit}")
    for binary in build["binaries"]:
        assert hashlib.sha256((ROOT / binary["path"]).read_bytes()).hexdigest() == binary["sha256"], "Stale binary metadata"
    core_root = ROOT / "third_party/sing-box"
    assert git(core_root, "rev-parse", "HEAD").decode().strip() == CORE
    assert not git(core_root, "status", "--porcelain", "--untracked-files=no")
    recipe = args.recipe.read_bytes()
    assert hashlib.sha256(recipe).hexdigest() == RECIPE_SHA
    assert len(recipe) == 335805

    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    target = dist / "MagicNet-source.tar.gz"
    temporary = target.with_suffix(".partial")
    manifest = {
        "schema": 1,
        "delivery_commit": revision,
        "delivery_tree": git(ROOT, "rev-parse", "HEAD^{tree}").decode().strip(),
        "functional_binary_source_commit": functional,
        "product": build["product"],
        "core_commit": CORE,
        "recipe_sha256": RECIPE_SHA,
        "archive_prefix": PREFIX,
        "inventory_scope": "All included content except this self-referential SOURCE_FILES.json; no tool caches, Git history, runtime state, screenshots or runtime executables",
        "files": [],
        "omitted_optional_core_gitlinks": [],
    }

    with temporary.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=output, mtime=0) as compressed:
            with tarfile.open(mode="w|", fileobj=compressed, format=tarfile.PAX_FORMAT) as tar:
                def add(path, data, mode=0o644, symlink=False, provenance="new_source"):
                    info = tarfile.TarInfo(PREFIX + path)
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = mode
                    if symlink:
                        info.type = tarfile.SYMTYPE
                        info.linkname = data.decode("utf-8")
                        tar.addfile(info)
                    else:
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                    manifest["files"].append({"path": path, "mode": oct(mode), "type": "symlink" if symlink else "file", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "provenance": provenance})

                for directory, commit, prefix, provenance in (
                    (ROOT, revision, "", "new_source"),
                    (core_root, CORE, "third_party_sources/sing-box-" + CORE + "/", "approved_core"),
                ):
                    reader = subprocess.Popen(["git", "-C", str(directory), "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    try:
                        for path, mode, kind, object_id in entries(directory, commit):
                            if kind == "commit":
                                assert provenance == "approved_core"
                                manifest["omitted_optional_core_gitlinks"].append({"path": path, "commit": object_id, "reason": "Optional GUI client; not used by headless module build"})
                                continue
                            assert kind == "blob"
                            reader.stdin.write((object_id + "\n").encode())
                            reader.stdin.flush()
                            actual, actual_kind, size = reader.stdout.readline().decode().split()
                            assert actual == object_id and actual_kind == "blob"
                            data = reader.stdout.read(int(size))
                            assert len(data) == int(size) and reader.stdout.read(1) == b"\n"
                            add(prefix + path, data, mode & 0o777, mode == 0o120000, provenance)
                    finally:
                        reader.stdin.close()
                        reader.stdout.close()
                        assert reader.wait() == 0
                add("recipe/BUILD_PROMPT.md", recipe, provenance="frozen_project_requirement")
                info = {key: value for key, value in manifest.items() if key not in ("files", "inventory_scope")}
                info["rebuild"] = "See README.md and BUILD_NOTES.md. scripts/fetch-build-inputs.py retrieves the exact core/toolchains into third_party/. The complete core source is also included under third_party_sources/ for inspection. Optional GUI clients, Go module download caches and toolchains are not bundled; go.mod/go.sum and fixed download hashes retain their identities. Set MAGICNET_SOURCE_REVISION to functional_binary_source_commit when reproducing the delivered controller version label."
                add("SOURCE_ARCHIVE_INFO.json", json_bytes(info), provenance="archive_metadata")
                manifest["files"].sort(key=lambda item: item["path"])
                data = json_bytes(manifest)
                descriptor = tarfile.TarInfo(PREFIX + "SOURCE_FILES.json")
                descriptor.mode = 0o644
                descriptor.size = len(data)
                tar.addfile(descriptor, io.BytesIO(data))
                (dist / "SOURCE_FILES.json").write_bytes(data)
    temporary.replace(target)
    rows = []
    for name in ("MagicNet-source.tar.gz", "SOURCE_FILES.json"):
        path = dist / name
        rows.append({"name": name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    checksums = dist / "SHA256SUMS"
    retained = [line for line in checksums.read_text().splitlines() if line.split()[-1] not in {row["name"] for row in rows}]
    checksums.write_text("\n".join(retained + [row["sha256"] + "  " + row["name"] for row in rows]) + "\n")
    (dist / "source-archive.json").write_bytes(json_bytes({"schema": 1, "delivery_commit": revision, "files": len(manifest["files"]), "artifacts": rows}))
    print(json.dumps({"delivery_commit": revision, "files": len(manifest["files"]), "artifacts": rows}, indent=2))


if __name__ == "__main__":
    main()
