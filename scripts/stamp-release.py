#!/usr/bin/env python3
"""Apply and verify a version overlay on an immutable MagicNet source checkout."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import tomllib

REPOSITORY = "LIghtJUNction/MagicNet"
METADATA_FILES = ("kam.toml", "src/MagicNet/module.prop", "update.json")
MAX_VERSION_CODE = 2147483647


def require(condition, message):
    if not condition:
        raise ValueError(message)


def normalize_version(value):
    require(isinstance(value, str), "Version must be a string")
    value = value if value.startswith("v") else "v" + value
    require(re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value),
            "Version must be X.Y.Z or vX.Y.Z without leading zeros")
    return value


def normalize_code(value):
    require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value),
            "versionCode must be a positive decimal integer")
    code = int(value)
    require(code <= MAX_VERSION_CODE, "versionCode exceeds 2147483647")
    return code


def updater(version, code):
    base = f"https://github.com/{REPOSITORY}"
    return {"changelog": f"{base}/blob/main/docs/releases/{version}.md",
            "version": version, "versionCode": code,
            "zipUrl": f"{base}/releases/download/{version}/magicnet_installer.zip"}


def fields(text):
    result = {}
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        require(key not in result, f"Duplicate module property: {key}")
        result[key] = value
    return result


def validate(files):
    kam = tomllib.loads(files["kam.toml"])
    prop = kam["prop"]
    module = fields(files["src/MagicNet/module.prop"])
    update = json.loads(files["update.json"])
    version = normalize_version(prop["version"])
    code = prop["versionCode"]
    require(type(code) is int and 1 <= code <= MAX_VERSION_CODE, "Invalid source versionCode")
    require(prop["id"] == module["id"] == "MagicNet", "Invalid module identity")
    require(prop["version"] == version and module["version"] == version
            and module["versionCode"] == str(code), "Source version metadata differs")
    require(update == updater(version, code), "Source updater is inconsistent or uses an unofficial URL")
    repo = kam["mmrl"]["repo"]
    require(repo["changelog"] == update["changelog"]
            and repo["changelog_file"] == f"docs/releases/{version}.md", "Source changelog metadata differs")
    return version, code


def replace_fields(text, values):
    for key, value in values.items():
        text, count = re.subn(rf"(?m)^([ \t]*{re.escape(key)}[ \t]*=[ \t]*)[^\n]*$",
                             lambda match: match[1] + value, text)
        require(count == 1, f"Expected exactly one {key} field")
    return text


def replace_section(text, section, values):
    match = re.search(rf"(?ms)^\[{re.escape(section)}\][^\n]*\n(.*?)(?=^\[|\Z)", text)
    require(match is not None, f"Missing [{section}] section")
    body = replace_fields(match[1], values)
    return text[:match.start(1)] + body + text[match.end(1):]


def overlay(original, version, code):
    validate(original)
    version = normalize_version(version)
    code = normalize_code(str(code))
    update = updater(version, code)
    kam = replace_section(original["kam.toml"], "prop",
                          {"version": json.dumps(version), "versionCode": str(code)})
    kam = replace_section(kam, "mmrl.repo", {"changelog": json.dumps(update["changelog"]),
                          "changelog_file": json.dumps(f"docs/releases/{version}.md")})
    result = {"kam.toml": kam,
              "src/MagicNet/module.prop": replace_fields(original["src/MagicNet/module.prop"],
                                                         {"version": version, "versionCode": str(code)}),
              "update.json": json.dumps(update, ensure_ascii=False, indent=2) + "\n"}
    validate(result)
    return result


def default_notes(version, code):
    return (f"# MagicNet {version}\n\n"
            f"Android versionCode: {code}.\n\n"
            f"Release notes: https://github.com/{REPOSITORY}/releases/tag/{version}\n")


def stamp(root, version, code, notes_file=None):
    version, code = normalize_version(version), normalize_code(code)
    original = {name: (root / name).read_text() for name in METADATA_FILES}
    source_version, _ = validate(original)
    require((root / f"docs/releases/{source_version}.md").is_file(), "Missing source release notes")
    rendered = overlay(original, version, code)
    notes_path = f"docs/releases/{version}.md"
    if notes_file:
        rendered[notes_path] = notes_file.read_text()
    elif not (root / notes_path).is_file():
        rendered[notes_path] = default_notes(version, code)
    # All validation and substitutions finish before the first write.
    for name, text in rendered.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return {"version": version, "version_code": str(code)}


def verify(root, version, code, notes_file=None):
    version, code = normalize_version(version), normalize_code(code)
    original = {name: subprocess.check_output(["git", "-C", str(root), "show", f"HEAD:{name}"], text=True)
                for name in METADATA_FILES}
    expected = overlay(original, version, code)
    actual = {name: (root / name).read_text() for name in METADATA_FILES}
    require(validate(actual) == (version, code), "Built version differs from the selected release")
    for name in METADATA_FILES:
        # KAM may reserialize JSON; every field and value must still match.
        matches = (json.loads(actual[name]) == json.loads(expected[name]) if name.endswith(".json")
                   else actual[name] == expected[name])
        require(matches, f"Build changed metadata outside the permitted version overlay: {name}")
    notes_path = f"docs/releases/{version}.md"
    if notes_file:
        notes = notes_file.read_text()
    else:
        result = subprocess.run(["git", "-C", str(root), "show", f"HEAD:{notes_path}"],
                                capture_output=True, text=True, check=False)
        notes = result.stdout if result.returncode == 0 else default_notes(version, code)
    require((root / notes_path).read_text() == notes, "Build changed release notes")
    return {"version": version, "version_code": str(code)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--version-code", required=True)
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    try:
        operation = verify if args.verify else stamp
        result = operation(Path.cwd(), args.version, args.version_code, args.notes_file)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"::error::{error}") from error


if __name__ == "__main__":
    main()
