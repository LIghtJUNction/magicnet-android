#!/usr/bin/env python3
"""Inspect packaged Android ARM64 executables without running foreign code."""

import argparse
import json
from pathlib import Path
import struct
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def elf_identity(path):
    # Read ELF program headers directly, as in android-curl-artifact.py. Curl
    # retains its additional Bionic dependency and provenance requirements.
    data = path.read_bytes()
    require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01',
            'expected a little-endian ELF64 executable')
    kind, machine, version, entry, offset = struct.unpack_from('<HHIQQ', data, 16)
    require(kind in (2, 3) and machine == 183 and version == 1,
            'expected an AArch64 ET_EXEC or ET_DYN executable')
    header_size, size, count = struct.unpack_from('<HHH', data, 52)
    require(header_size == 64 and size == 56 and 1 <= count <= 256
            and offset >= 64 and offset + size * count <= len(data),
            'invalid ELF program headers')
    executable_entry, interpreters, dynamics = False, [], []
    for index in range(count):
        segment, flags, start, address, _, length, memory, _ = struct.unpack_from(
            '<IIQQQQQQ', data, offset + index * size)
        require(start + length <= len(data) and length <= memory, 'invalid ELF segment')
        if segment == 1 and flags & 1 and address <= entry < address + length:
            executable_entry = True
        elif segment == 3:
            require(1 <= length <= 128, 'invalid ELF interpreter')
            interpreters.append(data[start:start + length])
        elif segment == 2:
            require(0 < length <= 65536 and length % 16 == 0,
                    'invalid ELF dynamic segment')
            dynamics.append(data[start:start + length])
    require(entry != 0 and executable_entry, 'ELF entry is not in an executable load segment')
    require(len(interpreters) <= 1 and len(dynamics) <= 1,
            'duplicate ELF interpreter or dynamic segment')
    tags = {}
    if dynamics:
        terminated = False
        for index in range(0, len(dynamics[0]), 16):
            tag, value = struct.unpack_from('<qQ', dynamics[0], index)
            if tag == 0:
                terminated = True
                break
            tags.setdefault(tag, []).append(value)
        require(terminated, 'unterminated ELF dynamic segment')
    if interpreters:
        require(interpreters == [b'/system/bin/linker64\x00'] and len(dynamics) == 1,
                'dynamic executable must use Android linker64')
        linkage = 'android'
    else:
        require(1 not in tags, 'static executable must not contain DT_NEEDED')
        if kind == 3:
            # ET_DYN alone also describes ordinary shared libraries. Static PIE
            # needs an executable entry and the loader's explicit DF_1_PIE flag.
            flags = tags.get(0x6FFFFFFB, [])
            require(len(flags) == 1 and flags[0] & 0x08000000,
                    'ET_DYN without an interpreter must have DF_1_PIE')
            linkage = 'static-pie'
        else:
            linkage = 'static'
    return {'machine': 'AArch64', 'linkage': linkage,
            'interpreter': '/system/bin/linker64' if interpreters else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    try:
        result = elf_identity(args.path)
    except (OSError, ValueError, struct.error) as error:
        print(f'Android ELF validation failed: {error}', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
