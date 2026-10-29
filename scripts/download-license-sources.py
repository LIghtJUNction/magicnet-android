#!/usr/bin/env python3
"""Populate pinned module source cache without altering the approved core tree."""
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

def main():
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOMODCACHE=str(ROOT / '.tools/gomodcache'), GOCACHE=str(ROOT / '.tools/gocache'))
    env.setdefault('GOPROXY', 'https://proxy.golang.org,direct')
    for directory in [ROOT, ROOT / 'third_party/sing-box']:
        with tempfile.TemporaryDirectory(prefix='license-module-', dir=ROOT / '.tools') as name:
            temporary = pathlib.Path(name)
            module = (directory / 'go.mod').read_text()
            if directory != ROOT:
                # The only relative replacement is the approved tracked core
                # tree; use that exact tree from this disposable module copy.
                module = module.replace('=> ./submodules/wireguard-go', '=> ' + str(directory / 'submodules/wireguard-go'))
            (temporary / 'go.mod').write_text(module)
            (temporary / 'go.sum').write_bytes((directory / 'go.sum').read_bytes())
            subprocess.run([str(ROOT / '.tools/go/bin/go'), 'mod', 'download', 'all'], cwd=temporary, env=env, check=True)
    print('Pinned license sources cached; original go.mod/go.sum files remain unchanged.')

if __name__ == '__main__':
    main()
