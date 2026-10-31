#!/usr/bin/env python3
"""Check a packaged tendns binary, optionally through a cross-target runner."""

import argparse
import base64
from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def smoke(command):
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    actual = subprocess.check_output([*command, "--version"], cwd=ROOT, timeout=60)
    if actual.strip() != f"tendns {version}".encode():
        raise ValueError(f"Unexpected binary version: {actual!r}")

    key = subprocess.check_output([*command, "keygen"], cwd=ROOT, timeout=60).strip()
    if len(key) != 43:
        raise ValueError("Key generation did not return an unpadded 256-bit key")
    decoded = base64.b64decode(key + b"=", altchars=b"-_", validate=True)
    if len(decoded) != 32:
        raise ValueError("Key generation did not return a 256-bit key")
    print("Packaged binary smoke passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs=argparse.REMAINDER, help="binary and optional runner")
    args = parser.parse_args()
    if not args.command:
        parser.error("a binary command is required")
    smoke(args.command)
