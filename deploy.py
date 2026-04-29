#!/usr/bin/env python3
"""Deploy ttlock_local custom_component to Home Assistant via paramiko SFTP.

Reads HA_SSH_* from ../.env. Recursively syncs custom_components/ttlock_local
to /config/custom_components/ttlock_local on the HA host.

Usage:
  python deploy.py            # copy
  python deploy.py --restart  # also restart HA core
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parent
PARENT_ENV = ROOT.parent / ".env"
LOCAL_DIR = ROOT / "custom_components" / "ttlock_local"
REMOTE_DIR = "/config/custom_components/ttlock_local"

# Files we don't want to ship (cache, tests, etc.)
SKIP_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache"}
SKIP_SUFFIXES = {".pyc", ".pyo"}


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    if PARENT_ENV.exists():
        for line in PARENT_ENV.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    for k in ["HA_SSH_HOST", "HA_SSH_PORT", "HA_SSH_USER", "HA_SSH_PASSWORD"]:
        env.setdefault(k, os.environ.get(k, ""))
    if not env.get("HA_SSH_HOST"):
        sys.exit("HA_SSH_HOST nerastas .env / env varuose")
    return env


def ensure_remote_dir(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = path.strip("/").split("/")
    cur = ""
    for p in parts:
        cur += "/" + p
        try:
            sftp.stat(cur)
        except FileNotFoundError:
            sftp.mkdir(cur)


def upload_dir(sftp: paramiko.SFTPClient, local: Path, remote: str) -> int:
    n = 0
    ensure_remote_dir(sftp, remote)
    for entry in sorted(local.iterdir()):
        if entry.name in SKIP_NAMES or entry.suffix in SKIP_SUFFIXES:
            continue
        rpath = f"{remote}/{entry.name}"
        if entry.is_dir():
            n += upload_dir(sftp, entry, rpath)
        else:
            sftp.put(str(entry), rpath)
            print(f"  -> {rpath}")
            n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--restart", action="store_true", help="Restart HA core after copy")
    args = ap.parse_args()

    env = load_env()

    print(f"Connecting to {env['HA_SSH_USER']}@{env['HA_SSH_HOST']}:{env.get('HA_SSH_PORT', '22')}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        env["HA_SSH_HOST"],
        port=int(env.get("HA_SSH_PORT", "22")),
        username=env["HA_SSH_USER"],
        password=env.get("HA_SSH_PASSWORD") or None,
        look_for_keys=False,
        allow_agent=False,
    )

    sftp = ssh.open_sftp()
    print(f"Syncing {LOCAL_DIR} -> {REMOTE_DIR}")
    count = upload_dir(sftp, LOCAL_DIR, REMOTE_DIR)
    sftp.close()
    print(f"\nUploaded {count} files.")

    if args.restart:
        print("\nRestarting HA core...")
        stdin, stdout, stderr = ssh.exec_command("ha core restart")
        print(stdout.read().decode(errors="replace"))
        err = stderr.read().decode(errors="replace")
        if err:
            print("STDERR:", err, file=sys.stderr)

    ssh.close()
    print("\n✓ Done. If --restart not used: Developer Tools -> YAML -> Restart.")


if __name__ == "__main__":
    main()
