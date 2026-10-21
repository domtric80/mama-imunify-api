#!/usr/bin/env python3
import subprocess
import sys


MOUNT_POINT = "/run/mama-imunify"
REQUIRED_OPTIONS = {"nosuid", "nodev", "noexec"}


def verify_mount() -> tuple[bool, str]:
    result = subprocess.run(
        [
            "/usr/bin/findmnt",
            "--noheadings",
            "--raw",
            "--output",
            "FSTYPE,OPTIONS",
            "--mountpoint",
            MOUNT_POINT,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False, f"{MOUNT_POINT} is not a mounted filesystem"

    fields = result.stdout.strip().split(maxsplit=1)
    if len(fields) != 2:
        return False, f"could not read filesystem options for {MOUNT_POINT}"

    filesystem, raw_options = fields
    options = set(raw_options.split(","))
    missing = sorted(REQUIRED_OPTIONS - options)
    if filesystem != "tmpfs" or missing:
        details = []
        if filesystem != "tmpfs":
            details.append(f"filesystem is {filesystem}, expected tmpfs")
        if missing:
            details.append(f"missing mount options: {', '.join(missing)}")
        return False, "; ".join(details)

    return True, ""


def main() -> int:
    valid, reason = verify_mount()
    if not valid:
        print(f"Refusing to start gateway: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
