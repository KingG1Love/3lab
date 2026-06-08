#!/usr/bin/env python3
"""
Task 4: Inventory openSUSE Leap 15.5 — OS info and installed packages.
Must be run ON the openSUSE Leap 15.5 system.

Output: result_task_4.json  (same folder as this script)

Usage:
    python3 task4_inventory_os.py
"""

import json
import os
import subprocess
import re
import platform

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def read_os_release():
    os_info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    os_info[k.strip()] = v.strip().strip('"')
    except FileNotFoundError:
        os_info = {"NAME": platform.system(), "VERSION": platform.release()}
    return os_info


def get_os_info():
    rel = read_os_release()
    name = rel.get("NAME", "Unknown")
    version = rel.get("VERSION", "")
    pretty = rel.get("PRETTY_NAME", "")
    codename = rel.get("VERSION_CODENAME", rel.get("CODENAME", None))
    return {
        "name": name,
        "version": version,
        "arch": platform.machine(),
        "id": rel.get("ID", ""),
        "version_id": rel.get("VERSION_ID", ""),
        "description": pretty if pretty else f"{name} {version}",
        **({"codename": codename} if codename else {}),
    }


def parse_rpm_packages():
    fmt = "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SUMMARY}|%{SIZE}\\n"
    try:
        result = subprocess.run(
            ["rpm", "-qa", "--queryformat", fmt],
            capture_output=True, text=True, timeout=120
        )
        packages = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) < 2:
                continue
            name    = parts[0].strip()
            version = parts[1].strip()
            arch    = parts[2].strip() if len(parts) > 2 else None
            summary = parts[3].strip() if len(parts) > 3 else None
            size_s  = parts[4].strip() if len(parts) > 4 else None

            description = None
            if summary:
                first = re.split(r'[.!\n]', summary)[0].strip()
                description = first or summary

            pkg = {"name": name, "version": version}
            if arch:
                pkg["arch"] = arch
            if description:
                pkg["description"] = description
            if size_s and size_s.isdigit():
                pkg["size"] = int(size_s)
            packages.append(pkg)

        return sorted(packages, key=lambda p: p["name"].lower())

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"rpm unavailable ({e}), falling back to zypper...")
        return parse_zypper_packages()


def parse_zypper_packages():
    packages = []
    try:
        result = subprocess.run(
            ["zypper", "--non-interactive", "packages", "--installed-only"],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.strip().split("\n")[4:]:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 5 or parts[2] in ("Name", ""):
                continue
            packages.append({
                "name": parts[2],
                "version": parts[3],
                **({"arch": parts[4]} if parts[4] else {}),
            })
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"zypper unavailable: {e}")
    return packages


def main():
    output_path = os.path.join(SCRIPT_DIR, "result_task_4.json")

    print("Reading OS information...")
    os_info = get_os_info()
    print(f"  {os_info['name']} {os_info['version']} ({os_info['arch']})")

    print("Reading installed packages...")
    packages = parse_rpm_packages()
    print(f"  Found {len(packages)} packages")

    result = {"OS": os_info, "packages": packages}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\n=== Task 4 Summary ===")
    print(f"OS: {os_info['description']}")
    print(f"Total packages: {len(packages)}")
    print(f"Saved: {output_path}")
    print("\nPackage versioning examples:")
    for pkg in packages[:5]:
        print(f"  {pkg['name']}: {pkg['version']}")


if __name__ == "__main__":
    main()
