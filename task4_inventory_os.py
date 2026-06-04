#!/usr/bin/env python3
"""
Task 4: Inventory openSUSE Leap 15.5 — OS info and installed packages.
All data is read from the system, no hardcode.
Must be run ON the openSUSE Leap 15.5 system (not the dev machine).

Usage on openSUSE Leap 15.5:
    python3 task4_inventory_os.py

Output: result_task_4.json
"""

import json
import os
import subprocess
import re
import platform


def read_os_release():
    """Read /etc/os-release for OS metadata"""
    os_info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    os_info[k.strip()] = v.strip().strip('"')
    except FileNotFoundError:
        # Fallback
        os_info = {
            "NAME": platform.system(),
            "VERSION": platform.release(),
        }
    return os_info


def get_os_info():
    """Build OS section of the result"""
    rel = read_os_release()
    name = rel.get("NAME", "Unknown")
    version = rel.get("VERSION", "")
    version_id = rel.get("VERSION_ID", "")
    arch = platform.machine()
    os_id = rel.get("ID", "")
    pretty_name = rel.get("PRETTY_NAME", "")
    codename = rel.get("VERSION_CODENAME", rel.get("CODENAME", None))
    description = pretty_name if pretty_name else f"{name} {version}"

    return {
        "name": name,
        "version": version,
        "arch": arch,
        "id": os_id,
        "version_id": version_id,
        "description": description,
        "codename": codename if codename else None
    }


def parse_rpm_packages():
    """
    Parse installed packages using rpm.
    Uses rpm queryformat to get structured data.
    """
    packages = []

    # rpm query format: name|version|arch|summary|size
    fmt = "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SUMMARY}|%{SIZE}\\n"
    try:
        result = subprocess.run(
            ["rpm", "-qa", "--queryformat", fmt],
            capture_output=True,
            text=True,
            timeout=120
        )
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) < 4:
                continue
            name = parts[0].strip()
            version = parts[1].strip()
            arch = parts[2].strip() if len(parts) > 2 else None
            summary = parts[3].strip() if len(parts) > 3 else None
            size_str = parts[4].strip() if len(parts) > 4 else None

            # Take first sentence of summary
            if summary:
                first_sentence = re.split(r'[.!?\n]', summary)[0].strip()
                description = first_sentence if first_sentence else summary
            else:
                description = None

            size = None
            if size_str and size_str.isdigit():
                size = int(size_str)

            pkg = {
                "name": name,
                "version": version,
                "arch": arch if arch else None,
            }
            if description:
                pkg["description"] = description
            if size is not None:
                pkg["size"] = size

            packages.append(pkg)

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"rpm not available or timed out: {e}")
        print("Falling back to zypper...")
        packages = parse_zypper_packages()

    return sorted(packages, key=lambda p: p["name"].lower())


def parse_zypper_packages():
    """
    Fallback: parse installed packages using zypper (openSUSE package manager).
    """
    packages = []
    try:
        result = subprocess.run(
            ["zypper", "--non-interactive", "packages", "--installed-only"],
            capture_output=True,
            text=True,
            timeout=120
        )
        lines = result.stdout.strip().split("\n")
        # Skip header lines (first 4)
        for line in lines[4:]:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 5:
                continue
            # Format: Status | Repo | Name | Version | Arch
            name = parts[2]
            version = parts[3]
            arch = parts[4] if len(parts) > 4 else None
            if not name or name == "Name":
                continue
            packages.append({
                "name": name,
                "version": version,
                "arch": arch
            })
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"zypper not available: {e}")

    return packages


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result_task_4.json")

    print("Reading OS information...")
    os_info = get_os_info()
    print(f"  OS: {os_info['name']} {os_info['version']} ({os_info['arch']})")

    print("Reading installed packages (this may take a moment)...")
    packages = parse_rpm_packages()
    print(f"  Found {len(packages)} packages")

    result = {
        "OS": os_info,
        "packages": packages
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\n=== Task 4 Summary ===")
    print(f"OS: {os_info['description']}")
    print(f"Architecture: {os_info['arch']}")
    print(f"Total packages: {len(packages)}")
    print(f"\nResult saved to: {output_path}")

    # Versioning analysis
    print(f"\n--- Package versioning examples ---")
    for pkg in packages[:5]:
        print(f"  {pkg['name']}: {pkg['version']}")


if __name__ == "__main__":
    main()
