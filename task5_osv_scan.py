#!/usr/bin/env python3
"""
Task 5: OSV-scanner workflow on openSUSE Leap 15.5
Run on the openSUSE Leap 15.5 system.

Steps:
  1. Generate CycloneDX SBOM from installed packages (before update)
  2. Run osv-scanner on it
  3. Update system (zypper update)
  4. Repeat steps 1-2
  5. Compare results

Requirements on openSUSE Leap 15.5:
  - osv-scanner (install via: curl -L https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner)
  - python3 (pre-installed)
  - sudo access for system update

Usage:
  python3 task5_osv_scan.py [--step 1|2|3|compare]
  Run without args to execute all steps sequentially.
"""

import json
import os
import subprocess
import sys
import datetime
import re
import platform
import argparse


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BEFORE_SBOM = os.path.join(SCRIPT_DIR, "sbom_before.cdx.json")
AFTER_SBOM = os.path.join(SCRIPT_DIR, "sbom_after.cdx.json")
BEFORE_OSV = os.path.join(SCRIPT_DIR, "osv_before.json")
AFTER_OSV = os.path.join(SCRIPT_DIR, "osv_after.json")
COMPARE_OUT = os.path.join(SCRIPT_DIR, "result_task_5.json")
COMPARE_MD = os.path.join(SCRIPT_DIR, "result_task_5.md")


def get_installed_packages_rpm():
    """Get installed packages via rpm -qa"""
    fmt = "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SUMMARY}|%{SIZE}\\n"
    result = subprocess.run(
        ["rpm", "-qa", "--queryformat", fmt],
        capture_output=True, text=True, timeout=180
    )
    packages = []
    for line in result.stdout.strip().split("\n"):
        parts = line.split("|")
        if len(parts) < 2:
            continue
        packages.append({
            "name": parts[0].strip(),
            "version": parts[1].strip(),
            "arch": parts[2].strip() if len(parts) > 2 else "noarch",
            "description": parts[3].strip() if len(parts) > 3 else None,
            "size": int(parts[4]) if len(parts) > 4 and parts[4].strip().isdigit() else None,
        })
    return sorted(packages, key=lambda p: p["name"].lower())


def generate_cyclonedx_sbom(packages, output_path, label="before"):
    """
    Generate CycloneDX 1.6 JSON SBOM from package list.
    Format: https://cyclonedx.org/docs/1.6/json/
    """
    # Read OS info
    os_info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    os_info[k.strip()] = v.strip().strip('"')
    except Exception:
        pass

    os_name = os_info.get("NAME", "openSUSE Leap")
    os_version = os_info.get("VERSION_ID", "15.5")
    arch = platform.machine()
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    components = []
    for pkg in packages:
        comp = {
            "type": "library",
            "bom-ref": f"pkg:rpm/{pkg['name']}@{pkg['version']}?arch={pkg['arch']}",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:rpm/opensuse.leap/{pkg['name']}@{pkg['version']}?arch={pkg['arch']}&distro=leap-{os_version}",
        }
        if pkg.get("description"):
            first = re.split(r'[.!\n]', pkg["description"])[0].strip()
            if first:
                comp["description"] = first
        components.append(comp)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:uuid:lab3-task5-{label}-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "operating-system",
                "name": os_name,
                "version": f"{os_version} ({arch})"
            }
        },
        "components": components
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

    print(f"  SBOM saved to {output_path} ({len(components)} components)")
    return sbom


def run_osv_scanner(sbom_path, output_path):
    """Run osv-scanner on a CycloneDX SBOM"""
    print(f"  Running osv-scanner on {sbom_path}...")
    cmd = [
        "osv-scanner",
        "--sbom", sbom_path,
        "--format", "json",
        "--output", output_path
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    # osv-scanner returns exit code 1 when vulnerabilities found — that's normal
    if result.returncode not in (0, 1):
        print(f"  osv-scanner error: {result.stderr}")
        return None

    # Also save human-readable output
    text_out = output_path.replace(".json", "_text.txt")
    cmd_text = ["osv-scanner", "--sbom", sbom_path]
    result_text = subprocess.run(cmd_text, capture_output=True, text=True, timeout=300)
    with open(text_out, "w") as f:
        f.write(result_text.stdout + result_text.stderr)

    print(f"  osv-scanner done. Results: {output_path}")
    return output_path


def update_system():
    """Update all system packages using zypper"""
    print("  Running: sudo zypper --non-interactive update")
    result = subprocess.run(
        ["sudo", "zypper", "--non-interactive", "update"],
        timeout=600
    )
    if result.returncode != 0:
        print("  WARNING: zypper update returned non-zero exit code")
    else:
        print("  System update complete.")


def load_osv_results(path):
    """Load and parse osv-scanner JSON output"""
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        # osv-scanner JSON format: {"results": [{"source": ..., "packages": [...]}]}
        vulns = []
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                pkg_info = pkg.get("package", {})
                for vuln in pkg.get("vulnerabilities", []):
                    vulns.append({
                        "package": pkg_info.get("name"),
                        "version": pkg_info.get("version"),
                        "ecosystem": pkg_info.get("ecosystem"),
                        "id": vuln.get("id"),
                        "aliases": vuln.get("aliases", []),
                        "summary": vuln.get("summary", ""),
                        "severity": _get_severity(vuln),
                    })
        return vulns
    except Exception as e:
        print(f"  Could not parse OSV results: {e}")
        return []


def _get_severity(vuln):
    severities = vuln.get("severity", [])
    if severities:
        return severities[0].get("score", "UNKNOWN")
    database_specific = vuln.get("database_specific", {})
    return database_specific.get("severity", "UNKNOWN")


def compare_results(before_packages, after_packages, before_vulns, after_vulns):
    """Compare before/after state"""

    before_pkg_map = {p["name"]: p["version"] for p in before_packages}
    after_pkg_map = {p["name"]: p["version"] for p in after_packages}

    # New packages after update
    new_packages = [n for n in after_pkg_map if n not in before_pkg_map]
    # Removed packages
    removed_packages = [n for n in before_pkg_map if n not in after_pkg_map]
    # Updated packages
    updated_packages = [
        {"name": n, "before": before_pkg_map[n], "after": after_pkg_map[n]}
        for n in before_pkg_map
        if n in after_pkg_map and before_pkg_map[n] != after_pkg_map[n]
    ]

    # Vulnerability comparison
    before_vuln_ids = {v["id"] for v in before_vulns}
    after_vuln_ids = {v["id"] for v in after_vulns}
    fixed_vulns = before_vuln_ids - after_vuln_ids
    new_vulns = after_vuln_ids - before_vuln_ids

    comparison = {
        "packages": {
            "before_count": len(before_packages),
            "after_count": len(after_packages),
            "new_packages": new_packages,
            "removed_packages": removed_packages,
            "updated_packages_count": len(updated_packages),
            "updated_packages": updated_packages[:50],  # cap at 50 for readability
        },
        "vulnerabilities": {
            "before_count": len(before_vulns),
            "after_count": len(after_vulns),
            "fixed_count": len(fixed_vulns),
            "fixed_ids": list(fixed_vulns),
            "new_count": len(new_vulns),
            "new_ids": list(new_vulns),
        }
    }
    return comparison


def generate_markdown_report(comparison, before_packages, after_packages, before_vulns, after_vulns):
    lines = []
    lines.append("# Отчёт по Задаче 5: Сравнение до и после обновления (openSUSE Leap 15.5)")
    lines.append("")
    lines.append("## Шаг 5: Сравнение пакетов и уязвимостей")
    lines.append("")

    pkg = comparison["packages"]
    vuln = comparison["vulnerabilities"]

    lines.append("### Пакеты")
    lines.append("")
    lines.append(f"| Параметр | До обновления | После обновления |")
    lines.append(f"|----------|--------------|-----------------|")
    lines.append(f"| Количество пакетов | {pkg['before_count']} | {pkg['after_count']} |")
    lines.append(f"| Новых пакетов после обновления | — | {len(pkg['new_packages'])} |")
    lines.append(f"| Удалённых пакетов | {len(pkg['removed_packages'])} | — |")
    lines.append(f"| Обновлённых пакетов | — | {pkg['updated_packages_count']} |")
    lines.append("")

    if pkg["updated_packages"]:
        lines.append("#### Примеры обновлённых пакетов (до 20)")
        lines.append("")
        lines.append("| Пакет | Версия до | Версия после |")
        lines.append("|-------|-----------|-------------|")
        for p in pkg["updated_packages"][:20]:
            lines.append(f"| {p['name']} | {p['before']} | {p['after']} |")
        lines.append("")

    lines.append("### Уязвимости (osv-scanner)")
    lines.append("")
    lines.append(f"| Параметр | До обновления | После обновления |")
    lines.append(f"|----------|--------------|-----------------|")
    lines.append(f"| Всего уязвимостей | {vuln['before_count']} | {vuln['after_count']} |")
    lines.append(f"| Устранено уязвимостей | — | {vuln['fixed_count']} |")
    lines.append(f"| Новых уязвимостей | — | {vuln['new_count']} |")
    lines.append("")

    if vuln["fixed_ids"]:
        lines.append("#### Устранённые уязвимости")
        for vid in sorted(vuln["fixed_ids"])[:20]:
            lines.append(f"- {vid}")
        lines.append("")

    lines.append("## Шаг 6: Оценка качества инвентаризации (Задача 4)")
    lines.append("")
    lines.append("### Что было минимально и достаточно")
    lines.append("- Получение имени, версии и архитектуры каждого пакета через `rpm -qa`")
    lines.append("- Получение базовой информации об ОС из `/etc/os-release`")
    lines.append("- Это достаточно для формирования SBOM в формате CycloneDX и последующего сканирования osv-scanner")
    lines.append("")
    lines.append("### Что было избыточным")
    lines.append("- Поле `size` — не требуется для анализа уязвимостей")
    lines.append("- Полное описание пакета (summary) — достаточно первого предложения или можно вовсе опустить")
    lines.append("")
    lines.append("### Чего не хватало для полноценной инвентаризации")
    lines.append("- `source_rpm` — источник пакета, важен для отслеживания upstream")
    lines.append("- `install_time` — дата установки, помогает понять когда появился потенциально уязвимый пакет")
    lines.append("- `license` — лицензия пакета, важно для compliance")
    lines.append("- Зависимости пакетов (`requires`/`provides`) — для построения дерева зависимостей")
    lines.append("- `vendor`/`packager` — для отслеживания цепочки поставки (supply chain)")
    lines.append("")
    lines.append("### Сравнение с osv-scanner SBOM")
    lines.append("- osv-scanner при сканировании системы использует `purl` (Package URL) для идентификации пакетов")
    lines.append("- Наша инвентаризация полностью совместима с форматом CycloneDX при указании `purl` в формате `pkg:rpm/...`")
    lines.append("- Количество пакетов может незначительно отличаться, так как osv-scanner может фильтровать пакеты без PURL или без версии")

    return "\n".join(lines)


def step1_before():
    print("\n=== STEP 1: Inventory before update ===")
    packages = get_installed_packages_rpm()
    print(f"  Found {len(packages)} packages")
    generate_cyclonedx_sbom(packages, BEFORE_SBOM, label="before")
    # Also save raw package list for comparison
    with open(os.path.join(SCRIPT_DIR, "packages_before.json"), "w") as f:
        json.dump(packages, f, indent=2)
    return packages


def step2_scan_before():
    print("\n=== STEP 2: OSV scan before update ===")
    return run_osv_scanner(BEFORE_SBOM, BEFORE_OSV)


def step3_update():
    print("\n=== STEP 3: System update ===")
    update_system()


def step4_after():
    print("\n=== STEP 4: Inventory after update ===")
    packages = get_installed_packages_rpm()
    print(f"  Found {len(packages)} packages")
    generate_cyclonedx_sbom(packages, AFTER_SBOM, label="after")
    with open(os.path.join(SCRIPT_DIR, "packages_after.json"), "w") as f:
        json.dump(packages, f, indent=2)

    print("\n=== OSV scan after update ===")
    run_osv_scanner(AFTER_SBOM, AFTER_OSV)
    return packages


def step5_compare():
    print("\n=== STEP 5: Compare results ===")
    with open(os.path.join(SCRIPT_DIR, "packages_before.json")) as f:
        before_packages = json.load(f)
    with open(os.path.join(SCRIPT_DIR, "packages_after.json")) as f:
        after_packages = json.load(f)

    before_vulns = load_osv_results(BEFORE_OSV)
    after_vulns = load_osv_results(AFTER_OSV)

    comparison = compare_results(before_packages, after_packages, before_vulns, after_vulns)

    result = {
        "before": {
            "package_count": len(before_packages),
            "vulnerability_count": len(before_vulns),
        },
        "after": {
            "package_count": len(after_packages),
            "vulnerability_count": len(after_vulns),
        },
        "comparison": comparison
    }

    with open(COMPARE_OUT, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    md = generate_markdown_report(comparison, before_packages, after_packages, before_vulns, after_vulns)
    with open(COMPARE_MD, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"\n=== Task 5 Summary ===")
    print(f"Packages before: {len(before_packages)}, after: {len(after_packages)}")
    print(f"Updated packages: {comparison['packages']['updated_packages_count']}")
    print(f"Vulnerabilities before: {len(before_vulns)}, after: {len(after_vulns)}")
    print(f"Fixed: {comparison['vulnerabilities']['fixed_count']}")
    print(f"\nResults saved to: {COMPARE_OUT}")
    print(f"Report saved to: {COMPARE_MD}")


def main():
    parser = argparse.ArgumentParser(description="Task 5: OSV scan workflow")
    parser.add_argument(
        "--step",
        choices=["1", "2", "3", "4", "5", "all"],
        default="all",
        help="Which step to run (default: all)"
    )
    args = parser.parse_args()

    step = args.step
    if step in ("1", "all"):
        step1_before()
    if step in ("2", "all"):
        step2_scan_before()
    if step in ("3", "all"):
        step3_update()
    if step in ("4", "all"):
        step4_after()
    if step in ("5", "all"):
        step5_compare()


if __name__ == "__main__":
    main()
