#!/usr/bin/env python3
"""
Task 5: OSV-scanner workflow on openSUSE Leap 15.5.
Must be run on the openSUSE Leap 15.5 system.
All output files are written to the same folder as this script.

Steps:
  1  — inventory before update  → sbom_before.cdx.json, packages_before.json
  2  — osv-scanner before       → osv_before.json
  3  — sudo zypper update
  4  — inventory after + scan   → sbom_after.cdx.json, packages_after.json, osv_after.json
  5  — compare + report         → result_task_5.json, result_task_5.md

Install osv-scanner on openSUSE:
  curl -L https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 \\
       -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

Usage:
  python3 task5_osv_scan.py              # all steps
  python3 task5_osv_scan.py --step 1    # single step
"""

import json
import os
import subprocess
import datetime
import re
import platform
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# All intermediate and result files go here
BEFORE_SBOM     = os.path.join(SCRIPT_DIR, "sbom_before.cdx.json")
AFTER_SBOM      = os.path.join(SCRIPT_DIR, "sbom_after.cdx.json")
BEFORE_OSV      = os.path.join(SCRIPT_DIR, "osv_before.json")
AFTER_OSV       = os.path.join(SCRIPT_DIR, "osv_after.json")
PKG_BEFORE      = os.path.join(SCRIPT_DIR, "packages_before.json")
PKG_AFTER       = os.path.join(SCRIPT_DIR, "packages_after.json")
COMPARE_OUT     = os.path.join(SCRIPT_DIR, "result_task_5.json")
COMPARE_MD      = os.path.join(SCRIPT_DIR, "result_task_5.md")


# ── helpers ──────────────────────────────────────────────────────────────────

def read_os_release():
    info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip().strip('"')
    except FileNotFoundError:
        pass
    return info


def get_installed_packages():
    fmt = "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SUMMARY}|%{SIZE}\\n"
    result = subprocess.run(["rpm", "-qa", "--queryformat", fmt],
                            capture_output=True, text=True, timeout=180)
    packages = []
    for line in result.stdout.strip().split("\n"):
        parts = line.split("|")
        if len(parts) < 2:
            continue
        packages.append({
            "name":    parts[0].strip(),
            "version": parts[1].strip(),
            "arch":    parts[2].strip() if len(parts) > 2 else "noarch",
            "description": (re.split(r'[.!\n]', parts[3].strip())[0].strip()
                            if len(parts) > 3 and parts[3].strip() else None),
            "size": (int(parts[4]) if len(parts) > 4 and parts[4].strip().isdigit() else None),
        })
    return sorted(packages, key=lambda p: p["name"].lower())


def generate_cyclonedx_sbom(packages, output_path, label="snapshot"):
    rel = read_os_release()
    os_version = rel.get("VERSION_ID", "15.5")
    os_name    = rel.get("NAME", "openSUSE Leap")
    arch       = platform.machine()
    ts         = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    components = []
    for pkg in packages:
        comp = {
            "type":    "library",
            "bom-ref": f"pkg:rpm/{pkg['name']}@{pkg['version']}?arch={pkg['arch']}",
            "name":    pkg["name"],
            "version": pkg["version"],
            "purl":    f"pkg:rpm/opensuse.leap/{pkg['name']}@{pkg['version']}"
                       f"?arch={pkg['arch']}&distro=leap-{os_version}",
        }
        if pkg.get("description"):
            comp["description"] = pkg["description"]
        components.append(comp)

    sbom = {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.6",
        "version":      1,
        "serialNumber": f"urn:uuid:lab3-task5-{label}-"
                        f"{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "metadata": {
            "timestamp": ts,
            "component": {
                "type":    "operating-system",
                "name":    os_name,
                "version": f"{os_version} ({arch})",
            }
        },
        "components": components,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
    print(f"  SBOM → {output_path}  ({len(components)} components)")


def run_osv_scanner(sbom_path, output_path):
    print(f"  osv-scanner on {os.path.basename(sbom_path)}...")
    # JSON report
    res = subprocess.run(
        ["osv-scanner", "--sbom", sbom_path, "--format", "json", "--output", output_path],
        capture_output=True, text=True, timeout=300
    )
    if res.returncode not in (0, 1):
        print(f"  osv-scanner error: {res.stderr[:300]}")
        return
    # Human-readable text report
    txt_path = output_path.replace(".json", "_text.txt")
    res2 = subprocess.run(["osv-scanner", "--sbom", sbom_path],
                          capture_output=True, text=True, timeout=300)
    with open(txt_path, "w") as f:
        f.write(res2.stdout + res2.stderr)
    print(f"  Done → {output_path}")


def load_osv_results(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        vulns = []
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                pi = pkg.get("package", {})
                for v in pkg.get("vulnerabilities", []):
                    sev_list = v.get("severity", [])
                    sev = sev_list[0].get("score", "UNKNOWN") if sev_list else \
                          v.get("database_specific", {}).get("severity", "UNKNOWN")
                    vulns.append({
                        "package":   pi.get("name"),
                        "version":   pi.get("version"),
                        "ecosystem": pi.get("ecosystem"),
                        "id":        v.get("id"),
                        "aliases":   v.get("aliases", []),
                        "summary":   v.get("summary", ""),
                        "severity":  sev,
                    })
        return vulns
    except Exception as e:
        print(f"  Parse error: {e}")
        return []


def compare_results(before_pkgs, after_pkgs, before_vulns, after_vulns):
    bp = {p["name"]: p["version"] for p in before_pkgs}
    ap = {p["name"]: p["version"] for p in after_pkgs}
    updated = [{"name": n, "before": bp[n], "after": ap[n]}
               for n in bp if n in ap and bp[n] != ap[n]]
    bv = {v["id"] for v in before_vulns}
    av = {v["id"] for v in after_vulns}
    return {
        "packages": {
            "before_count":          len(before_pkgs),
            "after_count":           len(after_pkgs),
            "new_packages":          [n for n in ap if n not in bp],
            "removed_packages":      [n for n in bp if n not in ap],
            "updated_packages_count": len(updated),
            "updated_packages":      updated[:50],
        },
        "vulnerabilities": {
            "before_count": len(before_vulns),
            "after_count":  len(after_vulns),
            "fixed_count":  len(bv - av),
            "fixed_ids":    sorted(bv - av),
            "new_count":    len(av - bv),
            "new_ids":      sorted(av - bv),
        },
    }


def generate_md(comparison):
    p = comparison["packages"]
    v = comparison["vulnerabilities"]
    lines = [
        "# Задача 5: Сравнение до/после обновления (openSUSE Leap 15.5)", "",
        "## Шаг 5 — Сравнение пакетов", "",
        "| Параметр | До | После |",
        "|----------|----|-------|",
        f"| Пакетов | {p['before_count']} | {p['after_count']} |",
        f"| Новых | — | {len(p['new_packages'])} |",
        f"| Удалённых | {len(p['removed_packages'])} | — |",
        f"| Обновлённых | — | {p['updated_packages_count']} |",
        "",
    ]
    if p["updated_packages"]:
        lines += ["### Примеры обновлённых пакетов", "",
                  "| Пакет | До | После |", "|------|----|-------|"]
        for u in p["updated_packages"][:20]:
            lines.append(f"| {u['name']} | {u['before']} | {u['after']} |")
        lines.append("")
    lines += [
        "## Шаг 5 — Сравнение уязвимостей (osv-scanner)", "",
        "| Параметр | До | После |",
        "|----------|----|-------|",
        f"| Уязвимостей | {v['before_count']} | {v['after_count']} |",
        f"| Устранено | — | {v['fixed_count']} |",
        f"| Новых | — | {v['new_count']} |",
        "",
    ]
    if v["fixed_ids"]:
        lines += ["### Устранённые уязвимости"]
        for vid in v["fixed_ids"][:20]:
            lines.append(f"- {vid}")
        lines.append("")
    lines += [
        "## Шаг 6 — Оценка качества инвентаризации (Задача 4)", "",
        "### Минимально достаточно",
        "- Имя, версия, архитектура пакета через `rpm -qa`",
        "- Базовая информация об ОС из `/etc/os-release`",
        "- Этого достаточно для формирования CycloneDX SBOM и сканирования osv-scanner", "",
        "### Избыточно",
        "- Поле `size` — не используется при анализе уязвимостей",
        "- Полное описание пакета — достаточно первого предложения или можно опустить", "",
        "### Чего не хватало",
        "- `source_rpm` — источник пакета, важен для upstream-трекинга",
        "- `install_time` — дата установки (когда появился потенциально уязвимый пакет)",
        "- `license` — лицензия (compliance)",
        "- Дерево зависимостей (`requires`/`provides`)",
        "- `vendor`/`packager` — для supply chain анализа", "",
        "### Сравнение с osv-scanner",
        "- osv-scanner идентифицирует пакеты через `purl` формата `pkg:rpm/...`",
        "- Наша инвентаризация полностью совместима при корректном указании `purl`",
        "- Количество пакетов может незначительно отличаться: osv-scanner фильтрует пакеты без PURL",
    ]
    return "\n".join(lines)


# ── steps ────────────────────────────────────────────────────────────────────

def step1_before():
    print("\n=== Step 1: Inventory before update ===")
    pkgs = get_installed_packages()
    with open(PKG_BEFORE, "w") as f:
        json.dump(pkgs, f, indent=2)
    generate_cyclonedx_sbom(pkgs, BEFORE_SBOM, label="before")
    print(f"  Packages: {len(pkgs)}")


def step2_scan_before():
    print("\n=== Step 2: OSV scan before update ===")
    run_osv_scanner(BEFORE_SBOM, BEFORE_OSV)


def step3_update():
    print("\n=== Step 3: System update (sudo zypper update) ===")
    subprocess.run(["sudo", "zypper", "--non-interactive", "update"], timeout=600)
    print("  Done.")


def step4_after():
    print("\n=== Step 4: Inventory + OSV scan after update ===")
    pkgs = get_installed_packages()
    with open(PKG_AFTER, "w") as f:
        json.dump(pkgs, f, indent=2)
    generate_cyclonedx_sbom(pkgs, AFTER_SBOM, label="after")
    run_osv_scanner(AFTER_SBOM, AFTER_OSV)
    print(f"  Packages: {len(pkgs)}")


def step5_compare():
    print("\n=== Step 5: Compare results ===")
    with open(PKG_BEFORE) as f: before_pkgs = json.load(f)
    with open(PKG_AFTER)  as f: after_pkgs  = json.load(f)
    before_vulns = load_osv_results(BEFORE_OSV)
    after_vulns  = load_osv_results(AFTER_OSV)

    cmp = compare_results(before_pkgs, after_pkgs, before_vulns, after_vulns)
    result = {
        "before": {"package_count": len(before_pkgs), "vulnerability_count": len(before_vulns)},
        "after":  {"package_count": len(after_pkgs),  "vulnerability_count": len(after_vulns)},
        "comparison": cmp,
    }
    with open(COMPARE_OUT, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    with open(COMPARE_MD, "w", encoding="utf-8") as f:
        f.write(generate_md(cmp))

    p, v = cmp["packages"], cmp["vulnerabilities"]
    print(f"  Packages  : {p['before_count']} → {p['after_count']}  (updated: {p['updated_packages_count']})")
    print(f"  Vulns     : {v['before_count']} → {v['after_count']}  (fixed: {v['fixed_count']})")
    print(f"  Saved     : {COMPARE_OUT}")
    print(f"            : {COMPARE_MD}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--step", choices=["1","2","3","4","5","all"], default="all")
    s = parser.parse_args().step
    if s in ("1","all"): step1_before()
    if s in ("2","all"): step2_scan_before()
    if s in ("3","all"): step3_update()
    if s in ("4","all"): step4_after()
    if s in ("5","all"): step5_compare()


if __name__ == "__main__":
    main()
