#!/usr/bin/env python3
"""
Task 3: Analyze result_task_2.json — vulnerability table with remediation strategy.
Reads result_task_2.json (same folder), outputs result_task_3.json + result_task_3.md.

Usage:
    python3 task3_analyze.py
"""

import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}

REMEDIATION_STRATEGIES = {
    "CRITICAL": (
        "Немедленное обновление (upgrade). КРИТИЧЕСКАЯ уязвимость — обновить до secure_version "
        "как можно скорее. При невозможности обновления — изолировать компонент или использовать WAF/патч."
    ),
    "HIGH": (
        "Плановое обновление в ближайшем спринте. HIGH уязвимость — обновить до secure_version. "
        "Приоритизировать перед следующим релизом."
    ),
    "MODERATE": (
        "Обновление в следующем релизном цикле. MODERATE — включить в план обновлений, "
        "отслеживать появление новых векторов атак."
    ),
    "LOW": (
        "Обновление при следующем крупном апдейте. LOW — зафиксировать, обновить при "
        "удобном случае или при мажорном апгрейде зависимостей."
    ),
    "UNKNOWN": (
        "Ручной анализ. Уточнить критичность через NVD/OSV, принять решение об обновлении."
    ),
}


def determine_strategy(vulns):
    if not vulns:
        return "Уязвимостей не обнаружено"
    highest = min(
        (v.get("severity", "UNKNOWN") for v in vulns),
        key=lambda s: SEVERITY_ORDER.get(s, 99)
    )
    return REMEDIATION_STRATEGIES.get(highest, REMEDIATION_STRATEGIES["UNKNOWN"])


def main():
    input_path  = os.path.join(SCRIPT_DIR, "result_task_2.json")
    output_json = os.path.join(SCRIPT_DIR, "result_task_3.json")
    output_md   = os.path.join(SCRIPT_DIR, "result_task_3.md")

    with open(input_path) as f:
        deps = json.load(f)

    vuln_deps = [d for d in deps if d.get("vulnerabilities")]

    table_rows = []
    for dep in vuln_deps:
        vulns = dep["vulnerabilities"]
        counts = {s: 0 for s in ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")}
        for v in vulns:
            sev = v.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1

        table_rows.append({
            "name": dep["name"],
            "version": dep["version"],
            "ecosystem": dep["ecosystem"],
            "total_vulnerabilities": len(vulns),
            "by_severity": counts,
            "secure_version": dep.get("secure_version"),
            "remediation_strategy": determine_strategy(vulns),
            "vulnerabilities": vulns,
        })

    table_rows.sort(key=lambda r: (
        -r["total_vulnerabilities"],
        -r["by_severity"].get("CRITICAL", 0),
        -r["by_severity"].get("HIGH", 0),
    ))

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(table_rows, f, indent=2, ensure_ascii=False)

    # ── Markdown ────────────────────────────────────────────────────────────────
    lines = []
    lines += [
        "# Анализ уязвимых зависимостей Spring Boot", "",
        f"**Всего уязвимых зависимостей:** {len(table_rows)}", "",
        "## Таблица уязвимостей (по убыванию количества)", "",
        "| Зависимость | Версия | Экосистема | CRITICAL | HIGH | MODERATE | LOW | UNKNOWN | Всего | Безопасная версия | Стратегия |",
        "|-------------|--------|------------|----------|------|----------|-----|---------|-------|-------------------|-----------|",
    ]
    for r in table_rows:
        sc = r["by_severity"]
        secure = r.get("secure_version") or "—"
        strategy = r["remediation_strategy"].split(".")[0]
        lines.append(
            f"| `{r['name']}` | {r['version']} | {r['ecosystem']} "
            f"| {sc.get('CRITICAL',0)} | {sc.get('HIGH',0)} | {sc.get('MODERATE',0)} "
            f"| {sc.get('LOW',0)} | {sc.get('UNKNOWN',0)} | **{r['total_vulnerabilities']}** "
            f"| {secure} | {strategy} |"
        )

    lines += ["", "## Стратегии устранения", ""]
    for sev, strategy in REMEDIATION_STRATEGIES.items():
        lines += [f"### {sev}", strategy, ""]

    lines += ["## Детали (топ-30)", ""]
    for row in table_rows[:30]:
        lines += [
            f"### `{row['name']}` @ {row['version']}",
            f"- **Безопасная версия:** {row.get('secure_version') or '—'}",
            f"- **Стратегия:** {row['remediation_strategy']}", "",
            "| GHSA | Severity | Уязвимый диапазон | First patched |",
            "|------|----------|-------------------|---------------|",
        ]
        for v in row["vulnerabilities"]:
            lines.append(
                f"| {v.get('name','')} | {v.get('severity','')} "
                f"| `{v.get('vulnerable_range','')}` | {v.get('first_patched_version') or '—'} |"
            )
        lines.append("")

    with open(output_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # Summary
    all_sev = {s: 0 for s in ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")}
    for r in table_rows:
        for s, c in r["by_severity"].items():
            all_sev[s] = all_sev.get(s, 0) + c
    total_vulns = sum(r["total_vulnerabilities"] for r in table_rows)

    print(f"\n=== Task 3 Summary ===")
    print(f"Vulnerable deps: {len(table_rows)}  |  Total vulns: {total_vulns}")
    print("By severity:", "  ".join(f"{s}: {all_sev[s]}" for s in ("CRITICAL","HIGH","MODERATE","LOW","UNKNOWN") if all_sev[s]))
    print("Top 5:")
    for r in table_rows[:5]:
        print(f"  {r['name']} @ {r['version']}: {r['total_vulnerabilities']} vulns")
    print(f"\nSaved: {output_json}\n       {output_md}")


if __name__ == "__main__":
    main()
