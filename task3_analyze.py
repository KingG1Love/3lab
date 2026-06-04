#!/usr/bin/env python3
"""
Task 3: Analyze result_task_2.json and produce a vulnerability analysis table.
Outputs:
  - result_task_3.json  — structured data
  - result_task_3.md    — human-readable Markdown table
"""

import json
import os


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}

REMEDIATION_STRATEGIES = {
    "CRITICAL": "Немедленное обновление (upgrade). КРИТИЧЕСКАЯ уязвимость — обновить до secure_version как можно скорее. При невозможности обновления — изолировать компонент или использовать WAF/патч.",
    "HIGH": "Плановое обновление в ближашее время. HIGH уязвимость — обновить до secure_version. Приоритизировать перед следующим релизом.",
    "MODERATE": "Обновление в следующем релизном цикле. MODERATE — включить в план обновлений, отслеживать появление новых векторов атак.",
    "LOW": "Обновление при следующем крупном апдейте. LOW — зафиксировать, обновить при удобном случае или при мажорном апгрейде зависимостей.",
    "UNKNOWN": "Ручной анализ. Уточнить критичность через NVD/OSV, принять решение об обновлении.",
}


def determine_strategy(vulns):
    """Determine remediation strategy based on highest severity vulnerability"""
    if not vulns:
        return "Уязвимостей не обнаружено"
    severities = [v.get("severity", "UNKNOWN") for v in vulns]
    highest = min(severities, key=lambda s: SEVERITY_ORDER.get(s, 99))
    return REMEDIATION_STRATEGIES.get(highest, REMEDIATION_STRATEGIES["UNKNOWN"])


def main():
    input_path = os.path.join(os.path.dirname(__file__), "../task2/result_task_2.json")
    output_json = os.path.join(os.path.dirname(__file__), "result_task_3.json")
    output_md = os.path.join(os.path.dirname(__file__), "result_task_3.md")

    with open(input_path) as f:
        deps = json.load(f)

    # Filter only vulnerable dependencies
    vuln_deps = [d for d in deps if d.get("vulnerabilities")]

    # Count vulnerabilities per dependency
    table_rows = []
    for dep in vuln_deps:
        vulns = dep["vulnerabilities"]
        counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "UNKNOWN": 0}
        for v in vulns:
            sev = v.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1

        row = {
            "name": dep["name"],
            "version": dep["version"],
            "ecosystem": dep["ecosystem"],
            "total_vulnerabilities": len(vulns),
            "by_severity": counts,
            "secure_version": dep.get("secure_version"),
            "remediation_strategy": determine_strategy(vulns),
            "vulnerabilities": vulns  # keep detail
        }
        table_rows.append(row)

    # Sort by total vulnerabilities descending, then by highest severity
    def sort_key(row):
        sev_counts = row["by_severity"]
        return (
            -row["total_vulnerabilities"],
            sev_counts.get("CRITICAL", 0) * -1,
            sev_counts.get("HIGH", 0) * -1,
        )

    table_rows.sort(key=sort_key)

    # Save JSON
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(table_rows, f, indent=2, ensure_ascii=False)

    # Build Markdown table
    lines = []
    lines.append("# Анализ уязвимых зависимостей Spring Boot")
    lines.append("")
    lines.append(f"**Всего уязвимых зависимостей:** {len(table_rows)}")
    lines.append("")
    lines.append("## Таблица уязвимостей (по убыванию количества)")
    lines.append("")
    lines.append(
        "| Зависимость | Версия | Экосистема | CRITICAL | HIGH | MODERATE | LOW | UNKNOWN | Всего | Безопасная версия | Стратегия устранения |"
    )
    lines.append(
        "|-------------|--------|------------|----------|------|----------|-----|---------|-------|-------------------|----------------------|"
    )

    for row in table_rows:
        sc = row["by_severity"]
        name = row["name"]
        ver = row["version"]
        eco = row["ecosystem"]
        crit = sc.get("CRITICAL", 0)
        high = sc.get("HIGH", 0)
        mod = sc.get("MODERATE", 0)
        low = sc.get("LOW", 0)
        unk = sc.get("UNKNOWN", 0)
        total = row["total_vulnerabilities"]
        secure = row.get("secure_version") or "Нет данных"
        strategy = row["remediation_strategy"].split(".")[0]  # first sentence for table brevity
        lines.append(
            f"| `{name}` | {ver} | {eco} | {crit} | {high} | {mod} | {low} | {unk} | **{total}** | {secure} | {strategy} |"
        )

    lines.append("")
    lines.append("## Стратегии устранения")
    lines.append("")
    for sev, strategy in REMEDIATION_STRATEGIES.items():
        lines.append(f"### {sev}")
        lines.append(strategy)
        lines.append("")

    lines.append("## Детали уязвимостей по зависимостям")
    lines.append("")
    for row in table_rows[:30]:  # show top 30 in detail
        lines.append(f"### `{row['name']}` @ {row['version']}")
        lines.append(f"- **Экосистема:** {row['ecosystem']}")
        lines.append(f"- **Безопасная версия:** {row.get('secure_version') or 'Нет данных'}")
        lines.append(f"- **Стратегия:** {row['remediation_strategy']}")
        lines.append("")
        lines.append("| GHSA | Severity | Уязвимый диапазон | Первая исправленная версия |")
        lines.append("|------|----------|-------------------|---------------------------|")
        for v in row["vulnerabilities"]:
            ghsa = v.get("name", "")
            sev = v.get("severity", "")
            vrange = v.get("vulnerable_range", "")
            fpv = v.get("first_patched_version") or "—"
            lines.append(f"| {ghsa} | {sev} | `{vrange}` | {fpv} |")
        lines.append("")

    with open(output_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # Print summary
    total_vulns = sum(r["total_vulnerabilities"] for r in table_rows)
    all_sev = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "UNKNOWN": 0}
    for row in table_rows:
        for sev, cnt in row["by_severity"].items():
            all_sev[sev] = all_sev.get(sev, 0) + cnt

    print(f"\n=== Task 3 Summary ===")
    print(f"Vulnerable dependencies: {len(table_rows)}")
    print(f"Total vulnerabilities: {total_vulns}")
    print(f"\nBy severity:")
    for sev in ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"]:
        print(f"  {sev}: {all_sev.get(sev, 0)}")
    print(f"\nTop 5 most vulnerable dependencies:")
    for row in table_rows[:5]:
        print(f"  {row['name']} @ {row['version']}: {row['total_vulnerabilities']} vulns")
    print(f"\nResults saved to:")
    print(f"  {output_json}")
    print(f"  {output_md}")


if __name__ == "__main__":
    main()
