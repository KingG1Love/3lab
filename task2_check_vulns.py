#!/usr/bin/env python3
"""
Task 2: Check dependencies against GitHub Security Advisory (GHSA) GraphQL API.
Reads result_task_1.json (same folder), outputs result_task_2.json (same folder).

УСКОРЕНИЕ: использует asyncio + aiohttp для параллельных запросов (20 workers).
Время выполнения снижается с ~100s до ~15-20s для 661 зависимости.

Usage:
    export GITHUB_TOKEN=ghp_your_token_here
    python3 task2_check_vulns.py
"""

import json
import os
import re
import asyncio
import aiohttp
import time
from packaging.version import Version, InvalidVersion

# ============================================================
# INSERT YOUR GITHUB TOKEN HERE (or set env var GITHUB_TOKEN)
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "YOUR_GITHUB_TOKEN_HERE")
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GHSA_API_URL = "https://api.github.com/graphql"
CONCURRENCY = 20          # parallel workers
REQUEST_DELAY = 0.05      # 50ms между запросами внутри каждого worker

QUERY = """
query($package: String!, $ecosystem: SecurityAdvisoryEcosystem!, $first: Int!) {
  securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: $first) {
    nodes {
      advisory {
        ghsaId
        summary
        severity
        publishedAt
      }
      vulnerableVersionRange
      firstPatchedVersion {
        identifier
      }
    }
  }
}
"""


def ecosystem_to_ghsa(ecosystem: str) -> str:
    return {
        "maven": "MAVEN", "npm": "NPM", "pypi": "PIP",
        "nuget": "NUGET", "rubygems": "RUBYGEMS", "go": "GO",
        "rust": "RUST", "composer": "COMPOSER",
    }.get(ecosystem.lower(), "MAVEN")


def parse_version_safe(v_str: str):
    try:
        v_clean = re.sub(r'[+].*$', '', v_str.strip())
        return Version(v_clean)
    except (InvalidVersion, TypeError):
        return None


def is_version_in_range(version_str: str, vuln_range: str) -> bool:
    pkg_ver = parse_version_safe(version_str)
    if pkg_ver is None:
        return False
    for condition in vuln_range.split(","):
        m = re.match(r'([><=!]+)\s*(.+)', condition.strip())
        if not m:
            continue
        op, ver_str = m.group(1), m.group(2).strip()
        cmp_ver = parse_version_safe(ver_str)
        if cmp_ver is None:
            continue
        if op == ">=" and not (pkg_ver >= cmp_ver): return False
        elif op == ">" and not (pkg_ver > cmp_ver): return False
        elif op == "<=" and not (pkg_ver <= cmp_ver): return False
        elif op == "<" and not (pkg_ver < cmp_ver): return False
        elif op == "=" and not (pkg_ver == cmp_ver): return False
    return True


def find_secure_version(dep_version: str, vulnerabilities: list) -> str | None:
    patched = []
    for vuln in vulnerabilities:
        fpv = vuln.get("first_patched_version")
        if fpv:
            pv = parse_version_safe(fpv)
            if pv:
                patched.append(pv)
    return str(max(patched)) if patched else None


async def query_ghsa_async(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                            package_name: str, ecosystem: str) -> list:
    variables = {
        "package": package_name,
        "ecosystem": ecosystem_to_ghsa(ecosystem),
        "first": 100
    }
    headers = {
        "Authorization": f"bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {"query": QUERY, "variables": variables}

    async with semaphore:
        for attempt in range(3):
            try:
                async with session.post(GHSA_API_URL, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 429:
                        wait = int(resp.headers.get("Retry-After", "60"))
                        print(f"\n  Rate limited — waiting {wait}s...")
                        await asyncio.sleep(wait)
                        continue
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    if "errors" in data:
                        return []
                    return data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
            except Exception:
                await asyncio.sleep(2 ** attempt)
        return []


async def process_dep(session, semaphore, dep, idx, total, counter, lock):
    name = dep["name"]
    version = dep["version"]
    ecosystem = dep["ecosystem"]
    package_query = name.split(":")[-1] if ":" in name else name

    nodes = await query_ghsa_async(session, semaphore, package_query, ecosystem)
    await asyncio.sleep(REQUEST_DELAY)

    applicable_vulns = []
    for node in nodes:
        vuln_range = node.get("vulnerableVersionRange", "")
        if is_version_in_range(version, vuln_range):
            advisory = node.get("advisory", {})
            fpv = node.get("firstPatchedVersion")
            applicable_vulns.append({
                "name": advisory.get("ghsaId", ""),
                "summary": advisory.get("summary", ""),
                "severity": advisory.get("severity", ""),
                "vulnerable_range": vuln_range,
                "first_patched_version": fpv.get("identifier") if fpv else None,
            })

    secure_version = find_secure_version(version, applicable_vulns) if applicable_vulns else None

    async with lock:
        counter[0] += 1
        done = counter[0]
        if done % 50 == 0 or done <= 5 or done == total:
            print(f"  [{done}/{total}] {name}:{version}"
                  + (f" — {len(applicable_vulns)} vulns" if applicable_vulns else ""))

    return {
        "name": dep["name"],
        "version": dep["version"],
        "ecosystem": dep["ecosystem"],
        "url": dep["url"],
        "purl": dep["purl"],
        "vulnerabilities": applicable_vulns,
        "secure_version": secure_version
    }


async def run_all(deps):
    semaphore = asyncio.Semaphore(CONCURRENCY)
    lock = asyncio.Lock()
    counter = [0]
    total = len(deps)

    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            process_dep(session, semaphore, dep, i, total, counter, lock)
            for i, dep in enumerate(deps)
        ]
        results = await asyncio.gather(*tasks)
    return results


def main():
    if GITHUB_TOKEN == "YOUR_GITHUB_TOKEN_HERE":
        print("ERROR: Set GITHUB_TOKEN env var or edit the GITHUB_TOKEN variable in this script.")
        raise SystemExit(1)

    input_path = os.path.join(SCRIPT_DIR, "result_task_1.json")
    output_path = os.path.join(SCRIPT_DIR, "result_task_2.json")

    print(f"Loading: {input_path}")
    with open(input_path) as f:
        deps = json.load(f)

    print(f"Checking {len(deps)} dependencies (concurrency={CONCURRENCY})...")
    t0 = time.time()
    results = asyncio.run(run_all(deps))
    elapsed = time.time() - t0

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    vuln_deps = [r for r in results if r["vulnerabilities"]]
    total_vulns = sum(len(r["vulnerabilities"]) for r in results)
    by_severity: dict[str, int] = {}
    for r in results:
        for v in r["vulnerabilities"]:
            sev = v.get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1

    print(f"\n=== Task 2 Summary ===")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Scanned: {len(results)}  |  Vulnerable: {len(vuln_deps)}  |  Total vulns: {total_vulns}")
    print("By severity:")
    for sev in ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"]:
        if by_severity.get(sev):
            print(f"  {sev}: {by_severity[sev]}")
    print(f"\nResult saved to: {output_path}")


if __name__ == "__main__":
    main()
