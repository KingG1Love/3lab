#!/usr/bin/env python3
"""
Task 2: Check dependencies against GitHub Security Advisory (GHSA) GraphQL API
Reads result_task_1.json, queries GHSA for each dependency, outputs result_task_2.json

Usage:
    export GITHUB_TOKEN=token
    python task2_check_vulns.py

OR edit GITHUB_TOKEN variable below.
"""

import json
import os
import time
import re
import requests
from packaging.version import Version, InvalidVersion

# ============================================================
# GITHUB TOKEN
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "GITHUB_TOKEN")
# ============================================================

GHSA_API_URL = "https://api.github.com/graphql"

HEADERS = {
    "Authorization": f"bearer {GITHUB_TOKEN}",
    "Content-Type": "application/json",
}

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
    """Map ecosystem names to GHSA enum values"""
    mapping = {
        "maven": "MAVEN",
        "npm": "NPM",
        "pypi": "PIP",
        "nuget": "NUGET",
        "rubygems": "RUBYGEMS",
        "go": "GO",
        "rust": "RUST",
        "composer": "COMPOSER",
    }
    return mapping.get(ecosystem.lower(), "MAVEN")


def query_ghsa(package_name: str, ecosystem: str) -> list:
    """Query GHSA GraphQL API for a package"""
    variables = {
        "package": package_name,
        "ecosystem": ecosystem_to_ghsa(ecosystem),
        "first": 100
    }

    for attempt in range(3):
        try:
            resp = requests.post(
                GHSA_API_URL,
                headers=HEADERS,
                json={"query": QUERY, "variables": variables},
                timeout=30
            )
            if resp.status_code == 429:
                print(f"  Rate limited, waiting 60s...")
                time.sleep(60)
                continue
            resp.raise_for_status()
            data = resp.json()
            if "errors" in data:
                return []
            nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
            return nodes
        except Exception as e:
            print(f"  Error querying {package_name}: {e}")
            time.sleep(2)
    return []


def parse_version_safe(v_str: str):
    """Try to parse a version string, return None if invalid"""
    try:
        # Strip epoch and local identifiers that break packaging.version
        v_clean = re.sub(r'[+].*$', '', v_str.strip())
        return Version(v_clean)
    except (InvalidVersion, TypeError):
        return None


def is_version_in_range(version_str: str, vuln_range: str) -> bool:
    """
    Check if version_str falls in vuln_range.
    GHSA uses semver expressions like: ">= 1.0.0, < 2.0.0" or "= 1.0.0"
    """
    pkg_ver = parse_version_safe(version_str)
    if pkg_ver is None:
        return False

    conditions = [c.strip() for c in vuln_range.split(",")]
    for condition in conditions:
        m = re.match(r'([><=!]+)\s*(.+)', condition.strip())
        if not m:
            continue
        op, ver_str = m.group(1), m.group(2).strip()
        cmp_ver = parse_version_safe(ver_str)
        if cmp_ver is None:
            continue
        if op == ">=" and not (pkg_ver >= cmp_ver):
            return False
        elif op == ">" and not (pkg_ver > cmp_ver):
            return False
        elif op == "<=" and not (pkg_ver <= cmp_ver):
            return False
        elif op == "<" and not (pkg_ver < cmp_ver):
            return False
        elif op == "=" and not (pkg_ver == cmp_ver):
            return False
    return True


def find_secure_version(dep_version: str, vulnerabilities: list) -> str | None:
    """
    Find the minimum first_patched_version that resolves ALL vulnerabilities.
    Returns version string or None if no safe version found.
    """
    patched_versions = []
    for vuln in vulnerabilities:
        fpv = vuln.get("first_patched_version")
        if fpv:
            pv = parse_version_safe(fpv)
            if pv:
                patched_versions.append(pv)

    if not patched_versions:
        return None

    # The secure version must be >= all first_patched_versions
    return str(max(patched_versions))


def main():
    input_path = os.path.join(os.path.dirname(__file__), "../task1/result_task_1.json")
    output_path = os.path.join(os.path.dirname(__file__), "result_task_2.json")

    print("Loading dependencies from result_task_1.json...")
    with open(input_path) as f:
        deps = json.load(f)

    print(f"Checking {len(deps)} dependencies against GitHub Security Advisory...")
    print("This may take several minutes due to API rate limits.\n")

    results = []
    total = len(deps)

    for i, dep in enumerate(deps, 1):
        name = dep["name"]
        version = dep["version"]
        ecosystem = dep["ecosystem"]

        # For Maven, GHSA uses artifactId only (the part after ':')
        if ":" in name:
            package_query = name.split(":")[-1]  # use artifactId
        else:
            package_query = name

        if i % 20 == 0 or i <= 5:
            print(f"[{i}/{total}] Checking: {name}:{version}")

        nodes = query_ghsa(package_query, ecosystem)

        # Filter nodes that actually apply to this version
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

        result_entry = {
            "name": dep["name"],
            "version": dep["version"],
            "ecosystem": dep["ecosystem"],
            "url": dep["url"],
            "purl": dep["purl"],
            "vulnerabilities": applicable_vulns,
            "secure_version": secure_version
        }
        results.append(result_entry)

        # Polite delay to avoid rate limiting
        time.sleep(0.15)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Summary
    vuln_deps = [r for r in results if r["vulnerabilities"]]
    total_vulns = sum(len(r["vulnerabilities"]) for r in results)
    by_severity = {}
    for r in results:
        for v in r["vulnerabilities"]:
            sev = v.get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1

    print(f"\n=== Task 2 Summary ===")
    print(f"Total dependencies scanned: {len(results)}")
    print(f"Dependencies with vulnerabilities: {len(vuln_deps)}")
    print(f"Total vulnerabilities found: {total_vulns}")
    print(f"\nBy severity:")
    for sev in ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"]:
        if sev in by_severity:
            print(f"  {sev}: {by_severity[sev]}")
    print(f"\nResult saved to: {output_path}")


if __name__ == "__main__":
    main()
