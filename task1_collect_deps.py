#!/usr/bin/env python3
"""
Task 1: Collect all dependencies from Spring Boot project.
Parses spring-boot-dependencies/build.gradle (BOM) and all subproject build.gradle files.

Output: result_task_1.json  (в той же папке, где лежит этот скрипт)

Usage:
    python3 task1_collect_deps.py [--project /path/to/spring-boot-main]
"""

import re
import json
import os
import argparse

# По умолчанию ищем проект рядом со скриптом: ./spring-boot-main
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROJECT = os.path.join(SCRIPT_DIR, "spring-boot-main")


def read_gradle_properties(path):
    props = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return props


def resolve_version(version_str, props):
    match = re.match(r'\$\{(.+?)\}', version_str)
    if match:
        key = match.group(1)
        return props.get(key, version_str)
    return version_str


def parse_bom(bom_path, props):
    with open(bom_path) as f:
        content = f.read()

    dependencies = []
    library_pattern = re.compile(
        r'library\("([^"]+)",\s*"([^"]+)"\)\s*\{(.*?)\n\t\}',
        re.DOTALL
    )

    for lib_match in library_pattern.finditer(content):
        lib_name = lib_match.group(1)
        lib_version = resolve_version(lib_match.group(2), props)
        lib_body = lib_match.group(3)

        site_match = re.search(r'site\("([^"]+)"\)', lib_body)
        site_url = site_match.group(1) if site_match else None

        group_pattern = re.compile(r'group\("([^"]+)"\)\s*\{(.*?)\}', re.DOTALL)
        for group_match in group_pattern.finditer(lib_body):
            group_id = group_match.group(1)
            group_body = group_match.group(2)

            modules_match = re.search(r'modules\s*=\s*\[(.*?)\]', group_body, re.DOTALL)
            if modules_match:
                for module in re.findall(r'"([^"]+)"', modules_match.group(1)):
                    url = site_url or f"https://search.maven.org/artifact/{group_id}/{module}/{lib_version}/jar"
                    dependencies.append({
                        "name": f"{group_id}:{module}",
                        "version": lib_version,
                        "ecosystem": "maven",
                        "url": url,
                        "purl": f"pkg:maven/{group_id}/{module}@{lib_version}"
                    })

            for bom_artifact in re.findall(r'bom\("([^"]+)"\)', group_body):
                url = site_url or f"https://search.maven.org/artifact/{group_id}/{bom_artifact}/{lib_version}/pom"
                dependencies.append({
                    "name": f"{group_id}:{bom_artifact}",
                    "version": lib_version,
                    "ecosystem": "maven",
                    "url": url,
                    "purl": f"pkg:maven/{group_id}/{bom_artifact}@{lib_version}"
                })

            plugins_match = re.search(r'plugins\s*=\s*\[(.*?)\]', group_body, re.DOTALL)
            if plugins_match:
                for plugin in re.findall(r'"([^"]+)"', plugins_match.group(1)):
                    url = site_url or f"https://search.maven.org/artifact/{group_id}/{plugin}/{lib_version}/jar"
                    dependencies.append({
                        "name": f"{group_id}:{plugin}",
                        "version": lib_version,
                        "ecosystem": "maven",
                        "url": url,
                        "purl": f"pkg:maven/{group_id}/{plugin}@{lib_version}"
                    })

    return dependencies


def parse_subproject_build_gradle(gradle_path, props):
    with open(gradle_path) as f:
        content = f.read()

    deps = []
    dep_pattern = re.compile(
        r'(?:api|implementation|compileOnly|runtimeOnly|annotationProcessor|'
        r'testImplementation|optional|testCompileOnly|testFixturesCompileOnly|'
        r'testRuntimeOnly|testFixturesImplementation)\s*\("([^"]+:[^"]+:[^"]+)"\)'
    )
    for m in dep_pattern.finditer(content):
        parts = m.group(1).split(":")
        if len(parts) == 3:
            group_id, artifact_id, version = parts
            version = resolve_version(version, props)
            deps.append({
                "name": f"{group_id}:{artifact_id}",
                "version": version,
                "ecosystem": "maven",
                "url": f"https://search.maven.org/artifact/{group_id}/{artifact_id}/{version}/jar",
                "purl": f"pkg:maven/{group_id}/{artifact_id}@{version}"
            })
    return deps


def collect_all_dependencies(project_root):
    props = read_gradle_properties(os.path.join(project_root, "gradle.properties"))

    bom_path = os.path.join(project_root, "platform", "spring-boot-dependencies", "build.gradle")
    all_deps = parse_bom(bom_path, props)

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "buildSrc"]
        for fname in files:
            if fname == "build.gradle":
                fpath = os.path.join(root, fname)
                if "spring-boot-dependencies" not in fpath:
                    sub_deps = parse_subproject_build_gradle(fpath, props)
                    all_deps.extend(sub_deps)

    # Deduplicate by purl
    seen = {}
    for dep in all_deps:
        key = dep["purl"]
        if key not in seen:
            seen[key] = dep

    result = sorted(seen.values(), key=lambda x: x["name"])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", default=DEFAULT_PROJECT,
                        help=f"Path to spring-boot-main (default: {DEFAULT_PROJECT})")
    args = parser.parse_args()

    project_root = os.path.abspath(args.project)
    print(f"Scanning project: {project_root}")

    deps = collect_all_dependencies(project_root)

    output_path = os.path.join(SCRIPT_DIR, "result_task_1.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(deps, f, indent=2, ensure_ascii=False)

    from collections import Counter
    eco_counts = Counter(d["ecosystem"] for d in deps)
    print(f"\n=== Task 1 Summary ===")
    print(f"Total dependencies: {len(deps)}")
    print(f"\nBy ecosystem:")
    for eco, count in eco_counts.most_common():
        print(f"  {eco}: {count}")
    print(f"\nResult saved to: {output_path}")


if __name__ == "__main__":
    main()
