#!/usr/bin/env python3
"""
Task 1: Collect all dependencies from Spring Boot project
Outputs result_task_1.json
"""

import re
import json
import os

# Path to spring-boot project
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "../../spring-boot/spring-boot-main")

# Read gradle.properties for variable substitution
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
    """Replace ${var} references with actual values from gradle.properties"""
    match = re.match(r'\$\{(.+?)\}', version_str)
    if match:
        key = match.group(1)
        return props.get(key, version_str)
    return version_str


def parse_bom(bom_path, props):
    """Parse spring-boot-dependencies/build.gradle BOM file"""
    with open(bom_path) as f:
        content = f.read()

    dependencies = []

    # Find each library block
    library_pattern = re.compile(
        r'library\("([^"]+)",\s*"([^"]+)"\)\s*\{(.*?)\n\t\}',
        re.DOTALL
    )

    for lib_match in library_pattern.finditer(content):
        lib_name = lib_match.group(1)
        lib_version = resolve_version(lib_match.group(2), props)
        lib_body = lib_match.group(3)

        # Extract site URL
        site_match = re.search(r'site\("([^"]+)"\)', lib_body)
        site_url = site_match.group(1) if site_match else None

        # Find all group blocks inside this library
        group_pattern = re.compile(r'group\("([^"]+)"\)\s*\{(.*?)\}', re.DOTALL)
        for group_match in group_pattern.finditer(lib_body):
            group_id = group_match.group(1)
            group_body = group_match.group(2)

            # Extract modules
            modules_match = re.search(r'modules\s*=\s*\[(.*?)\]', group_body, re.DOTALL)
            if modules_match:
                modules_str = modules_match.group(1)
                modules = re.findall(r'"([^"]+)"', modules_str)
                for module in modules:
                    artifact_id = module
                    name = f"{group_id}:{artifact_id}"
                    url = site_url or f"https://search.maven.org/artifact/{group_id}/{artifact_id}/{lib_version}/jar"
                    purl = f"pkg:maven/{group_id}/{artifact_id}@{lib_version}"
                    dependencies.append({
                        "name": name,
                        "artifact_id": artifact_id,
                        "group_id": group_id,
                        "version": lib_version,
                        "ecosystem": "maven",
                        "url": url,
                        "purl": purl,
                        "source": "spring-boot-dependencies BOM"
                    })

            # Extract BOMs (bom entries also define artifacts)
            bom_matches = re.findall(r'bom\("([^"]+)"\)', group_body)
            for bom_artifact in bom_matches:
                name = f"{group_id}:{bom_artifact}"
                url = site_url or f"https://search.maven.org/artifact/{group_id}/{bom_artifact}/{lib_version}/pom"
                purl = f"pkg:maven/{group_id}/{bom_artifact}@{lib_version}"
                dependencies.append({
                    "name": name,
                    "artifact_id": bom_artifact,
                    "group_id": group_id,
                    "version": lib_version,
                    "ecosystem": "maven",
                    "url": url,
                    "purl": purl,
                    "source": "spring-boot-dependencies BOM (bom)"
                })

            # Extract plugins
            plugins_match = re.search(r'plugins\s*=\s*\[(.*?)\]', group_body, re.DOTALL)
            if plugins_match:
                plugins_str = plugins_match.group(1)
                plugins = re.findall(r'"([^"]+)"', plugins_str)
                for plugin in plugins:
                    name = f"{group_id}:{plugin}"
                    url = site_url or f"https://search.maven.org/artifact/{group_id}/{plugin}/{lib_version}/jar"
                    purl = f"pkg:maven/{group_id}/{plugin}@{lib_version}"
                    dependencies.append({
                        "name": name,
                        "artifact_id": plugin,
                        "group_id": group_id,
                        "version": lib_version,
                        "ecosystem": "maven",
                        "url": url,
                        "purl": purl,
                        "source": "spring-boot-dependencies BOM (plugin)"
                    })

    return dependencies


def parse_subproject_build_gradle(gradle_path, props):
    """Parse a subproject build.gradle to extract external dependencies with versions"""
    with open(gradle_path) as f:
        content = f.read()

    deps = []
    # Match dependency declarations with explicit group:artifact:version
    dep_pattern = re.compile(
        r'(?:api|implementation|compileOnly|runtimeOnly|annotationProcessor|testImplementation|optional|testCompileOnly|testFixturesCompileOnly|testRuntimeOnly|testFixturesImplementation)\s*\("([^"]+:[^"]+:[^"]+)"\)',
    )
    for m in dep_pattern.finditer(content):
        coord = m.group(1)
        parts = coord.split(":")
        if len(parts) == 3:
            group_id, artifact_id, version = parts
            version = resolve_version(version, props)
            name = f"{group_id}:{artifact_id}"
            url = f"https://search.maven.org/artifact/{group_id}/{artifact_id}/{version}/jar"
            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"
            deps.append({
                "name": name,
                "artifact_id": artifact_id,
                "group_id": group_id,
                "version": version,
                "ecosystem": "maven",
                "url": url,
                "purl": purl,
                "source": gradle_path
            })
    return deps


def collect_all_dependencies(project_root):
    props = read_gradle_properties(os.path.join(project_root, "gradle.properties"))

    bom_path = os.path.join(project_root, "platform", "spring-boot-dependencies", "build.gradle")
    all_deps = parse_bom(bom_path, props)

    # Also parse all subproject build.gradle files for explicit versioned deps
    for root, dirs, files in os.walk(project_root):
        # Skip hidden dirs and buildSrc
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

    return list(seen.values())


def main():
    project_root = os.path.abspath(PROJECT_ROOT)
    print(f"Scanning project: {project_root}")

    deps = collect_all_dependencies(project_root)

    # Build final output format
    result = []
    for d in deps:
        result.append({
            "name": d["name"],
            "version": d["version"],
            "ecosystem": d["ecosystem"],
            "url": d["url"],
            "purl": d["purl"]
        })

    # Sort by name
    result.sort(key=lambda x: x["name"])

    output_path = os.path.join(os.path.dirname(__file__), "result_task_1.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    # Print summary
    from collections import Counter
    eco_counts = Counter(d["ecosystem"] for d in result)
    print(f"\n=== Task 1 Summary ===")
    print(f"Total dependencies: {len(result)}")
    print(f"\nBy ecosystem:")
    for eco, count in eco_counts.most_common():
        print(f"  {eco}: {count}")
    print(f"\nResult saved to: {output_path}")


if __name__ == "__main__":
    main()
