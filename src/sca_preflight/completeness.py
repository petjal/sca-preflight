"""Completeness verification, BOM baseline calculation, archetypes, and git diff analysis.

Provides baseline drift checking, Detect output verification against expected BOM,
supplemental BDIO generation, and git diff delta analysis.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import tomllib
import urllib.parse
import uuid
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from sca_preflight.catalog import (
    ARCHIVE_EXTENSIONS,
    BINARY_BANNER_BLOCKLIST,
    ECOSYSTEM_MAP,
    KNOWN_LOCKFILES,
    KNOWN_UNPINNED_MANIFESTS,
    STANDARD_SAFE_EXCLUSIONS,
    PrescanReport,
    _normalize_component_name,
    decode_manifest_bytes,
    load_pareto_catalog,
    load_pareto_vuln_kb,
    safe_parse_xml_bytes,
)


def _count_lockfile_entries(full_path: Path, filename: str) -> int:
    """Count declared component version entries inside a discovered lockfile."""
    try:
        raw_bytes = full_path.read_bytes()
        content, _ = decode_manifest_bytes(raw_bytes)
    except OSError:
        return 0

    if filename == "package-lock.json":
        try:
            data = json.loads(content)
            if "packages" in data and isinstance(data["packages"], dict):
                return sum(1 for k in data["packages"] if k != "")
            elif "dependencies" in data and isinstance(data["dependencies"], dict):

                def _count_npm_deps(deps: dict[str, Any]) -> int:
                    total = len(deps)
                    for v in deps.values():
                        if isinstance(v, dict) and "dependencies" in v and isinstance(v["dependencies"], dict):
                            total += _count_npm_deps(v["dependencies"])
                    return total

                return _count_npm_deps(data["dependencies"])
        except (json.JSONDecodeError, KeyError, TypeError):
            return 0

    elif filename == "yarn.lock":
        count = 0
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if line[0] in (" ", "\t"):
                continue
            if stripped.endswith(":") and stripped != "__metadata:":
                count += 1
        return count

    elif filename == "pnpm-lock.yaml":
        count = 0
        in_packages = False
        for line in content.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            if line.startswith("packages:"):
                in_packages = True
                continue
            if in_packages:
                if not line[0].isspace():
                    break
                if re.match(r"^ {2}(?![ ])['\"]?[^:\s]+.*:\s*$", line):
                    count += 1
        return count

    elif filename in ("Cargo.lock", "poetry.lock", "uv.lock"):
        try:
            data = tomllib.loads(content)
            pkgs = data.get("package", [])
            if isinstance(pkgs, list):
                return len(pkgs)
        except (tomllib.TOMLDecodeError, KeyError, TypeError):
            return content.count("[[package]]")

    elif filename == "Pipfile.lock":
        try:
            data = json.loads(content)
            def_deps = data.get("default", {})
            dev_deps = data.get("develop", {})
            c = 0
            if isinstance(def_deps, dict):
                c += len(def_deps)
            if isinstance(dev_deps, dict):
                c += len(dev_deps)
            return c
        except (json.JSONDecodeError, KeyError, TypeError):
            return 0

    elif filename == "composer.lock":
        try:
            data = json.loads(content)
            pkgs = data.get("packages", [])
            pkgs_dev = data.get("packages-dev", [])
            c = 0
            if isinstance(pkgs, list):
                c += len(pkgs)
            if isinstance(pkgs_dev, list):
                c += len(pkgs_dev)
            return c
        except (json.JSONDecodeError, KeyError, TypeError):
            return 0

    elif filename == "go.sum":
        unique_mods: set[str] = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                mod = parts[0]
                unique_mods.add(mod)
        return len(unique_mods)

    elif filename == "gradle.lockfile":
        count = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and not line.startswith("empty=") and "empty=" not in line:
                count += 1
        return count

    elif filename == "packages.lock.json":
        try:
            data = json.loads(content)
            deps = data.get("dependencies", {})
            c = 0
            if isinstance(deps, dict):
                for pkgs in deps.values():
                    if isinstance(pkgs, dict):
                        c += len(pkgs)
            return c
        except (json.JSONDecodeError, KeyError, TypeError):
            return 0

    elif filename == "conan.lock":
        try:
            data = json.loads(content)
            c = 0
            for key in ("requires", "build_requires", "python_requires"):
                arr = data.get(key)
                if isinstance(arr, list):
                    c += len(arr)
            if c == 0 and isinstance(data.get("graph_lock"), dict):
                nodes = data["graph_lock"].get("nodes", {})
                if isinstance(nodes, dict):
                    c = max(0, len(nodes) - 1)
            return c
        except (json.JSONDecodeError, KeyError, TypeError):
            return 0

    elif filename == "Gemfile.lock":
        return len(re.findall(r"^\s{4}[a-zA-Z0-9_.\-]+\s+\([0-9][^)]*\)\s*$", content, re.MULTILINE))

    elif filename == "mix.lock":
        return len(re.findall(r'^\s*"[^"]+":\s*\{:hex,', content, re.MULTILINE))

    elif filename == "Package.resolved":
        try:
            data = json.loads(content)
            pins = data.get("pins")
            if isinstance(pins, list):
                return len(pins)
            obj = data.get("object")
            if isinstance(obj, dict) and isinstance(obj.get("pins"), list):
                return len(obj["pins"])
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
        return 0

    elif filename == "Podfile.lock":
        return len(re.findall(r"^  - [A-Za-z0-9_.\-/]+\s+\([^)]+\)", content, re.MULTILINE))

    elif filename == "pubspec.lock":
        return len(re.findall(r"^  [a-zA-Z0-9_]+:\s*$", content, re.MULTILINE))

    elif filename == "status":
        return len(re.findall(r"^Package:\s+\S+", content, re.MULTILINE))

    return 0


def _count_manifest_direct_deps(full_path: Path, filename: str) -> int:
    """Count declared direct dependency specifications inside an unpinned manifest."""
    try:
        raw_bytes = full_path.read_bytes()
        content, _ = decode_manifest_bytes(raw_bytes)
    except OSError:
        return 0

    if filename == "requirements.txt":
        count = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            count += 1
        return count

    elif filename == "pyproject.toml":
        try:
            data = tomllib.loads(content)
            c = 0
            proj = data.get("project", {})
            if isinstance(proj, dict):
                pdeps = proj.get("dependencies", [])
                if isinstance(pdeps, list):
                    c += len(pdeps)
            tool = data.get("tool", {})
            if isinstance(tool, dict):
                poetry = tool.get("poetry", {})
                if isinstance(poetry, dict):
                    po_deps = poetry.get("dependencies", {})
                    if isinstance(po_deps, dict):
                        c += sum(1 for k in po_deps if k.lower() != "python")
            return c
        except (tomllib.TOMLDecodeError, KeyError, TypeError):
            return 0

    elif filename == "package.json":
        try:
            data = json.loads(content)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            c = 0
            if isinstance(deps, dict):
                c += len(deps)
            if isinstance(dev_deps, dict):
                c += len(dev_deps)
            return c
        except (json.JSONDecodeError, KeyError, TypeError):
            return 0

    elif filename == "go.mod":
        count = 0
        in_require = False
        for line in content.splitlines():
            line = line.strip()
            if "//" in line:
                line = line.split("//")[0].strip()
            if not line:
                continue
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require:
                if line == ")":
                    in_require = False
                    continue
                count += 1
            elif line.startswith("require "):
                parts = line.split()
                if len(parts) >= 2:
                    count += 1
        return count

    elif filename == "pom.xml":
        try:
            content_bytes = full_path.read_bytes()
            root_elem = safe_parse_xml_bytes(content_bytes)
            if root_elem is None:
                return 0
            parent_map = {c: p for p in root_elem.iter() for c in p}
            count = 0
            for elem in root_elem.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if tag == "dependency":
                    in_mgmt = False
                    curr = elem
                    while curr in parent_map:
                        curr = parent_map[curr]
                        ptag = curr.tag.split("}")[-1] if "}" in curr.tag else curr.tag
                        if ptag == "dependencyManagement":
                            in_mgmt = True
                            break
                    if not in_mgmt:
                        count += 1
            return count
        except OSError:
            return 0

    elif filename in ("build.gradle", "build.gradle.kts", "dependencies.gradle"):
        pattern = re.compile(r"^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation)\b")
        count = 0
        for line in content.splitlines():
            if pattern.search(line):
                count += 1
        if count == 0 and filename == "dependencies.gradle":
            count = len(re.findall(r"['\"][a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-]+:[^'\"]+['\"]", content))
        return count

    elif filename == "libs.versions.toml":
        try:
            data = tomllib.loads(content)
            libs = data.get("libraries")
            if isinstance(libs, dict):
                return len(libs)
        except Exception:  # noqa: BLE001
            pass
        return 0

    elif filename == "Cargo.toml":
        try:
            data = tomllib.loads(content)
            deps = data.get("dependencies", {})
            dev_deps = data.get("dev-dependencies", {})
            c = 0
            if isinstance(deps, dict):
                c += len(deps)
            if isinstance(dev_deps, dict):
                c += len(dev_deps)
            ws = data.get("workspace", {})
            if isinstance(ws, dict) and isinstance(ws.get("dependencies"), dict):
                c += len(ws["dependencies"])
            return c
        except (tomllib.TOMLDecodeError, KeyError, TypeError):
            return 0

    elif filename in ("MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"):
        return len(
            re.findall(
                r"\b(?:bazel_dep|http_archive|git_repository|maven_install)\s*\(",
                content,
            )
        )

    elif filename == "conanfile.txt":
        in_req = False
        c = 0
        for line in content.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("[") and s.endswith("]"):
                in_req = s.lower() in ("[requires]", "[tool_requires]", "[build_requires]")
            elif in_req and "/" in s:
                c += 1
        return c

    elif filename == "conanfile.py":
        c = len(re.findall(r"self\.(?:requires|tool_requires|build_requires)\s*\(", content))
        c += len(re.findall(r"['\"][a-zA-Z0-9_.\-]+/[0-9][a-zA-Z0-9_.\-@/]*['\"]", content))
        return c

    elif filename == "vcpkg.json":
        try:
            data = json.loads(content)
            deps = data.get("dependencies", [])
            if isinstance(deps, list):
                return len(deps)
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
        return 0

    elif filename == "Gemfile":
        return len(re.findall(r"^\s*gem\s+['\"][^'\"]+['\"]", content, re.MULTILINE))

    elif filename == "mix.exs":
        return len(re.findall(r"\{:[a-zA-Z0-9_]+,\s*\"", content))

    elif filename == "Package.swift":
        return len(re.findall(r"\.package\s*\(", content))

    elif filename == "Podfile":
        return len(re.findall(r"^\s*pod\s+['\"][^'\"]+['\"]", content, re.MULTILINE))

    elif filename == "pubspec.yaml":
        in_deps = False
        c = 0
        for line in content.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line[0].isspace() and line.rstrip().endswith(":"):
                in_deps = line.strip() in ("dependencies:", "dev_dependencies:")
            elif (
                in_deps
                and re.match(r"^  [a-zA-Z0-9_]+:", line)
                and not line.strip().startswith("sdk:")
            ):
                c += 1
        return c

    elif filename == "build.sbt":
        return len(re.findall(r'"[^"]+"\s*%{1,2}\s*"[^"]+"\s*%\s*"[^"]+"', content))

    elif filename == "environment.yml":
        return len(re.findall(r"^\s*-\s+[a-zA-Z0-9_.\-]+(?:\s*[=<>!]+|$)", content, re.MULTILINE))

    elif filename in ("Directory.Packages.props", "Directory.Build.props", "packages.config") or filename.endswith(".csproj"):
        return len(re.findall(r"<(?:PackageReference|PackageVersion|package)\b", content, re.IGNORECASE))

    elif filename == "layer.conf":
        layer_root = full_path.parent.parent if full_path.parent.name == "conf" else full_path.parent
        bb_cnt = 0
        try:
            for _ in layer_root.rglob("*.bb"):
                bb_cnt += 1
                if bb_cnt >= 5000:
                    break
        except OSError:
            pass
        return max(1, bb_cnt)

    elif filename in ("oe-init-build-env", "bblayers.conf"):
        return 1

    return 0


def build_expected_bom_baseline(
    root: Path,
    lockfiles: list[dict[str, Any]],
    manifests: list[dict[str, Any]],
) -> dict[str, Any]:
    """Group manifests and lockfiles into expected subprojects and compute baseline component bounds."""
    grouped: dict[tuple[str, str], dict[str, Any]] = {}

    for lf in lockfiles:
        rel_p = str(lf.get("path", ""))
        if any(seg in ("__fixtures__", "test-fixtures", "testdata") for seg in rel_p.replace("\\", "/").split("/")[:-1]):
            continue
        parent_dir = str(Path(rel_p).parent)
        if parent_dir == "":
            parent_dir = "."
        fname = str(lf.get("filename", ""))
        eco = ECOSYSTEM_MAP.get(fname, "UNKNOWN")
        key = (parent_dir, eco)
        if key not in grouped:
            grouped[key] = {
                "directory": parent_dir,
                "ecosystem": eco,
                "lockfiles": [],
                "manifests": [],
            }
        grouped[key]["lockfiles"].append(lf)

    for mf in manifests:
        rel_p = str(mf.get("path", ""))
        if any(seg in ("__fixtures__", "test-fixtures", "testdata") for seg in rel_p.replace("\\", "/").split("/")[:-1]):
            continue
        parent_dir = str(Path(rel_p).parent)
        if parent_dir == "":
            parent_dir = "."
        fname = str(mf.get("filename", ""))
        eco = ECOSYSTEM_MAP.get(fname, "NUGET" if fname.endswith(".csproj") else "UNKNOWN")
        key = (parent_dir, eco)
        if key not in grouped:
            grouped[key] = {
                "directory": parent_dir,
                "ecosystem": eco,
                "lockfiles": [],
                "manifests": [],
            }
        grouped[key]["manifests"].append(mf)

    subprojects: list[dict[str, Any]] = []

    for (rel_dir, eco), grp in grouped.items():
        l_list: list[dict[str, Any]] = grp["lockfiles"]
        m_list: list[dict[str, Any]] = grp["manifests"]
        locked_count = sum(int(lf.get("count", 0)) for lf in l_list)
        direct_manifest_count = sum(int(mf.get("count", 0)) for mf in m_list)
        if eco == "GO" and direct_manifest_count > 0 and locked_count > direct_manifest_count * 2:
            locked_count = direct_manifest_count
        expected_min = locked_count if locked_count > 0 else direct_manifest_count

        term = "package" if eco == "NPM" else ("module" if eco == "GO" else "component")
        if locked_count > 0:
            best_lf = max(l_list, key=lambda x: int(x.get("count", 0)))
            reason = f"{best_lf['path']} declares {locked_count} locked {term}(s)"
        elif direct_manifest_count > 0:
            best_mf = max(m_list, key=lambda x: int(x.get("count", 0)))
            if direct_manifest_count == 1:
                reason = f"{best_mf['path']} declares 1 direct dependency; no lockfile"
            else:
                reason = f"{best_mf['path']} declares {direct_manifest_count} direct dependency(s); no lockfile"
        else:
            reason = f"No dependencies declared in {rel_dir}"

        subprojects.append(
            {
                "directory": rel_dir,
                "ecosystem": eco,
                "lockfiles": [lf["path"] for lf in l_list],
                "manifests": [mf["path"] for mf in m_list],
                "locked_count": locked_count,
                "direct_manifest_count": direct_manifest_count,
                "expected_min_components": expected_min,
                "reason": reason,
            }
        )

    # Sort subdirectories first (alphabetically), then root "." last
    subprojects.sort(key=lambda s: (s["directory"] == ".", s["directory"], s["ecosystem"]))

    expected_code_locations = sum(1 for s in subprojects if s["expected_min_components"] > 0)
    total_locked_components = sum(s["locked_count"] for s in subprojects)
    total_unpinned_direct_dependencies = sum(
        s["direct_manifest_count"] for s in subprojects if s["locked_count"] == 0
    )
    expected_min_total_components = sum(s["expected_min_components"] for s in subprojects)
    if expected_min_total_components == 0:
        summary_statement = (
            "You should expect a BOM of at least 0 component version(s) "
            "across 0 code location(s) (0 locked + 0 direct unpinned) from package manager detectors "
            "(no third-party package lockfiles or external dependencies declared; BOM relies on Signature Scanning or BDBA)."
        )
    else:
        dedup_note = (
            "; per-subproject sum prior to cross-module BOM deduplication"
            if expected_code_locations > 1
            else ""
        )
        summary_statement = (
            f"You should expect a BOM of at least {expected_min_total_components} component version(s) "
            f"across {expected_code_locations} code location(s) "
            f"({total_locked_components} locked + {total_unpinned_direct_dependencies} direct unpinned{dedup_note}), "
            "and here is why:"
        )

    return {
        "expected_code_locations": expected_code_locations,
        "total_locked_components": total_locked_components,
        "total_unpinned_direct_dependencies": total_unpinned_direct_dependencies,
        "expected_min_total_components": expected_min_total_components,
        "subprojects": subprojects,
        "summary_statement": summary_statement,
    }


def infer_project_archetypes(report: PrescanReport) -> list[dict[str, Any]]:
    """Classify the workspace into applicable architecture archetypes and check tooling readiness."""
    archetypes: list[dict[str, Any]] = []

    lockfiles = [lf.get("filename", "") for lf in report.get("lockfiles", [])]
    manifests = [mf.get("filename", "") for mf in report.get("unpinned_manifests", [])]
    all_manifest_names = set(lockfiles + manifests)
    pareto = report.get("pareto_hints", {})
    dpi = report.get("deep_packet_inspection", {})

    native_deps = pareto.get("native_dependencies", [])
    archives = pareto.get("binary_version_artifacts", []) or report.get("oversized_archives", [])
    docker_imgs = pareto.get("docker_base_images", [])

    rec_args = report.get("recommended_detect_arguments")
    if isinstance(rec_args, dict):
        tools_val = str(rec_args.get("detect.tools", "")).upper()
    elif isinstance(rec_args, list):
        tools_val = ""
        for x in rec_args:
            s_x = str(x).strip()
            if s_x.lower().startswith("--detect.tools="):
                tools_val = s_x.split("=", 1)[1].upper()
    else:
        m_tools = re.search(r"--detect\.tools=([^\s'\"]+)", str(rec_args or ""), re.IGNORECASE)
        tools_val = m_tools.group(1).upper() if m_tools else ""
    has_detector_tool_only = (
        bool(tools_val)
        and "DETECTOR" in tools_val
        and "SIGNATURE_SCAN" not in tools_val
        and "ALL" not in tools_val
    )

    # 1. C_CPP_SYSTEMS_DAEMON
    has_cpp = bool(native_deps) or any(
        m.get("source_type") in ("cmakelists", "c_header", "version_dat")
        for m in dpi.get("internal_manifest_discoveries", [])
    )
    if has_cpp:
        arch_warns: list[str] = []
        has_cpp_pkg = bool(
            {"conan.lock", "conanfile.txt", "vcpkg.json"}.intersection(all_manifest_names)
        )
        if not has_cpp_pkg:
            if has_detector_tool_only:
                arch_warns.append(
                    "C_CPP_SYSTEMS_DAEMON archetype detected with --detect.tools=DETECTOR and no C/C++ package lockfile (Conan/vcpkg). "
                    "Package manager detectors focus on declared package manifests; enable Black Duck Signature Scanner (SIGNATURE_SCAN), "
                    "Black Duck Binary Analysis (BDBA), or supplemental BDIO to identify unmanaged C/C++ source trees, headers, and compiled libraries."
                )
            else:
                arch_warns.append(
                    "C_CPP_SYSTEMS_DAEMON archetype detected with no C/C++ package lockfile (Conan/vcpkg). "
                    "Package manager detectors (DETECTOR) will extract 0 components from unmanaged C/C++ source trees; "
                    "BOM identification here relies on Signature Scanner (enabled by default in online runs unless --detect.tools=DETECTOR is set) or Binary Analysis (BDBA)."
                )
        archetypes.append(
            {
                "archetype": "C_CPP_SYSTEMS_DAEMON",
                "description": "C/C++ Systems Daemon / Native Binary codebase",
                "expected_families": [
                    "CRYPTO_TLS",
                    "COMPRESSION",
                    "NETWORK_RPC",
                    "PARSER_XML",
                ],
                "warnings": arch_warns,
            }
        )

    # 2. JVM_ENTERPRISE_SERVICE
    has_jvm = bool(
        {"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"}.intersection(
            all_manifest_names
        )
    ) or bool(archives)
    if has_jvm:
        archetypes.append(
            {
                "archetype": "JVM_ENTERPRISE_SERVICE",
                "description": "JVM Enterprise Service (Maven/Gradle/Spring/JAR)",
                "expected_families": [
                    "LOGGING",
                    "WEB_FRAMEWORK",
                    "SERIALIZATION_XML_JSON",
                    "DATABASE_STORAGE",
                ],
                "warnings": [],
            }
        )

    # 3. CONTAINERIZED_APPLIANCE
    has_container = bool(docker_imgs)
    if has_container:
        c_warns: list[str] = []
        if has_detector_tool_only:
            c_warns.append(
                "CONTAINERIZED_APPLIANCE archetype detected (Dockerfile present) but container scanning (DOCKER) is not enabled."
            )
        archetypes.append(
            {
                "archetype": "CONTAINERIZED_APPLIANCE",
                "description": "Containerized Appliance / Docker deployment",
                "expected_families": ["SYSTEM", "EMBEDDED_OS"],
                "warnings": c_warns,
            }
        )

    # 4. MODERN_WEB_SPA
    has_spa = "package.json" in all_manifest_names and bool(
        {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}.intersection(all_manifest_names)
    )
    if has_spa:
        archetypes.append(
            {
                "archetype": "MODERN_WEB_SPA",
                "description": "Modern Web Single Page Application (Node.js/TypeScript)",
                "expected_families": ["WEB_FRAMEWORK", "NETWORK_RPC"],
                "warnings": [],
            }
        )

    # 5. PYTHON_APPLICATION
    has_python = bool(
        {
            "requirements.txt",
            "pyproject.toml",
            "Pipfile.lock",
            "poetry.lock",
            "setup.py",
        }.intersection(all_manifest_names)
    )
    if has_python:
        archetypes.append(
            {
                "archetype": "PYTHON_APPLICATION",
                "description": "Python Application / Service",
                "expected_families": ["WEB_FRAMEWORK", "DATABASE_STORAGE"],
                "warnings": [],
            }
        )

    # 6. GO_SERVICE
    has_go = bool({"go.mod", "go.sum"}.intersection(all_manifest_names))
    if has_go:
        archetypes.append(
            {
                "archetype": "GO_SERVICE",
                "description": "Go Microservice / Systems Daemon",
                "expected_families": ["NETWORK_RPC", "DATABASE_STORAGE"],
                "warnings": [],
            }
        )

    return archetypes


def save_baseline(report: PrescanReport, baseline_path: str | Path) -> None:
    """Save scan baseline to prevent Friday-afternoon silencer regressions."""
    expected_bom = report.get("expected_bom_baseline", {})
    verification = report.get("detect_verification", {})
    prov = verification.get("provenance_summary", {})

    actual_total = verification.get("actual_total_components")
    if actual_total is None:
        actual_total = prov.get("actual_total_components")
    if actual_total is None:
        actual_total = expected_bom.get("expected_min_total_components", 0)

    actual_locs = verification.get("actual_code_locations")
    if actual_locs is None:
        actual_locs = prov.get("actual_code_locations")
    if actual_locs is None:
        actual_locs = expected_bom.get("expected_code_locations", 0)

    silencer_flags = verification.get("silencer_flags_audit", [])

    baseline_data = {
        "expected_min_total_components": expected_bom.get("expected_min_total_components", 0),
        "actual_total_components": actual_total,
        "actual_code_locations": actual_locs,
        "silencer_flags": silencer_flags,
        "subprojects": expected_bom.get("subprojects", []),
    }
    b_path = Path(baseline_path)
    b_path.parent.mkdir(parents=True, exist_ok=True)
    b_path.write_text(json.dumps(baseline_data, indent=2) + "\n", encoding="utf-8")


def check_baseline(report: PrescanReport, baseline_path: str | Path) -> dict[str, Any]:
    """Check current scan against saved baseline to detect drift or silencer flag additions."""
    bpath = Path(baseline_path)
    if not bpath.exists():
        raise FileNotFoundError(f"Baseline file not found: {bpath}")
    baseline = json.loads(bpath.read_text(encoding="utf-8"))

    violations: list[str] = []

    # 1. Component count check (flag if dropped > 20%)
    if baseline.get("actual_total_components") is not None:
        base_comps = int(baseline["actual_total_components"])
    else:
        base_comps = int(baseline.get("expected_min_total_components", 0))

    expected_bom = report.get("expected_bom_baseline", {})
    verification = report.get("detect_verification", {})
    prov = verification.get("provenance_summary", {})

    curr_comps = verification.get("actual_total_components")
    if curr_comps is None:
        curr_comps = prov.get("actual_total_components")
    if curr_comps is None:
        curr_comps = expected_bom.get("expected_min_total_components", 0)
    curr_comps = int(curr_comps)

    if base_comps > 0:
        drop_pct = (base_comps - curr_comps) / base_comps
        if drop_pct > 0.20:
            violations.append(
                f"Total component count dropped by {round(drop_pct * 100, 1)}% "
                f"(baseline: {base_comps}, current: {curr_comps}, drop threshold > 20.0%)"
            )

    # 2. Code locations check
    if baseline.get("actual_code_locations") is not None:
        base_locs = int(baseline["actual_code_locations"])
    else:
        base_locs = int(baseline.get("expected_code_locations", 0))

    curr_locs = verification.get("actual_code_locations")
    if curr_locs is None:
        curr_locs = prov.get("actual_code_locations")
    if curr_locs is None:
        curr_locs = expected_bom.get("expected_code_locations", 0)
    curr_locs = int(curr_locs)

    if base_locs > 0 and curr_locs < base_locs:
        violations.append(f"Code locations dropped from {base_locs} to {curr_locs}")

    # 3. New silencer flags check
    base_silencers = {
        f"{s.get('property')}={s.get('value')}"
        for s in baseline.get("silencer_flags", [])
        if isinstance(s, dict)
    }
    curr_silencers = {
        f"{s.get('property')}={s.get('value')}"
        for s in verification.get("silencer_flags_audit", [])
        if isinstance(s, dict)
    }
    new_silencers = curr_silencers - base_silencers
    if new_silencers:
        violations.append(f"New silencer flag(s) introduced: {', '.join(sorted(new_silencers))}")

    status = "BASELINE_DRIFT_FAIL" if violations else "BASELINE_DRIFT_PASS"
    return {
        "status": status,
        "violations": violations,
        "baseline_components": base_comps,
        "current_components": curr_comps,
        "baseline_code_locations": base_locs,
        "current_code_locations": curr_locs,
        "new_silencers": sorted(new_silencers),
    }


def _hash_file_smart(
    task: tuple[Path, str, int, bool, int],
) -> tuple[str, str, bool, int]:
    """Hash a single file (full SHA-256 below threshold; sparse head+mid+tail above threshold)."""
    fpath, rel_posix, size, is_dep_input, sparse_threshold_bytes = task
    h = hashlib.sha256()
    bytes_read = 0
    try:
        with open(fpath, "rb") as rf:
            if size <= sparse_threshold_bytes or sparse_threshold_bytes <= 0:
                while True:
                    chunk = rf.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
                    bytes_read += len(chunk)
            else:
                # Sparse Fingerprint: exact byte size + 64KB header + 64KB midpoint + 64KB trailer (ZIP central dir / ELF section table)
                window = 65536
                h.update(f"SPARSE_V1:size={size}\0".encode())
                head = rf.read(window)
                h.update(head)
                bytes_read += len(head)

                mid_offset = max(window, (size // 2) - (window // 2))
                rf.seek(mid_offset)
                mid = rf.read(window)
                h.update(mid)
                bytes_read += len(mid)

                tail_offset = max(mid_offset + len(mid), size - window)
                rf.seek(tail_offset)
                tail = rf.read(window)
                h.update(tail)
                bytes_read += len(tail)
    except OSError:
        return (rel_posix, "", is_dep_input, 0)
    return (rel_posix, h.hexdigest(), is_dep_input, bytes_read)


def compute_workspace_merkle_provenance(
    workspace_root: str | Path,
    recommended_detect_args: list[str] | None = None,
    max_depth: int = 12,
    max_workers: int | None = None,
    max_source_files_to_hash: int = 5000,
    max_source_bytes_to_hash: int = 256 * 1024 * 1024,
    sparse_threshold_bytes: int = 4 * 1024 * 1024,
) -> dict[str, Any]:
    """Compute a multithreaded, top-down (breadth-first) 3-layer codebase signature with bounded 80/20 early stop.

    Layers:
      - L0 (topology_skeleton_sha256): Zero-file-read directory skeleton (relative dir paths, file counts,
        extension mix, and byte-size totals via stat metadata, ignoring timestamps/inodes).
      - L1 (dependency_inputs_merkle_sha256): 100% of dependency-bearing inputs (lockfiles, manifests, Dockerfiles,
        build scripts, and archives/binaries with sparse fingerprinting for files > 4 MB).
      - L2 (workspace_tree_merkle_sha256): Breadth-first top-down source tree hash bounded by
        max_source_files_to_hash and max_source_bytes_to_hash so huge monorepos stop cleanly after
        capturing >80% of structural/top-level integrity data without multi-minute I/O stalls.
    """
    root = Path(workspace_root).resolve()
    if not root.is_dir():
        return {
            "multilayer_codebase_signature": "sca-sig:v2:empty",
            "topology_skeleton_sha256": "0" * 64,
            "workspace_tree_merkle_sha256": "0" * 64,
            "dependency_inputs_merkle_sha256": "0" * 64,
            "effective_detect_config_sha256": "0" * 64,
            "files_discovered_count": 0,
            "files_hashed_count": 0,
            "dependency_inputs_hashed_count": 0,
            "coverage_pct": 0.0,
            "early_stop_triggered": False,
            "max_depth_reached": 0,
            "bd_ui_version_notes_arg": "",
        }

    effective_workers = (
        max(1, max_workers) if max_workers is not None else min(16, (os.cpu_count() or 4) * 2)
    )

    # Breadth-first (top-down) traversal queue: (dir_path, depth)
    bfs_queue: deque[tuple[Path, int]] = deque([(root, 0)])
    visited_inodes: set[tuple[int, int]] = set()
    with contextlib.suppress(OSError):
        st_root = root.stat()
        visited_inodes.add((st_root.st_dev, st_root.st_ino))

    topology_records: list[str] = []
    # Candidate files discovered breadth-first: (depth, is_not_dep_input, rel_posix, fpath, size, is_dep_input)
    discovered_files: list[tuple[int, int, str, Path, int, bool]] = []
    max_depth_seen = 0

    while bfs_queue:
        curr, depth = bfs_queue.popleft()
        if depth > max_depth_seen:
            max_depth_seen = depth
        try:
            entries = sorted(os.scandir(curr), key=lambda e: e.name)
        except OSError:
            continue

        rel_dir = "." if curr == root else curr.relative_to(root).as_posix()
        dir_file_count = 0
        dir_byte_sum = 0
        ext_counts: dict[str, int] = {}
        child_dirs: list[tuple[Path, int]] = []

        for entry in entries:
            try:
                name = entry.name
                if entry.is_dir(follow_symlinks=False):
                    if name in STANDARD_SAFE_EXCLUSIONS or name == "node_modules":
                        continue
                    st = entry.stat(follow_symlinks=False)
                    ikey = (st.st_dev, st.st_ino)
                    if ikey not in visited_inodes and depth < max_depth:
                        visited_inodes.add(ikey)
                        child_dirs.append((Path(entry.path), depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    if name == "GROUND_TRUTH_MANIFEST.json":
                        continue
                    st_f = entry.stat(follow_symlinks=False)
                    fsize = int(st_f.st_size)
                    dir_file_count += 1
                    dir_byte_sum += fsize
                    ext = Path(name).suffix.lower() or "<no_ext>"
                    ext_counts[ext] = ext_counts.get(ext, 0) + 1

                    fpath = Path(entry.path)
                    rel_posix = fpath.relative_to(root).as_posix()
                    lower = name.lower()
                    is_dep_input = (
                        name in KNOWN_LOCKFILES
                        or name in KNOWN_UNPINNED_MANIFESTS
                        or lower.endswith((".csproj", ".nuspec", ".spdx", ".spdx.json"))
                        or lower.startswith("dockerfile")
                        or lower
                        in (
                            "cmakelists.txt",
                            "makefile",
                            "configure.ac",
                            "meson.build",
                            "version.dat",
                            "zlib.h",
                            "opensslv.h",
                            "curlver.h",
                            "expat.h",
                            "sqlite3.h",
                            ".pkginfo",
                        )
                        or (lower.endswith(".h") and ("version" in lower or "ver.h" in lower))
                        or (
                            lower.startswith(
                                ("license", "copying", "notice", "third_party", "third-party", "licence")
                            )
                            and Path(name).suffix.lower() in ("", ".txt", ".md", ".rst", ".html", ".htm", ".rtf")
                        )
                        or any(lower.endswith(ext_a) for ext_a in ARCHIVE_EXTENSIONS)
                        or lower.endswith(
                            (".so", ".dll", ".dylib", ".exe", ".bin", ".pack", ".pack.gz", ".bdio")
                        )
                        or ".so." in lower
                    )
                    discovered_files.append(
                        (depth, 0 if is_dep_input else 1, rel_posix, fpath, fsize, is_dep_input)
                    )
            except OSError:
                continue

        ext_summary = ",".join(f"{k}:{v}" for k, v in sorted(ext_counts.items()))
        topology_records.append(
            f"d={depth}|dir={rel_dir}|files={dir_file_count}|bytes={dir_byte_sum}|exts={ext_summary}\n"
        )
        bfs_queue.extend(child_dirs)

    # Layer 0: Folder Tree Digest (100% workspace coverage, zero file reads)
    topo_hasher = hashlib.sha256()
    for rec in topology_records:
        topo_hasher.update(rec.encode("utf-8"))
    topology_sha256 = topo_hasher.hexdigest()

    # Prioritize top-down breadth-first:
    #   1) All dependency-bearing inputs (is_dep_input=True) across all depths are ALWAYS hashed.
    #   2) Remaining source files are ordered top-down by (depth, rel_posix) up to the file/byte budget.
    discovered_files.sort(key=lambda item: (item[1], item[0], item[2]))

    selected_tasks: list[tuple[Path, str, int, bool, int]] = []
    budget_files_count = 0
    budget_bytes_sum = 0
    early_stop_triggered = False
    max_depth_hashed = 0

    for depth, _prio, rel_posix, fpath, fsize, is_dep_input in discovered_files:
        effective_io_bytes = min(fsize, 196608) if fsize > sparse_threshold_bytes else fsize
        if is_dep_input:
            selected_tasks.append((fpath, rel_posix, fsize, True, sparse_threshold_bytes))
            if depth > max_depth_hashed:
                max_depth_hashed = depth
        else:
            if (
                budget_files_count < max_source_files_to_hash
                and (budget_bytes_sum + effective_io_bytes) <= max_source_bytes_to_hash
            ):
                selected_tasks.append((fpath, rel_posix, fsize, False, sparse_threshold_bytes))
                budget_files_count += 1
                budget_bytes_sum += effective_io_bytes
                if depth > max_depth_hashed:
                    max_depth_hashed = depth
            else:
                early_stop_triggered = True

    all_leaves: list[tuple[str, str]] = []
    dep_leaves: list[tuple[str, str]] = []
    total_bytes_hashed = 0

    if selected_tasks:
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            for rel_posix, digest, is_dep_input, bytes_read in pool.map(
                _hash_file_smart, selected_tasks
            ):
                if not digest:
                    continue
                all_leaves.append((rel_posix, digest))
                total_bytes_hashed += bytes_read
                if is_dep_input:
                    dep_leaves.append((rel_posix, digest))

    all_leaves.sort(key=lambda x: x[0])
    dep_leaves.sort(key=lambda x: x[0])

    # Layer 2: Breadth-First Source Tree Merkle Digest
    tree_hasher = hashlib.sha256()
    for rel_p, f_hash in all_leaves:
        tree_hasher.update(f"{rel_p}\0{f_hash}\n".encode())
    tree_merkle = tree_hasher.hexdigest()

    # Layer 1: Dependency Input Hash Digest
    dep_hasher = hashlib.sha256()
    for rel_p, f_hash in dep_leaves:
        dep_hasher.update(f"{rel_p}\0{f_hash}\n".encode())
    dep_merkle = dep_hasher.hexdigest()

    sorted_args = sorted(str(a).strip() for a in (recommended_detect_args or []) if str(a).strip())
    normalized_cfg_args = [
        re.sub(
            r"^(--detect\.blackduck\.signature\.scanner\.memory=)\d+$",
            r"\1<HOST_RAM_SCALED>",
            a,
        )
        for a in sorted_args
    ]
    cfg_hasher = hashlib.sha256("\n".join(normalized_cfg_args).encode("utf-8"))
    cfg_sha256 = cfg_hasher.hexdigest()

    total_discovered = len(discovered_files)
    coverage_pct = (
        round((len(all_leaves) / total_discovered) * 100.0, 1) if total_discovered > 0 else 100.0
    )
    multilayer_sig = (
        f"sca-sig:v2:L0={topology_sha256[:12]}:"
        f"L1={dep_merkle[:12]}:"
        f"L2={tree_merkle[:12]}:"
        f"CFG={cfg_sha256[:12]}"
        f"@d{max_depth_hashed}({coverage_pct}%)"
    )

    notes_val = (
        f"sca-ops-provenance:{multilayer_sig};"
        f"tree_merkle=sha256:{tree_merkle[:16]};"
        f"dep_merkle=sha256:{dep_merkle[:16]};"
        f"cfg_sha256={cfg_sha256[:16]};"
        f"files={len(all_leaves)}/{total_discovered};dep_inputs={len(dep_leaves)}"
    )

    dep_inputs_bytes = sum(fsize for _d, _p, _r, _f, fsize, is_d in discovered_files if is_d)
    return {
        "multilayer_codebase_signature": multilayer_sig,
        "topology_skeleton_sha256": topology_sha256,
        "workspace_tree_merkle_sha256": tree_merkle,
        "dependency_inputs_merkle_sha256": dep_merkle,
        "effective_detect_config_sha256": cfg_sha256,
        "files_discovered_count": total_discovered,
        "files_hashed_count": len(all_leaves),
        "dependency_inputs_hashed_count": len(dep_leaves),
        "dependency_input_paths": [p for p, _ in dep_leaves],
        "dependency_inputs_bytes": dep_inputs_bytes,
        "total_bytes_hashed": total_bytes_hashed,
        "coverage_pct": coverage_pct,
        "early_stop_triggered": early_stop_triggered,
        "max_depth_reached": max_depth_hashed,
        "threads_used": effective_workers,
        "effective_detect_arguments": sorted_args,
        "bd_ui_version_notes_arg": f"--detect.project.version.notes={notes_val}",
    }


def emit_supplemental_bdio(
    report: PrescanReport,
    output_path: str | Path,
    project_name: str | None = None,
    project_version: str = "1.0.0",
) -> int:
    """Generate a valid Black Duck BDIO 2.x archive for discovered prescan components."""
    root_str = report.get("workspace_root", "workspace")
    proj_name = project_name or Path(root_str).name or "Supplemental_Prescan"
    proj_id = f"http://blackducksoftware.com/project/{proj_name}/{project_version}"
    prov = report.get("scan_input_provenance") or compute_workspace_merkle_provenance(
        root_str, report.get("recommended_detect_arguments", [])
    )

    components: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # Pre-load known components from catalog and KB to filter generic binary banners
    cat = load_pareto_catalog()
    kb = load_pareto_vuln_kb()
    known_names: set[str] = set()
    for c in cat.get("components", []):
        if isinstance(c, dict):
            c_name = c.get("name")
            if c_name:
                known_names.add(_normalize_component_name(str(c_name)))
                for a in c.get("cmake_names", []) + c.get("pkgconfig_names", []) + c.get("sonames", []) + c.get("dir_markers", []):
                    known_names.add(_normalize_component_name(str(a)))
    for v in kb:
        if isinstance(v, dict):
            v_eco = str(v.get("ecosystem", "")).upper()
            if not v.get("vulnerable_version_regex") and "C_CPP" not in v_eco and "SYSTEM" not in v_eco:
                continue
            v_name = v.get("component")
            if v_name:
                known_names.add(_normalize_component_name(str(v_name)))
                for a in v.get("aliases", []):
                    known_names.add(_normalize_component_name(str(a)))

    # Collect from filename_version_assertions
    dpi = report.get("deep_packet_inspection", {})
    for a in dpi.get("filename_version_assertions", []):
        name = str(a.get("artifact_name") or "")
        ver = str(a.get("asserted_version") or "")
        if name and ver and ver != "unversioned":
            key = (name.lower(), ver)
            if key not in seen:
                seen.add(key)
                ns = (
                    "maven"
                    if str(a.get("relative_path", "")).endswith((".jar", ".war"))
                    else "generic"
                )
                components.append({"name": name, "version": ver, "namespace": ns})

    # Collect from archive_metadata
    for arch in dpi.get("archive_metadata", []):
        aid = str(arch.get("artifact_id") or arch.get("group_id") or "")
        aver = str(arch.get("version") or "")
        if aid and aver:
            key = (aid.lower(), aver)
            if key not in seen:
                seen.add(key)
                components.append({"name": aid, "version": aver, "namespace": "maven"})
        for m_coord in arch.get("maven_coordinates", []):
            m_aid = str(m_coord.get("artifactId") or m_coord.get("artifact_id") or "")
            m_ver = str(m_coord.get("version") or "")
            if m_aid and m_ver:
                key = (m_aid.lower(), m_ver)
                if key not in seen:
                    seen.add(key)
                    components.append({"name": m_aid, "version": m_ver, "namespace": "maven"})

    # Collect from tarball_metadata
    for t_meta in dpi.get("tarball_metadata", []):
        top_prefix = t_meta.get("top_level_prefix")
        if top_prefix and isinstance(top_prefix, dict):
            t_name = str(top_prefix.get("name") or "")
            t_ver = str(top_prefix.get("version") or "")
            if t_name and t_ver and t_ver != "unversioned":
                key = (t_name.lower(), t_ver)
                if key not in seen:
                    seen.add(key)
                    components.append({"name": t_name, "version": t_ver, "namespace": "generic"})

    # Collect from binary_inspection
    for b in dpi.get("binary_inspection", []):
        for c_match in b.get("catalog_version_matches", []):
            c_name = str(c_match.get("component") or "")
            c_ver = str(c_match.get("version") or "")
            if c_name and c_ver:
                key = (c_name.lower(), c_ver)
                if key not in seen:
                    seen.add(key)
                    components.append({"name": c_name, "version": c_ver, "namespace": "centos"})
        for g_mod in b.get("go_dependencies", []):
            g_name = str(g_mod.get("module") or "")
            g_ver = str(g_mod.get("version") or "")
            if g_name and g_ver:
                key = (g_name.lower(), g_ver)
                if key not in seen:
                    seen.add(key)
                    components.append({"name": g_name, "version": g_ver, "namespace": "golang"})
        for gb in b.get("generic_binary_banners", []):
            gb_name = str(gb.get("component") or "")
            gb_ver = str(gb.get("version") or "")
            if gb_name and gb_ver and gb_ver != "unversioned":
                gb_norm = _normalize_component_name(gb_name)
                if gb_norm in BINARY_BANNER_BLOCKLIST:
                    continue
                gb_without_lib = gb_norm[3:] if gb_norm.startswith("lib") and len(gb_norm) > 3 else gb_norm
                if gb_norm in known_names or gb_without_lib in known_names:
                    key = (gb_name.lower(), gb_ver)
                    if key not in seen:
                        seen.add(key)
                        components.append({"name": gb_name, "version": gb_ver, "namespace": "generic"})
        for rc in b.get("rust_crates", []):
            rc_name = str(rc.get("crate") or rc.get("name") or "")
            rc_ver = str(rc.get("version") or "")
            if rc_name and rc_ver and rc_ver != "unversioned":
                key = (rc_name.lower(), rc_ver)
                if key not in seen:
                    seen.add(key)
                    components.append({"name": rc_name, "version": rc_ver, "namespace": "cargo"})

    # Collect from internal_manifest_discoveries
    for imd in dpi.get("internal_manifest_discoveries", []):
        c_name = str(imd.get("component") or "")
        c_ver = str(imd.get("version") or "")
        if c_name and c_ver and c_ver != "unversioned":
            key = (c_name.lower(), c_ver)
            if key not in seen:
                seen.add(key)
                src = str(imd.get("source_type") or "")
                ns = "maven" if "pom" in src else ("cargo" if "cargo" in src else ("npm" if "package_json" in src else "generic"))
                components.append({"name": c_name, "version": c_ver, "namespace": ns})

    # Collect from pareto_hints binary_version_artifacts
    for p_art in report.get("pareto_hints", {}).get("binary_version_artifacts", []):
        p_name = str(p_art.get("name_hint") or "")
        p_ver = str(p_art.get("version_hint") or "")
        if p_name and p_ver and p_ver != "unversioned":
            key = (p_name.lower(), p_ver)
            if key not in seen:
                seen.add(key)
                components.append({"name": p_name, "version": p_ver, "namespace": "generic"})

    prov_comment = str(prov.get("bd_ui_version_notes_arg", "")).removeprefix("--detect.project.version.notes=")

    # Build BDIO graph
    graph: list[dict[str, Any]] = [
        {
            "@id": proj_id,
            "@type": "https://blackducksoftware.github.io/bdio#Project",
            "https://blackducksoftware.github.io/bdio#hasName": proj_name,
            "https://blackducksoftware.github.io/bdio#hasVersion": project_version,
            "https://blackducksoftware.github.io/bdio#hasIdentifier": f"{proj_name}/{project_version}",
            "https://blackducksoftware.github.io/bdio#hasComment": prov_comment,
            "https://blackducksoftware.github.io/bdio#hasDependency": [
                {
                    "@type": "https://blackducksoftware.github.io/bdio#Dependency",
                    "https://blackducksoftware.github.io/bdio#dependsOn": {
                        "@id": f"http://blackducksoftware.com/component/{c['namespace']}/{urllib.parse.quote(c['name'], safe='')}/{urllib.parse.quote(c['version'], safe='')}"
                    },
                }
                for c in components
            ],
        }
    ]

    for c in components:
        cid = (
            f"http://blackducksoftware.com/component/{c['namespace']}/{urllib.parse.quote(c['name'], safe='')}/{urllib.parse.quote(c['version'], safe='')}"
        )
        graph.append(
            {
                "@id": cid,
                "@type": "https://blackducksoftware.github.io/bdio#Component",
                "https://blackducksoftware.github.io/bdio#hasName": c["name"],
                "https://blackducksoftware.github.io/bdio#hasVersion": c["version"],
                "https://blackducksoftware.github.io/bdio#hasNamespace": c["namespace"],
                "https://blackducksoftware.github.io/bdio#hasIdentifier": f"{c['namespace']}:{c['name']}:{c['version']}",
            }
        )

    header = {
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "@type": "https://blackducksoftware.github.io/bdio#BillOfMaterials",
        "https://blackducksoftware.github.io/bdio#hasProject": proj_name,
        "https://blackducksoftware.github.io/bdio#hasProjectVersion": project_version,
        "https://blackducksoftware.github.io/bdio#hasComment": prov_comment,
        "scan_input_provenance": {
            "workspace_tree_merkle_sha256": prov.get("workspace_tree_merkle_sha256"),
            "dependency_inputs_merkle_sha256": prov.get("dependency_inputs_merkle_sha256"),
            "effective_detect_config_sha256": prov.get("effective_detect_config_sha256"),
            "files_hashed_count": prov.get("files_hashed_count"),
            "dependency_inputs_hashed_count": prov.get("dependency_inputs_hashed_count"),
        },
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("bdio-header.jsonld", json.dumps(header, indent=2))
        z.writestr("bdio-entry-00.jsonld", json.dumps({"@graph": graph}, indent=2))

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(buf.getvalue())
    return len(components)


def analyze_git_diff(workspace_root: str | Path, base_ref: str) -> dict[str, Any]:
    """Analyze git diff against base_ref to determine dependency delta and CI silencer additions."""
    if not isinstance(base_ref, str):
        raise ValueError("base_ref must be a string")
    if not base_ref:
        raise ValueError("base_ref cannot be empty")
    if base_ref.startswith("-"):
        raise ValueError(f"base_ref cannot start with hyphen: {base_ref}")
    if ".." in base_ref:
        raise ValueError(f"base_ref cannot contain '..': {base_ref}")
    if not re.match(r"^[a-zA-Z0-9_./~^@\-]+$", base_ref):
        raise ValueError(f"Invalid characters in base_ref: {base_ref}")

    root = Path(workspace_root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Workspace directory not found: {root}")

    # Run git diff --name-status (disable repo-local fsmonitor and textconv hooks for untrusted repos)
    cmd_names = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(root),
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-status",
        f"{base_ref}..HEAD",
    ]

    # Run git diff -U0
    cmd_patch = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(root),
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "-U0",
        f"{base_ref}..HEAD",
    ]

    try:
        proc_names = subprocess.run(
            cmd_names,
            shell=False,
            timeout=15,
            capture_output=True,
            text=True,
            check=True,
        )
        proc_patch = subprocess.run(
            cmd_patch,
            shell=False,
            timeout=15,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"Git diff failed for ref {base_ref}: {exc.stderr}") from exc

    changed_manifests: list[str] = []
    changed_archives_or_binaries: list[str] = []
    affected_subdirs: set[str] = set()

    for line in proc_names.stdout.splitlines():
        line = line[:4096].strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            status = parts[0].strip()
            # Ignore deleted files when computing dependency changes
            if status.startswith("D"):
                continue

            file_path = parts[-1]
            p = Path(file_path)
            fname = p.name
            fname_lower = fname.lower()

            is_manifest = (
                fname in KNOWN_LOCKFILES
                or fname in KNOWN_UNPINNED_MANIFESTS
                or fname_lower in (
                    "package.json",
                    "package-lock.json",
                    "pom.xml",
                    "build.gradle",
                    "build.gradle.kts",
                    "settings.gradle",
                    "requirements.txt",
                    "cargo.toml",
                    "cargo.lock",
                    "go.mod",
                    "go.sum",
                    "cmakelists.txt",
                    "conanfile.txt",
                    "conanfile.py",
                    "gemfile",
                    "gemfile.lock",
                )
                or fname_lower.endswith(".nuspec")
                or fname_lower.endswith(".pkginfo")
                or fname == "control"
            )

            is_archive_or_binary = (
                any(fname_lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)
                or fname_lower.endswith((".so", ".dylib", ".dll", ".exe", ".bin", ".whl", ".a", ".o"))
                or ".so." in fname_lower
            )

            if is_manifest:
                changed_manifests.append(file_path)
                sub_dir = str(p.parent) if str(p.parent) != "." else "."
                affected_subdirs.add(sub_dir)

            if is_archive_or_binary:
                changed_archives_or_binaries.append(file_path)
                sub_dir = str(p.parent) if str(p.parent) != "." else "."
                affected_subdirs.add(sub_dir)

    added_native_includes: list[str] = []
    ci_silencer_additions: list[str] = []

    current_file = ""
    is_ci_file = False

    for patch_line in proc_patch.stdout.splitlines():
        patch_line = patch_line[:4096]
        if patch_line.startswith("+++ b/"):
            current_file = patch_line[6:].strip()
            cf_name = Path(current_file).name.lower()
            is_ci_file = (
                cf_name in ("jenkinsfile", ".gitlab-ci.yml")
                or current_file.startswith(".github/workflows/")
                or cf_name.endswith((".sh", ".bash"))
            )
            continue
        if patch_line.startswith("+") and not patch_line.startswith("+++"):
            added_content = patch_line[1:].strip()
            m_inc = re.match(r"^#\s*include\s*([<\"].+?[>\"])", added_content)
            if m_inc:
                added_native_includes.append(f"{current_file}: {m_inc.group(1)}")
                sub_dir = str(Path(current_file).parent) if str(Path(current_file).parent) != "." else "."
                affected_subdirs.add(sub_dir)

            if is_ci_file:
                # Ignore commented-out lines
                if added_content.startswith("#") or added_content.startswith("//"):
                    continue
                for silencer_pat in (
                    "--detect.excluded.",
                    "--detect.accuracy.required=NONE",
                    "--detect.tools=DETECTOR",
                ):
                    if silencer_pat in added_content:
                        ci_silencer_additions.append(f"{current_file}: {added_content}")
                        break

    affected_subprojects = sorted(affected_subdirs)

    if ci_silencer_additions:
        verdict = "CI_SILENCER_ADDED_IN_DIFF"
        skip_full = False
    elif changed_manifests or changed_archives_or_binaries or added_native_includes:
        verdict = "SCOPED_DEPENDENCY_DELTA"
        skip_full = False
    else:
        verdict = "ZERO_DEPENDENCY_DELTA"
        skip_full = True

    return {
        "base_ref": base_ref,
        "verdict": verdict,
        "skip_full_scan": skip_full,
        "skip_full_bd_scan_recommended": skip_full,
        "changed_manifests": sorted(changed_manifests),
        "changed_archives_or_binaries": sorted(changed_archives_or_binaries),
        "added_native_includes": sorted(added_native_includes),
        "ci_silencer_additions": sorted(ci_silencer_additions),
        "affected_subprojects": affected_subprojects,
    }


def verify_detect_output(
    prescan_report: PrescanReport,
    detect_output_path: str | Path,
) -> dict[str, Any]:
    """Verify Black Duck Detect run output against expected BOM baseline to catch false negatives."""
    baseline: dict[str, Any] = (
        prescan_report.get("expected_bom_baseline", prescan_report)
        if isinstance(prescan_report, dict)
        else {}
    )

    run_path = Path(detect_output_path).resolve()
    if not run_path.exists():
        raise FileNotFoundError(f"Detect run output path not found: {run_path}")

    bdio_entries: list[tuple[str, bytes]] = []
    status_data: dict[str, Any] | None = None
    detector_issues: list[str] = []

    if run_path.is_file() and run_path.suffix.lower() == ".zip":
        with zipfile.ZipFile(run_path) as z:
            for zinfo in z.infolist():
                if zinfo.filename.endswith(".bdio"):
                    bdio_entries.append((Path(zinfo.filename).name, z.read(zinfo)))
                elif zinfo.filename == "status/status.json" or zinfo.filename.endswith("/status.json"):
                    with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
                        status_data = json.loads(z.read(zinfo).decode("utf-8"))
    elif run_path.is_file() and run_path.suffix.lower() == ".bdio":
        bdio_entries.append((run_path.name, run_path.read_bytes()))
    elif run_path.is_dir():
        # 1. Look in bdio subdirectory or scan all child .bdio files
        bdio_dir = run_path / "bdio"
        if bdio_dir.is_dir():
            for bf in sorted(bdio_dir.glob("*.bdio")):
                bdio_entries.append((bf.name, bf.read_bytes()))
        if not bdio_entries:
            for bf in sorted(run_path.rglob("*.bdio")):
                bdio_entries.append((bf.name, bf.read_bytes()))

        # 2. Look for status.json
        status_file = run_path / "status" / "status.json"
        if status_file.is_file():
            with contextlib.suppress(json.JSONDecodeError, OSError, UnicodeDecodeError):
                status_data = json.loads(status_file.read_text(encoding="utf-8"))
        if status_data is None:
            for sf in run_path.rglob("status.json"):
                try:
                    status_data = json.loads(sf.read_text(encoding="utf-8"))
                    break
                except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                    pass

        # 3. Check sibling or child diagnostic zip if artifacts still missing
        if not bdio_entries or status_data is None:
            sibling_zip = run_path.parent / f"detect-run-{run_path.name}.zip"
            zip_candidates = [sibling_zip] if sibling_zip.is_file() else list(run_path.glob("detect-run-*.zip"))
            for cand in zip_candidates:
                if cand.is_file():
                    with zipfile.ZipFile(cand) as z:
                        if not bdio_entries:
                            for zinfo in z.infolist():
                                if zinfo.filename.endswith(".bdio"):
                                    bdio_entries.append((Path(zinfo.filename).name, z.read(zinfo)))
                        if status_data is None:
                            for zinfo in z.infolist():
                                if zinfo.filename == "status/status.json" or zinfo.filename.endswith(
                                    "/status.json"
                                ):
                                    try:
                                        status_data = json.loads(z.read(zinfo).decode("utf-8"))
                                        break
                                    except (json.JSONDecodeError, UnicodeDecodeError):
                                        pass

    # Extract BDIO components and projects
    components_by_id: dict[str, dict[str, Any]] = {}
    projects: list[dict[str, Any]] = []

    for _bname, bbytes in bdio_entries:
        with zipfile.ZipFile(io.BytesIO(bbytes)) as bz:
            for fname in bz.namelist():
                if fname.startswith("bdio-entry-") and fname.endswith(".jsonld"):
                    try:
                        entry_data = json.loads(bz.read(fname).decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
                        continue
                    graph = entry_data.get("@graph", [])
                    for node in graph:
                        ntype = node.get("@type")
                        if ntype == "https://blackducksoftware.github.io/bdio#Component":
                            cid = node.get("@id", "")
                            if cid and cid not in components_by_id:
                                components_by_id[cid] = {
                                    "id": cid,
                                    "name": node.get(
                                        "https://blackducksoftware.github.io/bdio#hasName", ""
                                    ),
                                    "version": node.get(
                                        "https://blackducksoftware.github.io/bdio#hasVersion", ""
                                    ),
                                    "namespace": node.get(
                                        "https://blackducksoftware.github.io/bdio#hasNamespace", ""
                                    ),
                                    "identifier": node.get(
                                        "https://blackducksoftware.github.io/bdio#hasIdentifier", ""
                                    ),
                                }
                        elif ntype == "https://blackducksoftware.github.io/bdio#Project":
                            projects.append(node)

    # Collect detector issues from status.json
    if status_data:
        for issue in status_data.get("issues", []):
            msgs = issue.get("messages", [])
            if isinstance(msgs, list):
                joined = " ".join(m.strip() for m in msgs if m.strip())
                if joined:
                    detector_issues.append(joined)
            elif isinstance(msgs, str) and msgs.strip():
                detector_issues.append(msgs.strip())

        for overall in status_data.get("overallStatus", []):
            k = overall.get("key", "")
            st = overall.get("status", "")
            if k and k != "SUCCESS":
                detector_issues.append(f"{k}: {st}")

    # Match each expected subproject against BDIO and status.json
    subproject_results: list[dict[str, Any]] = []
    actual_code_locations = 0
    all_other_dirs = [
        s["directory"] for s in baseline.get("subprojects", []) if s.get("directory") != "."
    ]

    for sub in baseline.get("subprojects", []):
        d = sub.get("directory", ".")
        eco = sub.get("ecosystem", "UNKNOWN")
        exp_min = int(sub.get("expected_min_components", 0))

        # Match Project node
        matched_projs: list[dict[str, Any]] = []
        for p in projects:
            if (
                p.get("https://blackducksoftware.github.io/bdio#hasNamespace") == "root"
                or "https://blackducksoftware.github.io/bdio#hasSubproject" in p
            ):
                continue
            pid = str(p.get("@id", ""))
            pident = str(p.get("https://blackducksoftware.github.io/bdio#hasIdentifier", ""))

            if d == ".":
                is_root = (
                    "workspace" in pid.lower()
                    or "workspace" in pident.lower()
                    or not any(
                        f"/{od}/" in pid or f":{od}:" in pident or f"/{od}/" in pident
                        for od in all_other_dirs
                    )
                )
                if is_root:
                    matched_projs.append(p)
            else:
                clean_d = d.strip("/.")
                is_match = (
                    f"/{clean_d}/" in pid
                    or f":{clean_d}:" in pid
                    or f"/{clean_d}:" in pid
                    or f"/{clean_d}-" in pid
                    or f"/{clean_d}/" in pident
                    or f":{clean_d}:" in pident
                    or f"/{clean_d}:" in pident
                    or f"/{clean_d}-" in pident
                    or pid.endswith(f"/{clean_d}")
                    or pident.endswith(f"/{clean_d}")
                )
                if is_match:
                    matched_projs.append(p)

        dep_ids: set[str] = set()
        for proj in matched_projs:
            has_dep = proj.get("https://blackducksoftware.github.io/bdio#hasDependency", [])
            if isinstance(has_dep, dict):
                has_dep = [has_dep]
            for dep in has_dep:
                if isinstance(dep, dict):
                    d_on = dep.get("https://blackducksoftware.github.io/bdio#dependsOn", {})
                    cid = (
                        d_on.get("@id")
                        if isinstance(d_on, dict)
                        else (d_on if isinstance(d_on, str) else None)
                    )
                    if cid:
                        dep_ids.add(cid)

        actual_comp_count = len(dep_ids)
        if actual_comp_count > 0:
            actual_code_locations += 1

        # Match detector status from status.json
        det_status_str = "NOT_RUN"
        if status_data:
            matching_detectors: list[dict[str, Any]] = []
            for det in status_data.get("detectors", []):
                folder = det.get("folder", "")
                if d == ".":
                    folder_match = not any(
                        folder.endswith(f"/{od}") or f"/{od}/" in folder for od in all_other_dirs
                    )
                else:
                    clean_d = d.strip("/.")
                    folder_match = folder.endswith(f"/{clean_d}") or f"/{clean_d}/" in folder

                if folder_match:
                    matching_detectors.append(det)

            if matching_detectors:
                extracted_dets = [md for md in matching_detectors if md.get("extracted")]
                failed_dets = [md for md in matching_detectors if md.get("status") == "FAILURE"]
                if extracted_dets and actual_comp_count > 0:
                    det_status_str = "SUCCESS: PASSED"
                elif failed_dets:
                    det = failed_dets[0]
                    st = det.get("status", "")
                    code = det.get("statusCode", "")
                    rsn = det.get("statusReason", "")
                    det_status_str = f"{st}: {code}" if code != st else st
                    if rsn and rsn != "Passed":
                        det_status_str += f" ({rsn})"
                else:
                    det = matching_detectors[0]
                    st = det.get("status", "")
                    code = det.get("statusCode", "")
                    rsn = det.get("statusReason", "")
                    det_status_str = f"{st}: {code}" if code != st else st
                    if rsn and rsn != "Passed":
                        det_status_str += f" ({rsn})"

        if actual_comp_count >= exp_min:
            sub_status = "PASS"
        elif actual_comp_count == 0:
            sub_status = "FAIL_ZERO_COMPONENTS"
        else:
            sub_status = "FAIL_BELOW_BASELINE"

        subproject_results.append(
            {
                "directory": d,
                "ecosystem": eco,
                "expected_min_components": exp_min,
                "actual_components": actual_comp_count,
                "status": sub_status,
                "detector_status": det_status_str,
                "reason": sub.get("reason", ""),
            }
        )

    actual_total_components = len(components_by_id)
    expected_min_total = int(baseline.get("expected_min_total_components", 0))
    expected_code_locations = int(baseline.get("expected_code_locations", 0))

    if actual_total_components > 0:
        actual_code_locations = max(actual_code_locations, len(bdio_entries))
    else:
        actual_code_locations = 0

    if expected_min_total > 0 and actual_total_components == 0:
        verdict = "CRITICAL_EMPTY_BOM"
    elif (
        actual_code_locations < expected_code_locations
        or actual_total_components < expected_min_total
        or any(
            s["actual_components"] == 0
            for s in subproject_results
            if s["expected_min_components"] > 0
        )
    ):
        verdict = "INCOMPLETE_SILENT_FALSE_NEGATIVE"
    else:
        verdict = "COMPLETE_PASS"

    if verdict == "COMPLETE_PASS":
        summary = (
            f"COMPLETE PASS: Detected {actual_total_components} component(s) across "
            f"{actual_code_locations} code location(s), meeting baseline expectations."
        )
    elif verdict == "CRITICAL_EMPTY_BOM":
        summary = (
            f"CRITICAL EMPTY BOM: Zero components were extracted in BDIO output despite "
            f"baseline expecting at least {expected_min_total} component(s) across "
            f"{expected_code_locations} code location(s)."
        )
    else:
        missing = [
            f"{s['directory']} ({s['ecosystem']})"
            for s in subproject_results
            if s["actual_components"] < s["expected_min_components"]
        ]
        summary = (
            f"UNCALIBRATED COVERAGE GAP (Depth / Detector Configuration Mismatch): Detected {actual_total_components} component(s) across "
            f"{actual_code_locations} code location(s), below baseline expectations of at least "
            f"{expected_min_total} component(s) across {expected_code_locations} code location(s). "
            f"Subprojects requiring calibration: {', '.join(missing)}."
        )

    # 1. Detect operation telemetry
    detect_operations: list[dict[str, Any]] = []
    if status_data:
        for op in status_data.get("operations", []):
            desc = op.get("descriptionKey", "Unknown")
            st = op.get("status", "UNKNOWN")
            start = op.get("startTimestamp", "")
            end = op.get("endTimestamp", "")
            dur_sec: float | None = None
            if start and end:
                try:
                    t1 = datetime.fromisoformat(start.strip().replace(" ", "T"))
                    t2 = datetime.fromisoformat(end.strip().replace(" ", "T"))
                    dur_sec = round((t2 - t1).total_seconds(), 2)
                except (ValueError, TypeError):
                    pass
            detect_operations.append(
                {
                    "description": desc,
                    "status": st,
                    "duration_sec": dur_sec,
                    "start": start,
                    "end": end,
                }
            )

    # 2. Workspace & Scan Telemetry Summary
    pareto_hints = prescan_report.get("pareto_hints", {})
    workspace_telemetry = {
        "total_dirs_scanned": prescan_report.get("total_dirs_scanned", 0),
        "total_files_scanned": prescan_report.get("total_files_scanned", 0),
        "total_archives": len(prescan_report.get("oversized_archives", [])),
        "total_archives_mb": sum(
            float(a.get("size_mb", 0.0)) for a in prescan_report.get("oversized_archives", [])
        ),
        "lockfiles_count": len(prescan_report.get("lockfiles", [])),
        "unpinned_manifests_count": len(prescan_report.get("unpinned_manifests", [])),
        "docker_base_images_count": len(pareto_hints.get("docker_base_images", [])),
        "native_dependencies_count": len(pareto_hints.get("native_dependencies", [])),
        "binary_version_artifacts_count": len(pareto_hints.get("binary_version_artifacts", [])),
        "attribution_files_count": len(pareto_hints.get("attribution_files", [])),
    }
    provenance_summary = {
        "workspace_telemetry": workspace_telemetry,
        "detect_operations": detect_operations,
    }

    # 3. Silencer Flags Audit (Dev vs. AppSec/Admin Disconnect)
    silencer_flags_audit: list[dict[str, Any]] = []
    props = status_data.get("propertyValues", {}) if status_data else {}

    # Check empirical diagnostic bundle output path trap (Pete's Black Duck Community article)
    output_path_props = [
        prop_k for prop_k in ("detect.output.path", "detect.bdio.output.path", "detect.scan.output.path")
        if prop_k in props
    ]
    for prop_key in output_path_props:
        silencer_flags_audit.append(
            {
                "property": prop_key,
                "value": str(props[prop_key]),
                "level": "WARNING",
                "impact": (
                    "DIAGNOSTIC_BUNDLE_OUTPUT_PATH_TRAP: Overriding *output.path causes Detect's "
                    "-d / --detect.diagnostic=true log bundle .zip generator to exclude critical diagnostic "
                    "outputs (such as .bdio files) redirected outside the default ~/blackduck/runs/ directory. "
                    "Remove *output.path overrides during diagnostic runs or manually collect redirected directories."
                ),
            }
        )

    acc = str(props.get("detect.accuracy.required", ""))
    if acc.upper() == "NONE":
        silencer_flags_audit.append(
            {
                "property": "detect.accuracy.required",
                "value": "NONE",
                "level": "WARNING",
                "impact": (
                    "detect.accuracy.required=NONE suppresses Code 5 exit when package managers fail to resolve. "
                    "Allows low-accuracy heuristic fallbacks or empty BOMs into production."
                ),
            }
        )

    excl_det = str(props.get("detect.excluded.detector.types", ""))
    if excl_det:
        silencer_flags_audit.append(
            {
                "property": "detect.excluded.detector.types",
                "value": excl_det,
                "level": "NOTICE",
                "impact": f"detect.excluded.detector.types={excl_det} explicitly disables specific detector engines entirely.",
            }
        )

    excl_dir = str(props.get("detect.excluded.directories", ""))
    if excl_dir:
        silencer_flags_audit.append(
            {
                "property": "detect.excluded.directories",
                "value": excl_dir,
                "level": "NOTICE",
                "impact": f"detect.excluded.directories={excl_dir} excludes directories from traversal. Verify vendored dependencies were not skipped.",
            }
        )

    depth_val = props.get("detect.detector.search.depth")
    max_dep = int(prescan_report.get("max_manifest_depth", 0))
    if depth_val is not None:
        try:
            idp = int(depth_val)
            if idp < max_dep:
                silencer_flags_audit.append(
                    {
                        "property": "detect.detector.search.depth",
                        "value": str(idp),
                        "level": "CRITICAL",
                        "impact": (
                            f"detect.detector.search.depth={idp} is shallower than discovered manifest depth ({max_dep}). "
                            "Manifests in deeper subdirectories will be silently skipped."
                        ),
                    }
                )
        except ValueError:
            pass

    tools_val = str(props.get("detect.tools", ""))
    has_archives = bool(
        pareto_hints.get("binary_version_artifacts")
        or prescan_report.get("oversized_archives")
    )
    has_native = bool(pareto_hints.get("native_dependencies"))
    if (
        "DETECTOR" in tools_val.upper()
        and "SIGNATURE_SCAN" not in tools_val.upper()
        and "BINARY_SCAN" not in tools_val.upper()
        and (has_archives or has_native)
    ):
        count_arch = len(prescan_report.get("oversized_archives", [])) or len(
            pareto_hints.get("binary_version_artifacts", [])
        )
        silencer_flags_audit.append(
            {
                "property": "detect.tools",
                "value": tools_val,
                "level": "WARNING",
                "impact": (
                    f"detect.tools={tools_val} skips signature and binary scanning. "
                    f"{count_arch} archive(s) or unmanaged native C/C++ files will NOT be inspected for BOM components."
                ),
            }
        )

    # 4. Disconnect Analysis: "Our Pre-Scan Found X, But the BDIO Only Had Y - Is That By Explicit Design?"
    disconnect_audit: list[dict[str, Any]] = []
    recommended_remedy_args: list[str] = []

    # Check for missing/failed subprojects
    for s in subproject_results:
        if s["expected_min_components"] > 0 and s["actual_components"] == 0:
            det_status = s.get("detector_status", "NOT_RUN")
            disconnect_audit.append(
                {
                    "category": "MISSING_SUBPROJECT",
                    "item": f"[{s['ecosystem']}] {s['directory']}",
                    "pre_scan_finding": s["reason"],
                    "bdio_finding": "0 components in BDIO",
                    "root_cause": f"Detector status: {det_status}",
                    "remedy": (
                        f"Ensure required CLI tool for {s['ecosystem']} is installed in runtime environment, "
                        f"pass --detect.detector.search.depth={max(2, max_dep)}, and resolve detector errors."
                    ),
                }
            )
            if f"--detect.detector.search.depth={max(2, max_dep)}" not in recommended_remedy_args:
                recommended_remedy_args.append(f"--detect.detector.search.depth={max(2, max_dep)}")

    # Check for unscanned binary archives
    if (
        has_archives
        and "SIGNATURE_SCAN" not in tools_val.upper()
        and "BINARY_SCAN" not in tools_val.upper()
    ):
        arch_list = prescan_report.get("oversized_archives", []) or pareto_hints.get(
            "binary_version_artifacts", []
        )
        for arch in arch_list:
            disconnect_audit.append(
                {
                    "category": "UNSCANNED_ARCHIVE",
                    "item": arch.get("path", arch.get("filename", "unknown")),
                    "pre_scan_finding": f"Archive ({arch.get('size_mb', 0)} MB) present in workspace",
                    "bdio_finding": "Omitted from BDIO (detect.tools=DETECTOR)",
                    "root_cause": "Signature and binary scanners disabled by detect.tools=DETECTOR",
                    "remedy": "Add --detect.tools=DETECTOR,SIGNATURE_SCAN or upload archive via BINARY_SCAN",
                }
            )
        if "--detect.tools=DETECTOR,SIGNATURE_SCAN" not in recommended_remedy_args:
            recommended_remedy_args.append("--detect.tools=DETECTOR,SIGNATURE_SCAN")

    # Check for Docker base images
    if pareto_hints.get("docker_base_images"):
        for dimg in pareto_hints["docker_base_images"]:
            disconnect_audit.append(
                {
                    "category": "UNSCANNED_CONTAINER_BASE",
                    "item": dimg.get("full_spec", "unknown"),
                    "pre_scan_finding": f"Dockerfile base image '{dimg.get('full_spec')}' declared in {dimg.get('path')}",
                    "bdio_finding": "Base image components not present in BDIO",
                    "root_cause": "Detect workspace scan analyzes source code only; container layers require Docker tool",
                    "remedy": f"Scan image '{dimg.get('full_spec')}' with Black Duck container scanner or add --detect.tools=DOCKER",
                }
            )

    # Check for native C/C++ dependencies
    if pareto_hints.get("native_dependencies") and "SIGNATURE_SCAN" not in tools_val.upper():
        unique_native = sorted(
            {nd.get("name", "") for nd in pareto_hints["native_dependencies"] if nd.get("name")}
        )
        disconnect_audit.append(
            {
                "category": "UNSCANNED_NATIVE_DEPENDENCIES",
                "item": ", ".join(unique_native[:5]),
                "pre_scan_finding": f"{len(pareto_hints['native_dependencies'])} native C/C++ dependency hint(s) ({', '.join(unique_native[:5])})",
                "bdio_finding": "0 native C/C++ components in BDIO",
                "root_cause": "Package-manager-only (DETECTOR) scans miss unmanaged C/C++ headers and source files",
                "remedy": "Enable --detect.tools=DETECTOR,SIGNATURE_SCAN for snippet/file matching in Black Duck KnowledgeBase",
            }
        )
        if "--detect.tools=DETECTOR,SIGNATURE_SCAN" not in recommended_remedy_args:
            recommended_remedy_args.append("--detect.tools=DETECTOR,SIGNATURE_SCAN")

    # Prevent false COMPLETE_PASS when 0 BDIO components were extracted despite unscanned archives/native artifacts
    if verdict == "COMPLETE_PASS" and actual_total_components == 0 and disconnect_audit:
        verdict = "CRITICAL_EMPTY_BOM"
        summary = (
            f"CRITICAL EMPTY BOM: Zero components were extracted in BDIO output while "
            f"pre-scan identified {len(disconnect_audit)} unscanned binary/archive/native "
            f"artifact disconnect(s) in the workspace."
        )

    return {
        "verdict": verdict,
        "actual_total_components": actual_total_components,
        "expected_min_total_components": expected_min_total,
        "actual_code_locations": actual_code_locations,
        "expected_code_locations": expected_code_locations,
        "detect_run_path": str(run_path),
        "bdio_files": [name for name, _ in bdio_entries],
        "subproject_results": subproject_results,
        "components": list(components_by_id.values()),
        "detector_issues": detector_issues,
        "summary": summary,
        "provenance_summary": provenance_summary,
        "silencer_flags_audit": silencer_flags_audit,
        "disconnect_audit": disconnect_audit,
        "recommended_remedy_arguments": recommended_remedy_args,
    }
