"""Catalog loaders, manifest parsers, constants, and advisory definitions.

Provides the foundational component recognition tables, known lockfiles,
Pareto catalog/KB parsers, and confirmation notices.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

PrescanReport = dict[str, Any]

__all__ = [
    "ARCHIVE_EXTENSIONS",
    "BD_CONFIRMATION_ADVISORY",
    "BINARY_BANNER_BLOCKLIST",
    "C_PREFIX_COMPONENT_MAP",
    "CONDITIONAL_DIR_CANDIDATES",
    "ECOSYSTEM_MAP",
    "GENERIC_DIR_PREFIXES",
    "GENERIC_MACRO_PREFIXES",
    "JS_LOCKFILES",
    "KNOWN_LOCKFILES",
    "KNOWN_NON_BINARY_EXTENSIONS",
    "KNOWN_UNPINNED_MANIFESTS",
    "STANDARD_SAFE_EXCLUSIONS",
    "PrescanReport",
    "TokenizationDictionary",
    "_normalize_component_name",
    "_parse_c_version_header_bytes",
    "_parse_cargo_toml_bytes",
    "_parse_cmakelists_bytes",
    "_parse_debian_control_bytes",
    "_parse_nuspec_bytes",
    "_parse_package_json_bytes",
    "_parse_pkginfo_bytes",
    "export_learned_catalog",
    "load_pareto_catalog",
    "load_pareto_license_kb",
    "load_pareto_vuln_kb",
    "load_snippet_signatures",
    "safe_parse_xml_bytes",
    "sanitize_ipv4_match",
    "sanitize_line",
]

JS_LOCKFILES = frozenset({"package-lock.json", "yarn.lock", "pnpm-lock.yaml"})

KNOWN_LOCKFILES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.lock",
        "go.sum",
        "poetry.lock",
        "Pipfile.lock",
        "uv.lock",
        "composer.lock",
        "gradle.lockfile",
        "packages.lock.json",
        "conan.lock",
        "Gemfile.lock",
        "mix.lock",
        "Package.resolved",
        "Podfile.lock",
        "pubspec.lock",
    }
)

KNOWN_UNPINNED_MANIFESTS = frozenset(
    {
        "package.json",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "dependencies.gradle",
        "libs.versions.toml",
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "go.mod",
        "Cargo.toml",
        "MODULE.bazel",
        "WORKSPACE",
        "WORKSPACE.bazel",
        "conanfile.txt",
        "conanfile.py",
        "vcpkg.json",
        "Gemfile",
        "mix.exs",
        "Package.swift",
        "Podfile",
        "pubspec.yaml",
        "build.sbt",
        "environment.yml",
        "Directory.Packages.props",
        "Directory.Build.props",
        "packages.config",
        "oe-init-build-env",
        "layer.conf",
        "bblayers.conf",
    }
)

STANDARD_SAFE_EXCLUSIONS = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        ".gradle",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
    }
)

CONDITIONAL_DIR_CANDIDATES = frozenset(
    {"vendor", "third_party", "target", "build", "dist", "out"}
)

ARCHIVE_EXTENSIONS = frozenset(
    {
        ".jar",
        ".war",
        ".ear",
        ".zip",
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.bz2",
        ".tbz2",
        ".tar.xz",
        ".txz",
        ".whl",
        ".egg",
        ".nupkg",
        ".gem",
        ".ipk",
        ".deb",
        ".rpm",
    }
)

GENERIC_DIR_PREFIXES = frozenset(
    {
        "test",
        "tests",
        "release",
        "releases",
        "api",
        "v1",
        "v2",
        "tls",
        "http",
        "oauth",
        "schema",
        "step",
        "phase",
        "doc",
        "docs",
        "build",
        "dist",
        "stage",
        "layer",
    }
)

ECOSYSTEM_MAP: dict[str, str] = {
    "package-lock.json": "NPM",
    "yarn.lock": "NPM",
    "pnpm-lock.yaml": "NPM",
    "package.json": "NPM",
    "requirements.txt": "PYTHON",
    "pyproject.toml": "PYTHON",
    "setup.py": "PYTHON",
    "Pipfile.lock": "PYTHON",
    "poetry.lock": "PYTHON",
    "uv.lock": "PYTHON",
    "environment.yml": "CONDA",
    "go.sum": "GO",
    "go.mod": "GO",
    "pom.xml": "MAVEN",
    "build.gradle": "GRADLE",
    "build.gradle.kts": "GRADLE",
    "dependencies.gradle": "GRADLE",
    "libs.versions.toml": "GRADLE",
    "gradle.lockfile": "GRADLE",
    "build.sbt": "SBT",
    "Cargo.lock": "CARGO",
    "Cargo.toml": "CARGO",
    "composer.lock": "COMPOSER",
    "packages.lock.json": "NUGET",
    "Directory.Packages.props": "NUGET",
    "Directory.Build.props": "NUGET",
    "packages.config": "NUGET",
    "conan.lock": "C_CPP",
    "conanfile.txt": "C_CPP",
    "conanfile.py": "C_CPP",
    "vcpkg.json": "C_CPP",
    "MODULE.bazel": "BAZEL",
    "WORKSPACE": "BAZEL",
    "WORKSPACE.bazel": "BAZEL",
    "Gemfile": "RUBY",
    "Gemfile.lock": "RUBY",
    "mix.exs": "HEX",
    "mix.lock": "HEX",
    "Package.swift": "SWIFT",
    "Package.resolved": "SWIFT",
    "Podfile": "SWIFT",
    "Podfile.lock": "SWIFT",
    "pubspec.yaml": "DART",
    "pubspec.lock": "DART",
    "oe-init-build-env": "BITBAKE",
    "layer.conf": "BITBAKE",
    "bblayers.conf": "BITBAKE",
    "status": "OPKG",
}

C_PREFIX_COMPONENT_MAP: dict[str, str] = {
    "php": "php",
    "curl": "curl",
    "libcurl": "curl",
    "zlib": "zlib",
    "openssl": "openssl",
    "libxml": "libxml2",
    "libxml2": "libxml2",
    "nghttp2": "nghttp2",
    "expat": "expat",
    "libexpat": "expat",
    "webp": "libwebp",
    "libwebp": "libwebp",
}

BINARY_BANNER_BLOCKLIST: frozenset[str] = frozenset(
    {
        "http",
        "https",
        "tls",
        "ssl",
        "mozilla",
        "applewebkit",
        "gecko",
        "chrome",
        "safari",
        "edge",
        "linux",
        "windows",
        "darwin",
        "release",
        "version",
        "build",
        "api",
        "v1",
        "v2",
        "test",
        "dev",
        "prod",
        "usr",
        "lib",
        "bin",
        "opt",
        "etc",
        "var",
        "tmp",
        "gnu",
        "elf",
        "utf",
    }
)

KNOWN_NON_BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".md",
        ".txt",
        ".rst",
        ".bb",
        ".bbappend",
        ".inc",
        ".dts",
        ".dtsi",
        ".json",
        ".jsonl",
        ".yaml",
        ".yml",
        ".toml",
        ".xml",
        ".html",
        ".css",
        ".scss",
        ".svg",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".lock",
        ".sql",
        ".csv",
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cc",
        ".go",
        ".rs",
        ".sh",
        ".bat",
        ".ps1",
        ".rb",
        ".php",
        ".cs",
        ".kt",
        ".swift",
        ".scala",
        ".gradle",
        ".properties",
        ".cfg",
        ".ini",
        ".env",
        ".pem",
        ".key",
        ".crt",
        ".class",
    }
)

GENERIC_MACRO_PREFIXES: frozenset[str] = frozenset(
    {
        "min",
        "max",
        "default",
        "protocol",
        "schema",
        "api",
        "file",
        "product",
        "format",
        "abi",
        "major",
        "minor",
        "patch",
        "timeout",
    }
)

BD_CONFIRMATION_ADVISORY: str = (
    "PRELIMINARY PRE-FLIGHT HEURISTIC: bd-ops-toolkit provides fast local workspace "
    "preparation and configuration tuning. Always confirm preliminary component, license, "
    "and security canary findings using your licensed Black Duck SCA Server, Black Duck "
    "Package Manager Detectors, Black Duck Signature Scanner, and Black Duck Binary Analysis (BDBA)."
)


def safe_parse_xml_bytes(data: bytes) -> ET.Element | None:
    """Safely parse XML bytes, rejecting XXE injection, DOCTYPE declarations, entity expansions, or oversized payloads."""
    if len(data) > 2 * 1024 * 1024:
        return None
    lower_bytes = data.lower()
    if b"<!doctype" in lower_bytes or b"<!entity" in lower_bytes:
        return None
    try:
        return ET.fromstring(data)
    except (ET.ParseError, ValueError):
        return None


def _parse_package_json_bytes(raw_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract name and version from package.json bytes."""
    if len(raw_bytes) > 64 * 1024:
        return None, None
    try:
        data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        if isinstance(data, dict):
            name = data.get("name")
            ver = data.get("version")
            return (str(name).strip() if name else None, str(ver).strip() if ver else None)
    except Exception:  # noqa: BLE001
        pass
    return None, None


def _parse_nuspec_bytes(raw_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract package id and version from .nuspec XML bytes."""
    if len(raw_bytes) > 64 * 1024:
        return None, None
    root_elem = safe_parse_xml_bytes(raw_bytes)
    if root_elem is None:
        return None, None
    pkg_id: str | None = None
    pkg_ver: str | None = None
    for elem in root_elem.iter():
        tag = elem.tag.split("}")[-1].lower()
        if tag == "id" and elem.text and not pkg_id:
            pkg_id = elem.text.strip()
        elif tag == "version" and elem.text and not pkg_ver:
            pkg_ver = elem.text.strip()
    return pkg_id, pkg_ver


def _parse_debian_control_bytes(raw_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract Package and Version from DEBIAN/control bytes."""
    if len(raw_bytes) > 64 * 1024:
        return None, None
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        pkg: str | None = None
        ver: str | None = None
        for line in text.splitlines():
            line = line[:4096].strip()
            if line.lower().startswith("package:"):
                pkg = line.split(":", 1)[1].strip()
            elif line.lower().startswith("version:"):
                ver = line.split(":", 1)[1].strip()
        return pkg, ver
    except Exception:  # noqa: BLE001
        return None, None


def _parse_pkginfo_bytes(raw_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract pkgname and pkgver from .PKGINFO bytes."""
    if len(raw_bytes) > 64 * 1024:
        return None, None
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        pkg: str | None = None
        ver: str | None = None
        for line in text.splitlines():
            line = line[:4096].strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                k_s = k.strip()
                v_s = v.strip().strip('"').strip("'")
                if k_s == "pkgname":
                    pkg = v_s
                elif k_s == "pkgver":
                    ver = v_s
        return pkg, ver
    except Exception:  # noqa: BLE001
        return None, None


def _parse_cargo_toml_bytes(raw_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract package name and version from Cargo.toml bytes."""
    if len(raw_bytes) > 64 * 1024:
        return None, None
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        data = tomllib.loads(text)
        pkg = data.get("package", {})
        if isinstance(pkg, dict):
            name = pkg.get("name")
            ver = pkg.get("version")
            return (str(name).strip() if name else None, str(ver).strip() if ver else None)
    except Exception:  # noqa: BLE001
        pass
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        in_pkg = False
        name_s: str | None = None
        ver_s: str | None = None
        for line in text.splitlines():
            line = line[:4096].strip()
            if line.startswith("[") and line.endswith("]"):
                in_pkg = line == "[package]"
            elif in_pkg and "=" in line:
                k, v = line.split("=", 1)
                k_s = k.strip()
                v_s = v.strip().strip('"').strip("'")
                if k_s == "name" and not name_s:
                    name_s = v_s
                elif k_s == "version" and not ver_s:
                    ver_s = v_s
        return name_s, ver_s
    except Exception:  # noqa: BLE001
        return None, None


def _parse_cmakelists_bytes(raw_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract project name and VERSION from CMakeLists.txt bytes."""
    if len(raw_bytes) > 64 * 1024:
        raw_bytes = raw_bytes[:65536]
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        m = re.search(
            r"project\s*\(\s*([a-zA-Z0-9_\-]+)[^)]*?\bVERSION\s+(\d+(?:\.\d+)+[0-9a-zA-Z_.\-]*)",
            text[:65536],
            re.IGNORECASE,
        )
        if m:
            return m.group(1).strip(), m.group(2).strip()
    except Exception:  # noqa: BLE001
        pass
    return None, None


def _parse_c_version_header_bytes(raw_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract component and version from C/C++ *version*.h header bytes.

    Requires a mandatory version suffix (_VERSION, _VERSION_STR, etc.) and
    filters out generic macro prefixes (min, max, default, etc.).
    """
    if len(raw_bytes) > 64 * 1024:
        raw_bytes = raw_bytes[:65536]
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        for line in text.splitlines():
            line = line[:4096].strip()
            if not line.startswith("#"):
                continue
            m = re.search(
                r"^#\s*define\s+([A-Za-z0-9_]+?)(?:_VERSION|_VERSION_STR|_VERSION_STRING|_DOTTED_VERSION|_VER)\s+[\"'](\d+\.\d+(?:\.[0-9a-zA-Z_.\-]+)?)[\"']",
                line,
            )
            if m:
                raw_prefix = m.group(1).lower().rstrip("_")
                if raw_prefix in GENERIC_MACRO_PREFIXES:
                    continue
                comp = C_PREFIX_COMPONENT_MAP.get(raw_prefix, raw_prefix)
                ver = m.group(2).strip()
                if comp and ver:
                    return comp, ver
            m_str = re.search(
                r"^#\s*define\s+([A-Za-z0-9_]+?)(?:_VERSION|_VERSION_STR|_VERSION_STRING|_DOTTED_VERSION|_VER)\s+STR\s*\(\s*[\"']?(\d+\.\d+(?:\.[0-9a-zA-Z_.\-]+)?)[\"']?\s*\)",
                line,
            )
            if m_str:
                raw_prefix = m_str.group(1).lower().rstrip("_")
                if raw_prefix in GENERIC_MACRO_PREFIXES:
                    continue
                comp = C_PREFIX_COMPONENT_MAP.get(raw_prefix, raw_prefix)
                ver = m_str.group(2).strip()
                if comp and ver:
                    return comp, ver
    except Exception:  # noqa: BLE001
        pass
    return None, None


def _normalize_component_name(name: str) -> str:
    """Normalize component names by lowercasing, stripping punctuation, and trimming."""
    return re.sub(r"[-_\s.]+", "-", name.strip().lower()).strip("-")


def decode_manifest_bytes(raw_bytes: bytes) -> tuple[str, str]:
    """Decode manifest bytes while detecting UTF-16 BOM or null-byte interleaved encodings.

    Returns (decoded_text, encoding_name). Black Duck Detect reads requirements.txt
    as UTF-8, which corrupts UTF-16LE/BE files (common from Windows PowerShell) with
    interleaved null bytes (\\u0000) in BDIO output.
    """
    if raw_bytes.startswith(b"\xff\xfe"):
        try:
            return raw_bytes.decode("utf-16-le", errors="replace").lstrip("\ufeff"), "utf-16-le"
        except Exception:  # noqa: BLE001
            pass
    elif raw_bytes.startswith(b"\xfe\xff"):
        try:
            return raw_bytes.decode("utf-16-be", errors="replace").lstrip("\ufeff"), "utf-16-be"
        except Exception:  # noqa: BLE001
            pass
    elif raw_bytes.startswith(b"\xef\xbb\xbf"):
        return raw_bytes[3:].decode("utf-8", errors="replace"), "utf-8-sig"

    # Heuristic for BOM-less UTF-16LE/BE (interleaved null bytes in ASCII text)
    sample = raw_bytes[:512]
    if len(sample) >= 4 and b"\x00" in sample:
        even_nulls = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
        odd_nulls = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
        half_len = len(sample) // 2
        if odd_nulls >= max(2, int(half_len * 0.6)):
            return raw_bytes.decode("utf-16-le", errors="replace"), "utf-16-le"
        if even_nulls >= max(2, int(half_len * 0.6)):
            return raw_bytes.decode("utf-16-be", errors="replace"), "utf-16-be"

    return raw_bytes.decode("utf-8", errors="replace"), "utf-8"


def load_pareto_catalog(custom_catalog_path: str | Path | None = None) -> dict[str, Any]:
    """Load default pareto catalog and merge optional customer custom catalog."""
    default_catalog_file = Path(__file__).parent / "pareto_catalog.json"
    catalog: dict[str, Any] = {"version": "1.0.0", "components": [], "disaster_smells": []}
    if default_catalog_file.exists():
        try:
            with open(default_catalog_file, encoding="utf-8") as f:
                catalog = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    if custom_catalog_path:
        cpath = Path(custom_catalog_path)
        if cpath.exists():
            try:
                with open(cpath, encoding="utf-8") as cf:
                    custom_data = json.load(cf)

                comp_map = {
                    c["name"]: c
                    for c in catalog.get("components", [])
                    if isinstance(c, dict) and "name" in c
                }
                for cc in custom_data.get("components", []):
                    if isinstance(cc, dict) and "name" in cc:
                        comp_map[cc["name"]] = cc
                catalog["components"] = list(comp_map.values())

                smell_map = {
                    s["id"]: s
                    for s in catalog.get("disaster_smells", [])
                    if isinstance(s, dict) and "id" in s
                }
                for cs in custom_data.get("disaster_smells", []):
                    if isinstance(cs, dict) and "id" in cs:
                        smell_map[cs["id"]] = cs
                catalog["disaster_smells"] = list(smell_map.values())
            except (json.JSONDecodeError, OSError):
                pass

    return catalog


_DEFAULT_VULN_KB_CACHE: list[dict[str, Any]] | None = None


def load_pareto_vuln_kb(custom_kb_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load the 7-axis Pareto Actionable Vulnerability Knowledge Base and merge optional custom overlay."""
    global _DEFAULT_VULN_KB_CACHE  # noqa: PLW0603
    default_kb_file = Path(__file__).parent / "pareto_vuln_kb.json"
    vulns: list[dict[str, Any]] = []

    if _DEFAULT_VULN_KB_CACHE is not None:
        vulns = list(_DEFAULT_VULN_KB_CACHE)
    elif default_kb_file.is_file():
        try:
            data = json.loads(default_kb_file.read_text(encoding="utf-8"))
            raw_v = data.get("vulnerabilities", [])
            if isinstance(raw_v, list):
                vulns = [v for v in raw_v if isinstance(v, dict)]
                _DEFAULT_VULN_KB_CACHE = list(vulns)
        except (json.JSONDecodeError, OSError):
            pass

    if custom_kb_path:
        cpath = Path(custom_kb_path)
        if cpath.is_file():
            try:
                custom_data = json.loads(cpath.read_text(encoding="utf-8"))
                custom_vulns = custom_data.get("vulnerabilities", [])
                if isinstance(custom_vulns, list) and custom_vulns:
                    vuln_map: dict[tuple[str, str], dict[str, Any]] = {
                        (str(v.get("cve_id", "")), str(v.get("component", ""))): v
                        for v in vulns
                    }
                    for cv in custom_vulns:
                        if isinstance(cv, dict) and cv.get("cve_id"):
                            c_aliases = list(cv.get("aliases") or cv.get("component_aliases") or [])
                            comp_key = str(cv.get("component") or (c_aliases[0] if c_aliases else ""))
                            if comp_key:
                                vuln_map[(str(cv["cve_id"]), comp_key)] = cv
                    vulns = list(vuln_map.values())
            except (json.JSONDecodeError, OSError):
                pass
    return vulns


def load_pareto_license_kb(custom_kb_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load the Pareto High-Severity License & Rugpull Knowledge Base and merge optional custom overlay."""
    default_lic_file = Path(__file__).parent / "pareto_license_kb.json"
    rules: list[dict[str, Any]] = []

    if default_lic_file.is_file():
        try:
            data = json.loads(default_lic_file.read_text(encoding="utf-8"))
            raw_r = data.get("license_rules", [])
            if isinstance(raw_r, list):
                rules = [r for r in raw_r if isinstance(r, dict)]
        except (json.JSONDecodeError, OSError):
            pass

    if custom_kb_path:
        cpath = Path(custom_kb_path)
        if cpath.is_file():
            try:
                custom_data = json.loads(cpath.read_text(encoding="utf-8"))
                custom_rules = custom_data.get("license_rules", [])
                if isinstance(custom_rules, list) and custom_rules:
                    rule_map: dict[str, dict[str, Any]] = {
                        str(r.get("rule_id", "")): r for r in rules
                    }
                    for cr in custom_rules:
                        if isinstance(cr, dict) and cr.get("rule_id"):
                            rule_map[str(cr["rule_id"])] = cr
                    rules = list(rule_map.values())
            except (json.JSONDecodeError, OSError):
                pass
    return rules


_DEFAULT_SNIPPET_CACHE: list[dict[str, Any]] | None = None


def load_snippet_signatures(custom_kb_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load the unpatched code snippet and shaded-bytecode signatures and merge optional custom overlay."""
    global _DEFAULT_SNIPPET_CACHE  # noqa: PLW0603
    default_sig_file = Path(__file__).parent / "snippet_signatures.json"
    sigs: list[dict[str, Any]] = []

    if _DEFAULT_SNIPPET_CACHE is not None:
        sigs = list(_DEFAULT_SNIPPET_CACHE)
    elif default_sig_file.is_file():
        try:
            data = json.loads(default_sig_file.read_text(encoding="utf-8"))
            raw_s = data.get("signatures", [])
            if isinstance(raw_s, list):
                sigs = [s for s in raw_s if isinstance(s, dict)]
                _DEFAULT_SNIPPET_CACHE = list(sigs)
        except (json.JSONDecodeError, OSError):
            pass

    if custom_kb_path:
        cpath = Path(custom_kb_path)
        if cpath.is_file():
            try:
                custom_data = json.loads(cpath.read_text(encoding="utf-8"))
                custom_sigs = custom_data.get("snippet_signatures") or custom_data.get("signatures") or []
                if isinstance(custom_sigs, list) and custom_sigs:
                    sig_map: dict[str, dict[str, Any]] = {
                        str(s.get("rule_id", "")): s for s in sigs
                    }
                    for cs in custom_sigs:
                        if isinstance(cs, dict) and cs.get("rule_id"):
                            sig_map[str(cs["rule_id"])] = cs
                    sigs = list(sig_map.values())
            except (json.JSONDecodeError, OSError):
                pass
    return sigs



def export_learned_catalog(
    components: list[dict[str, Any]],
    output_path: str | Path,
) -> None:
    """Export discovered components as a reusable customer-specific overlay catalog JSON."""
    learned_components: list[dict[str, Any]] = []
    seen: set[str] = set()

    for comp in components:
        name = str(comp.get("name") or comp.get("componentName") or "")
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        namespace = str(
            comp.get("namespace") or comp.get("default_external_id_namespace") or "generic"
        )
        learned_components.append(
            {
                "name": name,
                "ecosystem": namespace.upper() if namespace in ("maven", "npm", "pypi") else "SYSTEM",
                "family": "LEARNED",
                "headers": [],
                "cmake_names": [name.lower()],
                "pkgconfig_names": [name.lower()],
                "sonames": [f"lib{name.lower()}.so"],
                "dir_markers": [name.lower()],
                "copyright_banners": [],
                "binary_version_regex": rf"{re.escape(name)}[\s/\-]+v?(\d+\.\d+[0-9a-zA-Z._\-]*)",
                "default_external_id_namespace": namespace,
            }
        )

    out_data = {
        "version": "1.0.0",
        "description": "Customer learned component overlay catalog",
        "components": learned_components,
        "disaster_smells": [],
    }

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(out_data, indent=2) + "\n", encoding="utf-8")


# ==============================================================================
# DLP Sanitization & Log Scrubbing (integrated for zero extra dependencies)
# ==============================================================================

RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_AUTH_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.+/=]{16,}")
RE_AUTH_BASIC = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/]+={0,2}")
RE_AUTH_BD_TOKEN = re.compile(
    r"""(?i)(?:Authorization:\s*token\s+|--(?:blackduck\.api\.token|bd-token)[=\s]+|BLACKDUCK_API_TOKEN[=\s]+|api_token[=\s]+)([A-Za-z0-9_\-\.+/=]{4,})"""
)
RE_URI_USERINFO = re.compile(r"""([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)""")
RE_PASSWORD_ASSIGN = re.compile(
    r"""(?i)\b([A-Za-z0-9_.]*(?:password|passwd|pwd|secret|PGPASSWORD))\b\s*([:=])\s*(?:"([^"]+)"|'([^']+)'|([^\s,;'"\]\}]+))"""
)
RE_PASSWORD_JSON = re.compile(
    r'(?i)("[A-Za-z0-9_.]*(?:password|passwd|pwd|secret|PGPASSWORD)")\s*:\s*"([^"]+)"'
)
RE_INTERNAL_FQDN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:local|internal|corp|lan|intranet|priv)\b",
    re.IGNORECASE,
)
RE_HOME_PATH_LINUX = re.compile(r"""/home/(?!api/|sys/|proc/)[A-Za-z0-9_\.\-]+(?=/|["'\s,;:)\]]|$)""")
RE_HOME_PATH_DARWIN = re.compile(r"""/Users/(?!api/|sys/|proc/)[A-Za-z0-9_\.\-]+(?=/|["'\s,;:)\]]|$)""")
RE_HOME_PATH_WINDOWS = re.compile(r"""[A-Za-z]:\\Users\\[A-Za-z0-9_\.\-]+(?=\\|["'\s,;:)\]]|$)""")
RE_VERSION_PREFIX = re.compile(
    r"""(?i)(?:^|(?<![A-Za-z0-9]))(?:v|ver|version|rel|release|detect|postgres(?:ql)?\s+version)(?:\s*[:=/_-]|\s*)$"""
)
RE_IPV4 = re.compile(
    r"""(?<!\d\.)(?<!\d)((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?!\.\d)(?!\d)"""
)


class TokenizationDictionary:
    """Deterministic tokenization mapping table for sensitive customer entities."""

    def __init__(self) -> None:
        self.counters: dict[str, int] = {
            "Project": 0,
            "Version": 0,
            "CodeLoc": 0,
            "Term": 0,
        }
        self.term_to_token: dict[str, str] = {}
        self.token_to_term: dict[str, str] = {}

    def get_or_create(self, raw_term: str, category: str = "Term") -> str:
        """Return existing token or register new token for the given entity string."""
        clean = raw_term.strip()
        if not clean:
            return ""
        if clean in self.term_to_token:
            return self.term_to_token[clean]

        self.counters[category] = self.counters.get(category, 0) + 1
        token = f"{category}_{self.counters[category]:03d}"
        self.term_to_token[clean] = token
        self.token_to_term[token] = clean
        return token

    def ingest_terms(self, terms: list[str], category: str = "Term") -> None:
        """Register a list of terms into the dictionary."""
        for t in terms:
            self.get_or_create(t, category)

    def save_mapping(self, path: str | Path) -> None:
        """Write mapping table to JSON file with strict 0600 file permissions."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "term_to_token": self.term_to_token,
            "token_to_term": self.token_to_term,
        }
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        with contextlib.suppress(OSError):
            os.chmod(target, 0o600)

    def load_mapping(self, path: str | Path) -> None:
        """Load existing mapping table from JSON file."""
        target = Path(path)
        if not target.is_file():
            return
        data = json.loads(target.read_text(encoding="utf-8"))
        self.term_to_token = data.get("term_to_token", {})
        self.token_to_term = data.get("token_to_term", {})


def sanitize_ipv4_match(match: re.Match[str], line_prefix: str) -> str:
    """Replace IP with [REDACTED_IP] unless it is loopback or preceded by version prefix."""
    ip_str = match.group(1)
    if ip_str == "127.0.0.1":
        return ip_str

    if RE_VERSION_PREFIX.search(line_prefix):
        return ip_str

    return "[REDACTED_IP]"


def sanitize_line(
    line: str,
    tokenizer: TokenizationDictionary | None = None,
) -> str:
    """Sanitize a single log line according to DLP rules."""
    text = line

    text = RE_AUTH_BD_TOKEN.sub(
        lambda m: m.group(0).replace(m.group(1), "[REDACTED_TOKEN]"), text
    )
    text = RE_AUTH_BEARER.sub("Bearer [REDACTED_TOKEN]", text)
    text = RE_AUTH_BASIC.sub("Basic [REDACTED_TOKEN]", text)

    text = RE_URI_USERINFO.sub(r"\1[REDACTED_SECRET]\3", text)

    text = RE_PASSWORD_ASSIGN.sub(r"\1\2[REDACTED_PASSWORD]", text)
    text = RE_PASSWORD_JSON.sub(r'\1: "[REDACTED_PASSWORD]"', text)

    text = RE_EMAIL.sub("user@redacted.domain", text)

    text = RE_HOME_PATH_LINUX.sub("/REDACTED_HOME/[REDACTED_USER]", text)
    text = RE_HOME_PATH_DARWIN.sub("/Users/[REDACTED_USER]", text)
    text = RE_HOME_PATH_WINDOWS.sub(lambda _: "C:\\Users\\[REDACTED_USER]", text)
    text = RE_INTERNAL_FQDN.sub("[REDACTED_HOST]", text)

    def _ip_replacer(m: re.Match[str]) -> str:
        start_idx = m.start()
        prefix = text[max(0, start_idx - 32) : start_idx]
        return sanitize_ipv4_match(m, prefix)

    text = RE_IPV4.sub(_ip_replacer, text)

    if tokenizer and tokenizer.term_to_token:
        sorted_terms = sorted(tokenizer.term_to_token.keys(), key=len, reverse=True)
        for term in sorted_terms:
            if term and term in text:
                if re.fullmatch(r"[A-Za-z0-9_]+", term):
                    text = re.sub(rf"\b{re.escape(term)}\b", tokenizer.term_to_token[term], text)
                else:
                    text = text.replace(term, tokenizer.term_to_token[term])

    return text

