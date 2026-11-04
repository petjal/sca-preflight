"""Deep Packet Inspection (DPI) and Build Execution Risk Guards.

Provides binary and archive inspection, PE version extraction, disaster smell
scanning, and pre-Detect build execution risk analysis (Jia Tan xz / Lazarus guard).
"""

from __future__ import annotations

import ast
import concurrent.futures
import gzip
import json
import os
import re
import tarfile
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any

from sca_preflight.catalog import (
    ARCHIVE_EXTENSIONS,
    BINARY_BANNER_BLOCKLIST,
    GENERIC_DIR_PREFIXES,
    KNOWN_NON_BINARY_EXTENSIONS,
    STANDARD_SAFE_EXCLUSIONS,
    _parse_c_version_header_bytes,
    _parse_cargo_toml_bytes,
    _parse_cmakelists_bytes,
    _parse_debian_control_bytes,
    _parse_nuspec_bytes,
    _parse_package_json_bytes,
    _parse_pkginfo_bytes,
    load_pareto_catalog,
    load_snippet_signatures,
    safe_parse_xml_bytes,
)

TRUSTED_WRAPPER_HOSTS: frozenset[str] = frozenset(
    {
        "services.gradle.org",
        "downloads.gradle.org",
        "repo.maven.apache.org",
        "apache.org",
        "maven.org",
        "github.com",
    }
)

MALICIOUS_SHELL_PATTERNS: tuple[str, ...] = (
    "curl ",
    "wget ",
    "nc ",
    "netcat",
    "/dev/tcp/",
    "base64",
    "eval ",
    "bash -c",
    "sh -c",
    "powershell",
    "Invoke-WebRequest",
    "Invoke-Expression",
    "node -e",
    "python -c",
    "python3 -c",
)

BENIGN_NPM_HOOK_PREFIXES: tuple[str, ...] = (
    "husky",
    "patch-package",
    "node-gyp",
    "npm run",
    "yarn run",
    "pnpm run",
    "tsc",
    "esbuild",
    "lerna",
    "corepack",
)

SUSPICIOUS_WRAPPER_PATTERNS: tuple[str, ...] = (
    "base64 -d",
    "eval ",
    "/dev/tcp/",
    "nc ",
    "bash -i",
    "python -c",
    "perl -e",
)


def extract_pe_version_strings(raw_bytes: bytes) -> dict[str, str]:
    """Extract ProductVersion and FileVersion strings from PE binary UTF-16LE resources."""
    results: dict[str, str] = {}
    for key in ("ProductVersion", "FileVersion"):
        key_bytes = key.encode("utf-16le")
        idx = 0
        while True:
            pos = raw_bytes.find(key_bytes, idx)
            if pos == -1:
                break
            idx = pos + len(key_bytes)
            cursor = idx
            while cursor + 1 < len(raw_bytes) and raw_bytes[cursor : cursor + 2] == b"\x00\x00":
                cursor += 2

            val_bytes = bytearray()
            while cursor + 1 < len(raw_bytes):
                unit = raw_bytes[cursor : cursor + 2]
                if unit == b"\x00\x00":
                    break
                val_bytes.extend(unit)
                cursor += 2
                if len(val_bytes) > 256:
                    break

            if val_bytes:
                try:
                    val_str = val_bytes.decode("utf-16le", errors="ignore").strip()
                    if val_str and any(c.isdigit() for c in val_str):
                        results[key] = val_str
                        break
                except Exception:  # noqa: BLE001
                    pass
    return results


def _is_archive(filename: str) -> bool:
    """Return True if filename matches known archive extensions."""
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)


HIGH_RISK_LICENSE_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    (
        "AGPL-3.0",
        "CRITICAL",
        r"(?:(?<!Use with the )(?<!under version 3 of the )GNU\s+AFFERO\s+GENERAL\s+PUBLIC\s+LICENSE|SPDX-License-Identifier:\s*AGPL-3\.0|\bAGPL-3\.0(?:-only|-or-later)?\b|\bAGPLv3\b)",
        "Network copyleft (AGPL-3.0) detected; embedding or modifying in commercial appliances/services triggers full source-code disclosure obligations.",
    ),
    (
        "SSPL-1.0",
        "CRITICAL",
        r"(?:SERVER\s+SIDE\s+PUBLIC\s+LICENSE|SPDX-License-Identifier:\s*SSPL-1\.0|\bSSPL-1\.0\b|\bSSPLv1\b)",
        "Server Side Public License (SSPL-1.0) detected; requires releasing complete management stack source code if offered as a service.",
    ),
    (
        "RSALv2",
        "CRITICAL",
        r"(?:REDIS\s+SOURCE\s+AVAILABLE\s+LICENSE|SPDX-License-Identifier:\s*RSAL-2\.0|\bRSALv2\b)",
        "Redis Source Available License (RSALv2) detected; restricts commercial distribution and managed service offerings.",
    ),
    (
        "Commons-Clause",
        "CRITICAL",
        r"(?:Commons\s+Clause\s+Restriction|SPDX-License-Identifier:\s*Commons-Clause|\bCommons-Clause\b)",
        "Commons Clause commercial restriction detected; prohibits selling products or services whose value derives substantially from the component.",
    ),
    (
        "BSL-1.1",
        "HIGH",
        r"(?:Business\s+Source\s+License\s+1\.1|SPDX-License-Identifier:\s*BUSL-1\.1|\bBUSL-1\.1\b)",
        "Business Source License (BSL-1.1 / BUSL-1.1) detected; non-open-source production usage restrictions apply prior to change date.",
    ),
    (
        "GPL-3.0",
        "HIGH",
        r"(?:GNU\s+GENERAL\s+PUBLIC\s+LICENSE\s*(?:\r?\n|\s)+Version\s+3|SPDX-License-Identifier:\s*GPL-3\.0(?:-only|-or-later)?\b)",
        "Strong reciprocal copyleft (GPL-3.0) with anti-tivoization (installation information) clauses detected.",
    ),
)


def _detect_high_risk_licenses_in_bytes(raw_bytes: bytes, loc_path: str) -> list[dict[str, str]]:
    """Scan raw text bytes from an archive member or source file for high-risk reciprocal/restricted licenses."""
    if not raw_bytes:
        return []
    text = raw_bytes[:32768].decode("utf-8", errors="ignore")
    header_text = text[:2048]
    findings: list[dict[str, str]] = []
    for lic_id, severity, pattern, summary in HIGH_RISK_LICENSE_PATTERNS:
        target_text = (
            header_text
            if lic_id in ("AGPL-3.0", "GPL-3.0") and not any(k in text for k in ("SPDX-License-Identifier", "<license", '"license"'))
            else text
        )
        if re.search(pattern, target_text, re.IGNORECASE):
            findings.append(
                {
                    "license_id": lic_id,
                    "severity": severity,
                    "location": loc_path,
                    "summary": summary,
                }
            )
    return findings


def _inspect_pack200_file(file_path: Path, rel_path: str, lower_name: str) -> dict[str, Any] | None:
    """Detect Pack200 (.pack / .pack.gz / 0xCAFED00D) archives and flag the commons-compress Java 6 (pack50 / majver 160) trap."""
    if not (lower_name.endswith((".pack", ".pack.gz")) or ".pack." in lower_name):
        return None
    try:
        if lower_name.endswith(".gz"):
            with gzip.open(file_path, "rb") as gf:
                head = gf.read(16)
        else:
            with open(file_path, "rb") as rf:
                head = rf.read(16)
        if len(head) >= 6 and head[:4] == b"\xca\xfe\xd0\x0d":
            minver = head[4]
            majver = head[5]
            if majver != 150:
                desc = (
                    f"PACK200_COMMONS_COMPRESS_TRAP: Pack200 archive '{rel_path}' has segment major version {majver} "
                    f"(minor {minver}; Java 6+ class version 50+ 'pack50' uses majver 160+). Since JDK 14 removed native "
                    f"java.util.jar.Pack200, Black Duck scan.cli's shaded Apache commons-compress falls back to Apache Harmony "
                    f"unpack200 (SegmentHeader.java:315), which hardcodes (version != 150) and throws Pack200Exception / uncaught "
                    f"java.lang.Error, silently dropping 100% of this packed JAR from the Black Duck BOM."
                )
            else:
                desc = (
                    f"PACK200_COMMONS_COMPRESS_TRAP: Pack200 archive '{rel_path}' (majver={majver}, minver={minver}) detected. "
                    f"Verify Black Duck scan.cli unpacks this archive cleanly under your JRE without throwing Apache Harmony unpack200 Errors."
                )
            return {
                "id": "PACK200_COMMONS_COMPRESS_TRAP",
                "name": f"Pack200 Archive Unpack Trap (majver={majver})",
                "severity": "HIGH" if majver != 150 else "MEDIUM",
                "location": rel_path,
                "archive_majver": majver,
                "archive_minver": minver,
                "description": desc,
                "detail": desc,
            }
    except Exception:  # noqa: BLE001
        pass
    return None


def _build_snippet_filename_index(
    snip_sigs: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Build O(1) lookup table mapping lowercase target filenames/classes to snippet signature rules."""
    idx: dict[str, list[dict[str, Any]]] = {}
    for sig in snip_sigs:
        for fn in sig.get("target_filenames") or []:
            fn_lower = str(fn).strip().lower()
            if fn_lower:
                idx.setdefault(fn_lower, []).append(sig)
    return idx


def _is_test_or_demo_path(rel_path: str) -> bool:
    """Return True if rel_path is inside a test, fixture, fuzz, or demo directory."""
    rel_lower = rel_path.lower().replace("\\", "/")
    rel_parts = rel_lower.split("/")
    return (
        any(
            p in (
                "test",
                "tests",
                "testsuite",
                "test-fixtures",
                "testdata",
                "fixture",
                "fixtures",
                "__fixtures__",
                "demos",
                "demo",
                "fuzz",
                "enos",
                "certdir",
                "examples",
                "example",
                "devenv",
                ".github",
            )
            or p.endswith(("-test", "-tests", "_test", "_tests", "-fixtures", "_fixtures"))
            for p in rel_parts[:-1]
        )
        or rel_parts[-1].endswith(
            ("_test.go", "test.java", "tests.java", ".test.js", ".spec.js", ".test.ts", ".spec.ts")
        )
        or rel_parts[-1].startswith("test_")
    )


def _inspect_single_file(
    f_info: tuple[Path, str, str, int],
    root: Path,
    cat_components: list[dict[str, Any]],
    cat_smells: list[dict[str, Any]],
    snip_by_filename: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Inspect a single candidate file for archive/binary/manifest metadata and disaster smells."""
    file_path, rel_path, name, size_bytes = f_info
    snip_index = snip_by_filename or {}

    assertions: list[dict[str, Any]] = []
    archive_metadata: list[dict[str, Any]] = []
    tarball_metadata: list[dict[str, Any]] = []
    binary_inspection: list[dict[str, Any]] = []
    disaster_smells: list[dict[str, Any]] = []
    internal_manifest_discoveries: list[dict[str, Any]] = []
    internal_license_discoveries: list[dict[str, str]] = []
    snippet_findings: list[dict[str, Any]] = []

    # Check Pack200 (.pack / .pack.gz / 0xCAFED00D) commons-compress trap
    pack200_smell = _inspect_pack200_file(file_path, rel_path, name.lower())
    if pack200_smell is not None:
        disaster_smells.append(pack200_smell)

    # Filename binary regex smells against filenames
    for smell in cat_smells:
        stype = str(smell.get("type") or "")
        if stype == "filename_binary_regex":
            pat = str(smell.get("pattern") or smell.get("filename_binary_regex") or "")
            if pat and (re.search(pat, name) or re.search(pat, rel_path)):
                disaster_smells.append(
                    {
                        "id": smell["id"],
                        "name": smell["name"],
                        "severity": smell.get("severity", "CRITICAL"),
                        "location": rel_path,
                        "description": smell.get("description", ""),
                    }
                )

    # Filename version assertion on files
    art_name: str | None = None
    art_ver: str | None = None
    src_type: str | None = None

    if name.endswith((".so", ".dylib", ".dll")) or ".so." in name:
        m_so = re.match(
            r"^(lib[a-zA-Z0-9_\-+]+)\.so\.(\d+\.\d+(?:\.[0-9a-zA-Z_.\-]+)*)$", name
        )
        if m_so:
            art_name = m_so.group(1)
            art_ver = m_so.group(2)
            src_type = "shared_library"
        else:
            base = name.rsplit(".", 1)[0]
            m_f = re.match(
                r"^([a-zA-Z0-9_.\-]+)[-_]v?(\d+\.\d+[0-9a-zA-Z_.\-]*)$", base
            )
            if m_f:
                art_name = m_f.group(1)
                art_ver = m_f.group(2)
                src_type = "shared_library"
    elif name.endswith(".whl"):
        whl_parts = name[:-4].split("-")
        if len(whl_parts) >= 2:
            art_name = whl_parts[0]
            art_ver = whl_parts[1]
            src_type = "archive"
    elif name.endswith((".jar", ".war", ".ear", ".zip", ".tar.gz", ".tgz")):
        if name.endswith(".tar.gz"):
            base = name[:-7]
        elif name.endswith(".tgz"):
            base = name[:-4]
        else:
            base = name.rsplit(".", 1)[0]

        m_f = re.match(r"^([a-zA-Z0-9_.\-]+)[-_]v?(\d+\.\d+[0-9a-zA-Z_.\-]*)$", base)
        if m_f:
            art_name = m_f.group(1)
            art_ver = m_f.group(2)
            src_type = "archive"

    assertion_record: dict[str, Any] | None = None
    if art_name and art_ver and src_type:
        assertion_record = {
            "artifact_name": art_name,
            "asserted_version": art_ver,
            "relative_path": rel_path,
            "source_type": src_type,
            "verified_by_internal_metadata": False,
        }
        assertions.append(assertion_record)

    # Inspect Zip/JAR archives
    is_zip = False
    lower_name = name.lower()
    if (
        any(lower_name.endswith(ext) for ext in (".jar", ".war", ".ear", ".zip", ".whl", ".nupkg"))
        and size_bytes < 500 * 1024 * 1024
    ):
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                is_zip = True
                namelist = z.namelist()[:10000]
                total_bytes_read = 0
                MAX_ARCHIVE_BYTES = 512 * 1024

                group_id: str | None = None
                artifact_id: str | None = None
                internal_ver: str | None = None
                manifest_attrs: dict[str, str] = {}
                nested_jars: list[dict[str, Any]] = []
                archive_smells: list[dict[str, Any]] = []
                maven_coordinates: list[dict[str, str]] = []
                candidate_member_smells: list[tuple[dict[str, Any], str]] = []
                candidate_snip_members: list[tuple[str, str, list[dict[str, Any]]]] = []

                def _read_member(m_name: str) -> bytes | None:
                    nonlocal total_bytes_read
                    budget = max(0, min(64 * 1024, MAX_ARCHIVE_BYTES - total_bytes_read))
                    if budget <= 0:
                        return None
                    try:
                        with z.open(m_name) as mf:
                            raw_b = mf.read(budget + 1)
                        if len(raw_b) <= budget:
                            total_bytes_read += len(raw_b)
                            return raw_b
                    except Exception:  # noqa: BLE001
                        pass
                    return None

                for member in namelist:
                    # Filename binary regex smells against archive member names
                    for smell in cat_smells:
                        stype = str(smell.get("type") or "")
                        if stype == "filename_binary_regex":
                            pat = str(
                                smell.get("pattern")
                                or smell.get("filename_binary_regex")
                                or ""
                            )
                            if pat and (
                                re.search(pat, member)
                                or re.search(pat, Path(member).name)
                            ):
                                loc = f"{rel_path}!/{member}"
                                sm_finding = {
                                    "id": smell["id"],
                                    "name": smell["name"],
                                    "severity": smell.get("severity", "CRITICAL"),
                                    "location": loc,
                                    "archive_path": rel_path,
                                    "member_name": member,
                                    "description": smell.get("description", ""),
                                }
                                archive_smells.append(sm_finding)
                                disaster_smells.append(sm_finding)

                    # Pom properties
                    if member.startswith("META-INF/maven/") and member.endswith(
                        "/pom.properties"
                    ):
                        raw_bytes = _read_member(member)
                        if raw_bytes is not None:
                            ptext = raw_bytes.decode("utf-8", errors="replace")
                            m_gid = ""
                            m_aid = ""
                            m_ver = ""
                            for line in ptext.splitlines():
                                s_line = line[:4096].strip()
                                if "=" in s_line and not s_line.startswith(("#", "!")):
                                    k, v = s_line.split("=", 1)
                                    k_s = k.strip()
                                    v_s = v.strip()
                                    if k_s == "groupId":
                                        m_gid = v_s
                                    elif k_s == "artifactId":
                                        m_aid = v_s
                                    elif k_s == "version":
                                        m_ver = v_s
                            if m_aid and m_ver:
                                maven_coordinates.append(
                                    {
                                        "groupId": m_gid,
                                        "artifactId": m_aid,
                                        "version": m_ver,
                                        "pom_properties_path": member,
                                    }
                                )
                                if not artifact_id:
                                    group_id = m_gid
                                    artifact_id = m_aid
                                    internal_ver = m_ver

                    # Pom.xml fallback
                    elif (
                        not artifact_id
                        and member.startswith("META-INF/maven/")
                        and member.endswith("/pom.xml")
                    ):
                        raw_bytes = _read_member(member)
                        if raw_bytes is not None:
                            try:
                                root_el = safe_parse_xml_bytes(raw_bytes)
                                if root_el is not None:
                                    def _find_text(tag: str, tree: Any = root_el) -> str | None:
                                        for el in tree.iter():
                                            if el.tag.split("}")[-1] == tag and el.text:
                                                return str(el.text).strip()
                                        return None

                                    p_aid = _find_text("artifactId")
                                    p_gid = _find_text("groupId")
                                    p_ver = _find_text("version")
                                    if p_aid and p_ver:
                                        artifact_id = p_aid
                                        group_id = p_gid or ""
                                        internal_ver = p_ver
                                        maven_coordinates.append(
                                            {
                                                "groupId": group_id,
                                                "artifactId": artifact_id,
                                                "version": internal_ver,
                                                "pom_properties_path": member,
                                            }
                                        )
                            except Exception:  # noqa: BLE001
                                pass

                    # MANIFEST.MF
                    elif member == "META-INF/MANIFEST.MF":
                        raw_bytes = _read_member(member)
                        if raw_bytes is not None:
                            mtext = raw_bytes.decode("utf-8", errors="replace")
                            for line in mtext.splitlines():
                                s_line = line[:4096].strip()
                                if ":" in s_line:
                                    k, v = s_line.split(":", 1)
                                    manifest_attrs[k.strip()] = v.strip()

                    # Nested JARs
                    elif member.endswith(".jar") and not member.endswith("/"):
                        m_nj = re.match(
                            r"^(?:.*?/)?([a-zA-Z0-9_.\-]+)[-_]v?(\d+\.\d+[0-9a-zA-Z_.\-]*)\.jar$",
                            member,
                        )
                        if m_nj:
                            nested_jars.append(
                                {
                                    "member_path": member,
                                    "artifact_name": m_nj.group(1),
                                    "asserted_version": m_nj.group(2),
                                }
                            )
                        else:
                            nested_jars.append(
                                {
                                    "member_path": member,
                                    "artifact_name": Path(member).stem,
                                    "asserted_version": "unversioned",
                                }
                            )

                    # Python wheel dist-info METADATA
                    elif member.endswith(".dist-info/METADATA"):
                        raw_bytes = _read_member(member)
                        if raw_bytes is not None:
                            wtext = raw_bytes.decode("utf-8", errors="replace")
                            for line in wtext.splitlines():
                                if line.startswith("Name:"):
                                    artifact_id = line.split(":", 1)[1].strip()
                                elif line.startswith("Version:"):
                                    internal_ver = line.split(":", 1)[1].strip()

                    # Internal manifests inside archive (.nuspec, package.json, Cargo.toml)
                    elif member.endswith(".nuspec"):
                        raw_bytes = _read_member(member)
                        if raw_bytes is not None:
                            n_id, n_ver = _parse_nuspec_bytes(raw_bytes)
                            if n_id and n_ver:
                                internal_manifest_discoveries.append(
                                    {
                                        "component": n_id,
                                        "version": n_ver,
                                        "source_type": "nuspec",
                                        "path": f"{rel_path}!/{member}",
                                    }
                                )
                    elif member.endswith("package.json") and not member.endswith("/"):
                        raw_bytes = _read_member(member)
                        if raw_bytes is not None:
                            pj_id, pj_ver = _parse_package_json_bytes(raw_bytes)
                            if pj_id and pj_ver:
                                internal_manifest_discoveries.append(
                                    {
                                        "component": pj_id,
                                        "version": pj_ver,
                                        "source_type": "package_json",
                                        "path": f"{rel_path}!/{member}",
                                    }
                                )
                    elif member.endswith("Cargo.toml"):
                        raw_bytes = _read_member(member)
                        if raw_bytes is not None:
                            cg_id, cg_ver = _parse_cargo_toml_bytes(raw_bytes)
                            if cg_id and cg_ver:
                                internal_manifest_discoveries.append(
                                    {
                                        "component": cg_id,
                                        "version": cg_ver,
                                        "source_type": "cargo_toml",
                                        "path": f"{rel_path}!/{member}",
                                    }
                                )

                    # Check LICENSE / COPYING / metadata inside ZIP archives for high-risk licenses
                    m_base = Path(member).name.upper()
                    if not member.endswith("/") and (
                        m_base.startswith(("LICENSE", "COPYING"))
                        or m_base in ("METADATA", "PKG-INFO")
                        or member.endswith((".nuspec", "pom.xml", "package.json"))
                    ):
                        lic_bytes = _read_member(member)
                        if lic_bytes is not None:
                            internal_license_discoveries.extend(
                                _detect_high_risk_licenses_in_bytes(lic_bytes, f"{rel_path}!/{member}")
                            )

                    # Unpatched code snippet & shaded-bytecode check (O(1) by member filename)
                    m_fname_lower = Path(member).name.lower()
                    if not member.endswith("/") and m_fname_lower in snip_index:
                        snip_bytes = _read_member(member)
                        if snip_bytes is not None:
                            snip_text = snip_bytes.decode("latin-1", errors="ignore")
                            candidate_snip_members.append((member, snip_text, snip_index[m_fname_lower]))

                    # Member suffix or regex disaster smells
                    for smell in cat_smells:
                        stype = str(smell.get("type") or "")
                        pat = str(
                            smell.get("pattern")
                            or smell.get("archive_member_suffix")
                            or ""
                        )
                        re_pat = str(smell.get("archive_member_regex") or "")
                        if (
                            ((stype == "archive_member_suffix" or smell.get("archive_member_suffix")) and pat and member.endswith(pat))
                            or (re_pat and re.search(re_pat, member))
                        ):
                            candidate_member_smells.append((smell, member))

                # Manifest version extraction
                if not internal_ver:
                    for v_key in (
                        "Implementation-Version",
                        "Bundle-Version",
                        "Specification-Version",
                    ):
                        if v_key in manifest_attrs and manifest_attrs[v_key]:
                            internal_ver = manifest_attrs[v_key]
                            break
                if not artifact_id:
                    for a_key in ("Bundle-SymbolicName", "Implementation-Title"):
                        if a_key in manifest_attrs and manifest_attrs[a_key]:
                            artifact_id = manifest_attrs[a_key].split(";")[0].strip()
                            break

                # Evaluate snippet and shaded-bytecode rules on matched archive members
                patched_snip_cves_in_archive: set[str] = set()
                for member, snip_text, m_rules in candidate_snip_members:
                    for rule in m_rules:
                        anchor_re = str(rule.get("vulnerable_anchor_regex") or "")
                        guard_re = str(rule.get("patch_guard_regex") or "")
                        if anchor_re and re.search(anchor_re, snip_text):
                            has_guard = bool(guard_re and re.search(guard_re, snip_text))
                            status = "PATCH_GUARD_PRESENT" if has_guard else "UNPATCHED_SNIPPET"
                            if has_guard:
                                patched_snip_cves_in_archive.add(str(rule.get("cve_id", "")))
                            src_type_snip = "bytecode_pattern" if member.endswith(".class") else "code_snippet"
                            snippet_findings.append(
                                {
                                    "rule_id": str(rule["rule_id"]),
                                    "cve_id": str(rule["cve_id"]),
                                    "component": str(rule["component"]),
                                    "ecosystem": str(rule.get("ecosystem", "")),
                                    "cvss": float(rule.get("cvss", 0.0)),
                                    "cisa_kev": bool(rule.get("cisa_kev", False)),
                                    "cwe": str(rule.get("cwe", "CWE-Unknown")),
                                    "published_date": str(rule.get("published_date", "")),
                                    "pre_nvd": bool(rule.get("pre_nvd", False)),
                                    "fixed_in_version": str(rule.get("fixed_in_version", "latest")),
                                    "target_type": str(rule.get("target_type", "bytecode_class")),
                                    "source_type": src_type_snip,
                                    "status": status,
                                    "location": f"{rel_path}!/{member}",
                                    "archive_path": rel_path,
                                    "has_archive_coordinates": bool(maven_coordinates or internal_ver or art_ver),
                                    "actionable_remedy": str(rule.get("actionable_remedy", "")),
                                }
                            )
                if patched_snip_cves_in_archive:
                    for snip_item in snippet_findings:
                        if (
                            snip_item.get("archive_path") == rel_path
                            and snip_item.get("cve_id") in patched_snip_cves_in_archive
                        ):
                            snip_item["status"] = "PATCH_GUARD_PRESENT"

                # Evaluate member suffix smells against verified or filename version
                for smell, member in candidate_member_smells:
                    vuln_re = smell.get("vulnerable_version_regex")
                    cand_ver: str | None = None
                    s_meta = f"{smell.get('id', '')} {smell.get('name', '')} {member}".lower()
                    if maven_coordinates:
                        for c in maven_coordinates:
                            c_aid = c.get("artifactId", "").lower()
                            if (
                                ("log4j" in s_meta and "log4j" in c_aid)
                                or (("text" in s_meta or "stringlookup" in s_meta) and "text" in c_aid)
                                or ("spring" in s_meta and "spring" in c_aid)
                                or ("postgresql" in s_meta and "postgresql" in c_aid)
                            ):
                                cand_ver = c.get("version")
                                break
                    if not cand_ver:
                        outer_id = f"{rel_path} {artifact_id or ''}".lower()
                        if (
                            ("log4j" in s_meta and "log4j" in outer_id)
                            or (("text" in s_meta or "stringlookup" in s_meta) and "text" in outer_id)
                            or ("spring" in s_meta and "spring" in outer_id)
                            or ("postgresql" in s_meta and "postgresql" in outer_id)
                        ):
                            cand_ver = internal_ver or art_ver

                    is_vuln = True
                    if vuln_re and cand_ver:
                        is_vuln = bool(re.search(vuln_re, cand_ver))
                    elif not cand_ver and str(smell.get("id", "")) in patched_snip_cves_in_archive:
                        is_vuln = False
                    if is_vuln:
                        loc = f"{rel_path}!/{member}"
                        sm_finding = {
                            "id": smell["id"],
                            "name": smell["name"],
                            "severity": smell.get("severity", "CRITICAL"),
                            "location": loc,
                            "archive_path": rel_path,
                            "member_name": member,
                            "verified_version": cand_ver,
                            "description": smell.get("description", ""),
                        }
                        archive_smells.append(sm_finding)
                        disaster_smells.append(sm_finding)

                # Verify filename version assertion
                if assertion_record and internal_ver and art_ver and internal_ver == art_ver:
                    assertion_record["verified_by_internal_metadata"] = True

                archive_metadata.append(
                    {
                        "path": rel_path,
                        "group_id": group_id,
                        "artifact_id": artifact_id,
                        "version": internal_ver,
                        "manifest_attributes": manifest_attrs,
                        "nested_jar_count": len(nested_jars),
                        "nested_jars": nested_jars,
                        "maven_coordinates": maven_coordinates,
                        "disaster_smells": archive_smells,
                    }
                )
        except (zipfile.BadZipFile, OSError, KeyError, ValueError):
            pass

    # Inspect Tarballs
    is_tar = False
    if (
        not is_zip
        and any(lower_name.endswith(ext) for ext in (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"))
        and size_bytes < 500 * 1024 * 1024
    ):
        try:
            with tarfile.open(file_path, "r:*") as t:
                is_tar = True
                t_members: list[str] = []
                tar_lic_checked = 0
                for count, ti in enumerate(t, start=1):
                    t_members.append(ti.name)
                    ti_base = Path(ti.name).name.upper()
                    if (
                        tar_lic_checked < 4
                        and ti.isfile()
                        and 0 < ti.size <= 128 * 1024
                        and (
                            ti_base.startswith(("LICENSE", "COPYING"))
                            or ti_base in ("PKG-INFO", "PACKAGE.JSON")
                        )
                    ):
                        try:
                            f_obj = t.extractfile(ti)
                            if f_obj is not None:
                                t_bytes = f_obj.read(32768)
                                tar_lic_checked += 1
                                internal_license_discoveries.extend(
                                    _detect_high_risk_licenses_in_bytes(t_bytes, f"{rel_path}!/{ti.name}")
                                )
                        except Exception:  # noqa: BLE001
                            pass
                    if count >= 100:
                        break

                top_prefix: dict[str, str] | None = None
                if t_members:
                    first = t_members[0].split("/")[0]
                    m_p = re.match(
                        r"^([a-zA-Z0-9_.\-]+)[-_]v?(\d+\.\d+[0-9a-zA-Z_.\-]*)$", first
                    )
                    if m_p:
                        top_prefix = {"name": m_p.group(1), "version": m_p.group(2)}
                        if assertion_record and art_ver and m_p.group(2) == art_ver:
                            assertion_record["verified_by_internal_metadata"] = True

                tarball_metadata.append(
                    {
                        "path": rel_path,
                        "members_peeked": len(t_members),
                        "top_level_prefix": top_prefix,
                    }
                )
        except Exception:  # noqa: BLE001
            pass

    # Inspect Binaries (ELF / PE / Mach-O / Shared Libs)
    is_binary = False
    bin_format: str | None = None
    ext = file_path.suffix.lower()
    is_archive_or_tarball = is_zip or is_tar or _is_archive(name)

    if ext not in KNOWN_NON_BINARY_EXTENSIONS and not is_archive_or_tarball:
        try:
            with open(file_path, "rb") as bf:
                header = bf.read(16)
                if header.startswith(b"\x7fELF"):
                    is_binary = True
                    bin_format = "ELF"
                elif header.startswith(b"MZ"):
                    is_binary = True
                    bin_format = "PE"
                elif header[:4] in (
                    b"\xfe\xed\xfa\xce",
                    b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe",
                    b"\xcf\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe",
                ):
                    is_binary = True
                    bin_format = "Mach-O"
                elif name.endswith((".so", ".dylib", ".dll")) or ".so." in name:
                    is_binary = True
                    bin_format = "SHARED_LIB"
        except OSError:
            pass

    if is_binary:
        try:
            read_len = min(size_bytes, 2 * 1024 * 1024)
            with open(file_path, "rb") as bf:
                raw_bytes = bf.read(read_len)
            str_list = [
                s.decode("ascii", errors="ignore")[:4096]
                for s in re.findall(rb"[\x20-\x7e\t]{5,}", raw_bytes)
            ]
            full_text = "\n".join(str_list)

            sonames = sorted(
                set(
                    re.findall(
                        r"\b(lib[a-zA-Z0-9_+-]+\.so(?:\.\d+)*|[a-zA-Z0-9_+-]+\.dll)\b",
                        full_text,
                    )
                )
            )
            go_matches = re.findall(
                r"\bdep\t([a-zA-Z0-9._/\-]+)\t(v\d+\.\d+\.\d+[^\s\x00]*)",
                full_text,
            )
            go_deps = [{"module": gm[0], "version": gm[1]} for gm in go_matches]

            cat_ver_matches: list[dict[str, str]] = []
            for comp in cat_components:
                r_ver = comp.get("binary_version_regex")
                if r_ver:
                    m_bver = re.search(r_ver, full_text)
                    if m_bver:
                        c_v = next(
                            (g for g in m_bver.groups() if g is not None), ""
                        )
                        cat_ver_matches.append(
                            {
                                "component": comp["name"],
                                "version": c_v,
                                "matched_string": m_bver.group(0),
                            }
                        )

            # ELF symbol version extraction
            raw_syms = re.findall(
                r"\b(OPENSSL|GLIBC|GLIBCXX|ZLIB|CURL_OPENSSL|LIBXML2)_(\d+\.\d+(?:\.\d+)?)\b",
                full_text,
            )
            symbol_versions: list[dict[str, str]] = [
                {"symbol": f"{s[0]}_{s[1]}", "library": s[0], "version": s[1]}
                for s in sorted(set(raw_syms))
            ]

            # Rust crate extraction
            raw_crates = re.findall(
                r"cargo/registry/src/[^/]+/([a-zA-Z0-9_-]+)-(\d+\.\d+\.\d+[a-zA-Z0-9._-]*)",
                full_text,
            )
            rust_crates: list[dict[str, str]] = [
                {"crate": c[0], "name": c[0], "version": c[1]}
                for c in sorted(set(raw_crates))
            ]

            # PE UTF-16LE ProductVersion and FileVersion extraction
            pe_versions: dict[str, str] = {}
            if bin_format == "PE" or raw_bytes.startswith(b"MZ"):
                pe_versions = extract_pe_version_strings(raw_bytes)

            # Generic binary banners (Unknowns mode)
            raw_banners = re.findall(
                r"\b([A-Za-z][A-Za-z0-9_.\-]{2,24})/(\d+\.\d+\.\d+[a-zA-Z0-9._\-]*)\b",
                full_text,
            )
            generic_binary_banners: list[dict[str, str]] = [
                {"component": b[0], "version": b[1], "banner": f"{b[0]}/{b[1]}"}
                for b in sorted(set(raw_banners))
                if b[0].lower() not in BINARY_BANNER_BLOCKLIST
            ]

            bin_smells: list[dict[str, Any]] = []
            for smell in cat_smells:
                pat = str(
                    smell.get("pattern")
                    or smell.get("filename_binary_regex")
                    or smell.get("binary_source_regex")
                    or ""
                )
                stype = str(smell.get("type") or "")
                if (
                    stype in ("filename_binary_regex", "binary_source_regex")
                    and pat
                ):
                    m_bs = re.search(pat, full_text) or re.search(pat, name)
                    if m_bs:
                        f_sm = {
                            "id": smell["id"],
                            "name": smell["name"],
                            "severity": smell.get("severity", "CRITICAL"),
                            "location": rel_path,
                            "description": smell.get("description", ""),
                        }
                        bin_smells.append(f_sm)
                        disaster_smells.append(f_sm)

            # Check if internal binary metadata verifies assertion
            if assertion_record and art_ver:
                if pe_versions.get("ProductVersion") == art_ver or pe_versions.get("FileVersion") == art_ver:
                    assertion_record["verified_by_internal_metadata"] = True
                elif art_name:
                    for rc in rust_crates:
                        if rc["name"].lower() == art_name.lower() and rc["version"] == art_ver:
                            assertion_record["verified_by_internal_metadata"] = True
                            break
                    for sym in symbol_versions:
                        if sym["library"].lower() in art_name.lower() and sym["version"].startswith(art_ver):
                            assertion_record["verified_by_internal_metadata"] = True
                            break

            binary_inspection.append(
                {
                    "path": rel_path,
                    "format": bin_format,
                    "sonames": sonames,
                    "go_dependencies": go_deps,
                    "catalog_version_matches": cat_ver_matches,
                    "disaster_smells": bin_smells,
                    "symbol_versions": symbol_versions,
                    "rust_crates": rust_crates,
                    "pe_version_info": pe_versions,
                    "product_version": pe_versions.get("ProductVersion"),
                    "file_version": pe_versions.get("FileVersion"),
                    "generic_binary_banners": generic_binary_banners,
                }
            )
        except Exception:  # noqa: BLE001
            pass

    # Inspect source / config files for private keys, EOL OpenSSL, and embedded manifests
    if (
        name.endswith(
            (
                ".c",
                ".h",
                ".cpp",
                ".cc",
                ".hpp",
                ".py",
                ".java",
                ".go",
                ".rs",
                ".js",
                ".ts",
                ".php",
                ".sh",
                ".pem",
                ".key",
                ".conf",
                ".yml",
                ".yaml",
                ".xml",
                ".json",
                ".nuspec",
            )
        )
        or name in ("CMakeLists.txt", "VERSION.dat", "Cargo.toml", ".PKGINFO", "control")
        or name.upper() in ("LICENSE", "LICENSE.TXT", "LICENSE.MD", "COPYING", "COPYING.TXT", "NOTICE", "NOTICE.TXT")
    ) and size_bytes < 1024 * 1024:
        try:
            raw_file_bytes = file_path.read_bytes()
            stext = raw_file_bytes.decode("utf-8", errors="replace")

            # Unpatched code snippet inspection (O(1) by filename)
            if lower_name in snip_index and not _is_test_or_demo_path(rel_path):
                for rule in snip_index[lower_name]:
                    anchor_re = str(rule.get("vulnerable_anchor_regex") or "")
                    guard_re = str(rule.get("patch_guard_regex") or "")
                    if anchor_re and re.search(anchor_re, stext):
                        has_guard = bool(guard_re and re.search(guard_re, stext))
                        status = "PATCH_GUARD_PRESENT" if has_guard else "UNPATCHED_SNIPPET"
                        snippet_findings.append(
                            {
                                "rule_id": str(rule["rule_id"]),
                                "cve_id": str(rule["cve_id"]),
                                "component": str(rule["component"]),
                                "ecosystem": str(rule.get("ecosystem", "")),
                                "cvss": float(rule.get("cvss", 0.0)),
                                "cisa_kev": bool(rule.get("cisa_kev", False)),
                                "cwe": str(rule.get("cwe", "CWE-Unknown")),
                                "published_date": str(rule.get("published_date", "")),
                                "pre_nvd": bool(rule.get("pre_nvd", False)),
                                "fixed_in_version": str(rule.get("fixed_in_version", "latest")),
                                "target_type": str(rule.get("target_type", "source_snippet")),
                                "source_type": "code_snippet",
                                "status": status,
                                "location": rel_path,
                                "archive_path": "",
                                "has_archive_coordinates": False,
                                "actionable_remedy": str(rule.get("actionable_remedy", "")),
                            }
                        )

            # Source content disaster smells
            for smell in cat_smells:
                stype = str(smell.get("type") or "")
                if stype in ("source_content_regex", "binary_source_regex"):
                    pat = str(
                        smell.get("pattern")
                        or smell.get("source_content_regex")
                        or smell.get("binary_source_regex")
                        or ""
                    )
                    if pat:
                        m_sm = re.search(pat, stext)
                        if m_sm:
                            smell_id = str(smell["id"])
                            rel_lower = rel_path.lower().replace("\\", "/")
                            rel_parts = rel_lower.split("/")
                            is_test_fixture = (
                                any(
                                    p in (
                                        "test",
                                        "tests",
                                        "testsuite",
                                        "test-fixtures",
                                        "testdata",
                                        "fixture",
                                        "fixtures",
                                        "__fixtures__",
                                        "demos",
                                        "demo",
                                        "fuzz",
                                        "enos",
                                        "certdir",
                                        "examples",
                                        "example",
                                        "devenv",
                                        ".github",
                                    )
                                    or p.endswith(("-test", "-tests", "_test", "_tests", "-fixtures", "_fixtures"))
                                    for p in rel_parts[:-1]
                                )
                                or (len(rel_parts) == 2 and rel_parts[0] == "apps" and rel_parts[1].endswith(".pem"))
                                or rel_parts[-1].endswith(
                                    ("_test.go", "test.java", "tests.java", ".test.js", ".spec.js", ".test.ts", ".spec.ts")
                                )
                                or "test" in rel_parts[-1]
                            )
                            is_secret = (
                                smell_id == "EMBEDDED_PRIVATE_KEY_HEADER"
                                or "secret" in smell_id.lower()
                                or "key" in smell_id.lower()
                            )
                            if is_secret:
                                if is_test_fixture:
                                    continue
                                if smell_id == "EMBEDDED_PRIVATE_KEY_HEADER":
                                    line_start = stext.rfind("\n", 0, m_sm.start()) + 1
                                    line_prefix = stext[line_start : m_sm.start()]
                                    if '"' in line_prefix or "'" in line_prefix:
                                        # Quoted string literal (e.g. PemUtils.java / parser constants).
                                        # Check if there is an unquoted match elsewhere in the file.
                                        unquoted_match = None
                                        for m_cand in re.finditer(pat, stext):
                                            ls = stext.rfind("\n", 0, m_cand.start()) + 1
                                            lp = stext[ls : m_cand.start()]
                                            if '"' not in lp and "'" not in lp:
                                                unquoted_match = m_cand
                                                break
                                        if unquoted_match is not None:
                                            m_sm = unquoted_match
                                        else:
                                            continue
                                desc = smell.get(
                                    "description",
                                    "Embedded private key header detected in source file.",
                                )
                            elif m_sm.group(0) and "OPENSSL" in smell_id:
                                if is_test_fixture:
                                    continue
                                desc = f"Legacy OpenSSL detected: {m_sm.group(0)}"
                            else:
                                desc = smell.get("description", "")

                            disaster_smells.append(
                                {
                                    "id": smell_id,
                                    "name": smell["name"],
                                    "severity": smell.get("severity", "HIGH"),
                                    "location": rel_path,
                                    "description": desc,
                                }
                            )

            # Discover manifests in source files
            if name == "CMakeLists.txt":
                cm_name, cm_ver = _parse_cmakelists_bytes(raw_file_bytes)
                if cm_name and cm_ver:
                    internal_manifest_discoveries.append(
                        {
                            "component": cm_name,
                            "version": cm_ver,
                            "source_type": "cmakelists",
                            "path": rel_path,
                        }
                    )
            elif name == "VERSION.dat" and "SHLIB_VERSION=" in stext and "MAJOR=" in stext:
                m_maj = re.search(r"^MAJOR=(\d+)", stext, re.MULTILINE)
                m_min = re.search(r"^MINOR=(\d+)", stext, re.MULTILINE)
                m_pat = re.search(r"^PATCH=(\d+)", stext, re.MULTILINE)
                if m_maj and m_min and m_pat:
                    internal_manifest_discoveries.append(
                        {
                            "component": "openssl",
                            "version": f"{m_maj.group(1)}.{m_min.group(1)}.{m_pat.group(1)}",
                            "source_type": "version_dat",
                            "path": rel_path,
                        }
                    )
            elif name.lower().endswith(".h") and (
                "version" in name.lower()
                or "ver" in name.lower()
                or "_VERSION" in stext
            ):
                ch_name, ch_ver = _parse_c_version_header_bytes(raw_file_bytes)
                if ch_name and ch_ver:
                    internal_manifest_discoveries.append(
                        {
                            "component": ch_name,
                            "version": ch_ver,
                            "source_type": "c_header",
                            "path": rel_path,
                        }
                    )
            elif name.endswith(".nuspec"):
                nu_id, nu_ver = _parse_nuspec_bytes(raw_file_bytes)
                if nu_id and nu_ver:
                    internal_manifest_discoveries.append(
                        {
                            "component": nu_id,
                            "version": nu_ver,
                            "source_type": "nuspec",
                            "path": rel_path,
                        }
                    )
            elif name == ".PKGINFO":
                pkg_name, pkg_ver = _parse_pkginfo_bytes(raw_file_bytes)
                if pkg_name and pkg_ver:
                    internal_manifest_discoveries.append(
                        {
                            "component": pkg_name,
                            "version": pkg_ver,
                            "source_type": "pkginfo",
                            "path": rel_path,
                        }
                    )
            elif name == "control" and (rel_path.endswith("DEBIAN/control") or rel_path.endswith("debian/control")):
                deb_pkg, deb_ver = _parse_debian_control_bytes(raw_file_bytes)
                if deb_pkg and deb_ver:
                    internal_manifest_discoveries.append(
                        {
                            "component": deb_pkg,
                            "version": deb_ver,
                            "source_type": "debian_control",
                            "path": rel_path,
                        }
                    )
            elif name == "Cargo.toml":
                cg_name, cg_ver = _parse_cargo_toml_bytes(raw_file_bytes)
                if cg_name and cg_ver:
                    internal_manifest_discoveries.append(
                        {
                            "component": cg_name,
                            "version": cg_ver,
                            "source_type": "cargo_toml",
                            "path": rel_path,
                        }
                    )
            elif name == "package.json":
                p_name, p_ver = _parse_package_json_bytes(raw_file_bytes)
                if p_name and p_ver:
                    internal_manifest_discoveries.append(
                        {
                            "component": p_name,
                            "version": p_ver,
                            "source_type": "package_json",
                            "path": rel_path,
                        }
                    )

            # Scan source/header/config files for SPDX / reciprocal license markers
            internal_license_discoveries.extend(
                _detect_high_risk_licenses_in_bytes(raw_file_bytes, rel_path)
            )
        except Exception:  # noqa: BLE001
            pass

    return {
        "assertions": assertions,
        "archive_metadata": archive_metadata,
        "tarball_metadata": tarball_metadata,
        "binary_inspection": binary_inspection,
        "disaster_smells": disaster_smells,
        "internal_manifest_discoveries": internal_manifest_discoveries,
        "internal_license_discoveries": internal_license_discoveries,
        "snippet_findings": snippet_findings,
    }


def inspect_archives_and_binaries(
    workspace_root: str | Path,
    catalog: dict[str, Any] | None = None,
    max_depth: int = 12,
    max_workers: int | None = None,
) -> dict[str, Any]:
    """Inspect archives, directories, and compiled binaries for ground-truth versions and disaster smells."""
    root = Path(workspace_root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Workspace directory not found: {root}")

    if catalog is None:
        catalog = load_pareto_catalog()

    filename_version_assertions: list[dict[str, Any]] = []
    archive_metadata: list[dict[str, Any]] = []
    tarball_metadata: list[dict[str, Any]] = []
    binary_inspection: list[dict[str, Any]] = []
    disaster_smells: list[dict[str, Any]] = []
    internal_manifest_discoveries: list[dict[str, Any]] = []
    internal_license_discoveries: list[dict[str, str]] = []
    snippet_findings: list[dict[str, Any]] = []

    cat_components: list[dict[str, Any]] = catalog.get("components", [])
    cat_smells: list[dict[str, Any]] = catalog.get("disaster_smells", [])
    snip_sigs = list(load_snippet_signatures())
    if "snippet_signatures" in catalog and isinstance(catalog["snippet_signatures"], list):
        snip_sigs.extend(catalog["snippet_signatures"])
    snip_by_filename = _build_snippet_filename_index(snip_sigs)

    dir_assertions: dict[str, dict[str, Any]] = {}
    candidate_files: list[tuple[Path, str, str, int]] = []

    stack: list[tuple[Path, int]] = [(root, 0)]
    visited_inodes: set[tuple[int, int]] = set()
    root_stat = root.stat()
    visited_inodes.add((root_stat.st_dev, root_stat.st_ino))

    while stack:
        current_dir, depth = stack.pop()
        try:
            entries = list(os.scandir(current_dir))
        except OSError:
            continue

        for entry in entries:
            try:
                name = entry.name
                entry_stat = entry.stat(follow_symlinks=False)
                inode_key = (entry_stat.st_dev, entry_stat.st_ino)

                if entry.is_dir(follow_symlinks=False):
                    if name in STANDARD_SAFE_EXCLUSIONS or name == "node_modules":
                        continue

                    rel_dir = str(Path(entry.path).relative_to(root))

                    # Filename binary regex smells against directory names
                    for smell in cat_smells:
                        stype = str(smell.get("type") or "")
                        if stype == "filename_binary_regex":
                            pat = str(
                                smell.get("pattern")
                                or smell.get("filename_binary_regex")
                                or ""
                            )
                            if pat and (re.search(pat, name) or re.search(pat, rel_dir)):
                                disaster_smells.append(
                                    {
                                        "id": smell["id"],
                                        "name": smell["name"],
                                        "severity": smell.get("severity", "CRITICAL"),
                                        "location": rel_dir,
                                        "description": smell.get("description", ""),
                                    }
                                )

                    # Directory version assertion check
                    m_dir = re.match(
                        r"^([a-zA-Z0-9_.\-]+)[-_]v?(\d+\.\d+[0-9a-zA-Z_.\-]*)$", name
                    )
                    if m_dir:
                        art_name = m_dir.group(1)
                        art_ver = m_dir.group(2)
                        if art_name.lower() not in GENERIC_DIR_PREFIXES:
                            assertion_rec = {
                                "artifact_name": art_name,
                                "asserted_version": art_ver,
                                "relative_path": rel_dir,
                                "source_type": "directory",
                                "verified_by_internal_metadata": False,
                            }
                            dir_assertions[rel_dir] = assertion_rec
                            filename_version_assertions.append(assertion_rec)

                    if depth < max_depth and inode_key not in visited_inodes:
                        visited_inodes.add(inode_key)
                        stack.append((Path(entry.path), depth + 1))

                elif entry.is_file(follow_symlinks=False):
                    rel_path = str(Path(entry.path).relative_to(root))
                    size_bytes = entry_stat.st_size
                    candidate_files.append((Path(entry.path), rel_path, name, size_bytes))
            except OSError:
                continue

    workers = min(8, (os.cpu_count() or 4)) if max_workers is None else max(1, max_workers)

    if candidate_files:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(
                    _inspect_single_file,
                    f_info,
                    root,
                    cat_components,
                    cat_smells,
                    snip_by_filename,
                )
                for f_info in candidate_files
            ]
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                filename_version_assertions.extend(res["assertions"])
                archive_metadata.extend(res["archive_metadata"])
                tarball_metadata.extend(res["tarball_metadata"])
                binary_inspection.extend(res["binary_inspection"])
                disaster_smells.extend(res["disaster_smells"])
                internal_manifest_discoveries.extend(res["internal_manifest_discoveries"])
                internal_license_discoveries.extend(res.get("internal_license_discoveries", []))
                snippet_findings.extend(res.get("snippet_findings", []))

    # Cross-verify directory assertions against discovered internal manifests
    for disc in internal_manifest_discoveries:
        disc_path = disc.get("path", "")
        disc_ver = disc.get("version", "")
        for rel_dir, dir_assertion in dir_assertions.items():
            if (disc_path.startswith(rel_dir + "/") or disc_path.startswith(rel_dir + "!/")) and (
                disc_ver == dir_assertion.get("asserted_version")
            ):
                dir_assertion["verified_by_internal_metadata"] = True

    # Deduplicate assertions
    dedup_assertions: list[dict[str, Any]] = []
    seen_assertions: set[tuple[str, str, str]] = set()
    for a in filename_version_assertions:
        a_key = (
            str(a.get("artifact_name", "")).lower(),
            str(a.get("asserted_version", "")),
            str(a.get("relative_path", "")),
        )
        if a_key not in seen_assertions:
            seen_assertions.add(a_key)
            dedup_assertions.append(a)

    # Deduplicate disaster smells
    dedup_smells: list[dict[str, Any]] = []
    seen_smells: set[tuple[str, str]] = set()
    for s in disaster_smells:
        s_key = (str(s.get("id", "")), str(s.get("location", "")))
        if s_key not in seen_smells:
            seen_smells.add(s_key)
            dedup_smells.append(s)

    # Deduplicate internal manifest discoveries
    dedup_imd: list[dict[str, Any]] = []
    seen_imd: set[tuple[str, str, str]] = set()
    for imd in internal_manifest_discoveries:
        imd_key = (
            str(imd.get("component", "")).lower(),
            str(imd.get("version", "")),
            str(imd.get("path", "")),
        )
        if imd_key not in seen_imd:
            seen_imd.add(imd_key)
            dedup_imd.append(imd)

    # Deduplicate internal license discoveries
    dedup_lic: list[dict[str, str]] = []
    seen_lic: set[tuple[str, str]] = set()
    for lic in internal_license_discoveries:
        l_key = (str(lic.get("license_id", "")), str(lic.get("location", "")))
        if l_key not in seen_lic:
            seen_lic.add(l_key)
            dedup_lic.append(lic)

    # Deduplicate snippet findings
    dedup_snip: list[dict[str, Any]] = []
    seen_snip: set[tuple[str, str, str]] = set()
    for snip in snippet_findings:
        snip_key = (
            str(snip.get("rule_id", "")),
            str(snip.get("location", "")),
            str(snip.get("status", "")),
        )
        if snip_key not in seen_snip:
            seen_snip.add(snip_key)
            dedup_snip.append(snip)

    # Sort all resulting lists deterministically
    dedup_assertions.sort(
        key=lambda x: (
            str(x.get("relative_path", "")),
            str(x.get("artifact_name", "")),
            str(x.get("asserted_version", "")),
        )
    )
    archive_metadata.sort(key=lambda x: str(x.get("path", "")))
    tarball_metadata.sort(key=lambda x: str(x.get("path", "")))
    binary_inspection.sort(key=lambda x: str(x.get("path", "")))
    dedup_smells.sort(
        key=lambda x: (str(x.get("location", "")), str(x.get("id", "")))
    )
    dedup_imd.sort(
        key=lambda x: (str(x.get("path", "")), str(x.get("component", "")))
    )
    dedup_lic.sort(
        key=lambda x: (str(x.get("location", "")), str(x.get("license_id", "")))
    )
    dedup_snip.sort(
        key=lambda x: (
            str(x.get("cve_id", "")),
            str(x.get("location", "")),
            str(x.get("rule_id", "")),
        )
    )

    return {
        "filename_version_assertions": dedup_assertions,
        "archive_metadata": archive_metadata,
        "tarball_metadata": tarball_metadata,
        "binary_inspection": binary_inspection,
        "disaster_smells": dedup_smells,
        "internal_manifest_discoveries": dedup_imd,
        "internal_license_discoveries": dedup_lic,
        "snippet_findings": dedup_snip,
    }


def inspect_build_execution_risks(
    workspace_root: str | Path,
    max_depth: int = 12,
) -> dict[str, Any]:
    """Inspect workspace build manifests and scripts for untrusted build execution risks.

    Detects malicious lifecycle scripts (NPM), arbitrary setup.py code execution (Python),
    tampered wrapper scripts/URLs (Gradle/Maven), and obfuscated Autotools/M4 hooks (Jia Tan xz).
    """
    root = Path(workspace_root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Workspace directory not found: {root}")

    findings: list[dict[str, Any]] = []
    safe_detect_arguments: list[str] = []

    has_npm_risk = False
    has_wrapper_risk = False

    stack: list[tuple[Path, int]] = [(root, 0)]
    visited_inodes: set[tuple[int, int]] = set()
    root_stat = root.stat()
    visited_inodes.add((root_stat.st_dev, root_stat.st_ino))

    while stack:
        current_dir, depth = stack.pop()
        try:
            entries = list(os.scandir(current_dir))
        except OSError:
            continue

        for entry in entries:
            try:
                name = entry.name
                entry_stat = entry.stat(follow_symlinks=False)
                inode_key = (entry_stat.st_dev, entry_stat.st_ino)

                if entry.is_dir(follow_symlinks=False):
                    if name in STANDARD_SAFE_EXCLUSIONS or name == "node_modules":
                        continue
                    if depth < max_depth and inode_key not in visited_inodes:
                        visited_inodes.add(inode_key)
                        stack.append((Path(entry.path), depth + 1))
                    continue

                if not entry.is_file(follow_symlinks=False):
                    continue

                rel_path = str(Path(entry.path).relative_to(root))
                file_path = Path(entry.path)

                # 1. NPM Lifecycle Hooks (package.json)
                if name == "package.json":
                    try:
                        raw = file_path.read_bytes()
                        if len(raw) <= 512 * 1024:
                            data = json.loads(raw.decode("utf-8", errors="replace"))
                            scripts = data.get("scripts", {})
                            if isinstance(scripts, dict):
                                for hook in (
                                    "preinstall",
                                    "install",
                                    "postinstall",
                                    "preprepare",
                                    "prepare",
                                    "prepublish",
                                ):
                                    val = scripts.get(hook)
                                    if isinstance(val, str) and val.strip():
                                        val_clean = val.strip()
                                        # Check malicious shell
                                        matched_malicious = [
                                            pat for pat in MALICIOUS_SHELL_PATTERNS if pat in val_clean
                                        ]
                                        if matched_malicious:
                                            has_npm_risk = True
                                            findings.append(
                                                {
                                                    "id": "NPM_MALICIOUS_LIFECYCLE_SHELL",
                                                    "severity": "CRITICAL",
                                                    "file": rel_path,
                                                    "hook": hook,
                                                    "command": val_clean,
                                                    "pattern": matched_malicious[0],
                                                    "description": (
                                                        f"Malicious shell invocation pattern '{matched_malicious[0]}' "
                                                        f"detected in package.json '{hook}' lifecycle script."
                                                    ),
                                                }
                                            )
                                        elif hook in ("preinstall", "install", "postinstall"):
                                            # Check benign tool allowlist
                                            is_benign = any(
                                                val_clean.startswith(bp) for bp in BENIGN_NPM_HOOK_PREFIXES
                                            )
                                            if not is_benign:
                                                has_npm_risk = True
                                                findings.append(
                                                    {
                                                        "id": "NPM_CUSTOM_INSTALL_HOOK",
                                                        "severity": "WARNING",
                                                        "file": rel_path,
                                                        "hook": hook,
                                                        "command": val_clean,
                                                        "description": (
                                                            f"Custom '{hook}' lifecycle script detected in package.json; "
                                                            "may execute arbitrary code during Detect NPM detector execution."
                                                        ),
                                                    }
                                                )
                    except Exception:  # noqa: BLE001
                        pass

                # 2. Python setup.py execution risk
                elif name == "setup.py":
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                        parsed_ast = False
                        try:
                            tree = ast.parse(text, filename=rel_path)
                            parsed_ast = True
                            for node in ast.walk(tree):
                                if isinstance(node, ast.Call):
                                    call_id = ""
                                    if isinstance(node.func, ast.Name):
                                        call_id = node.func.id
                                    elif isinstance(node.func, ast.Attribute):
                                        val_name = ""
                                        if isinstance(node.func.value, ast.Name):
                                            val_name = node.func.value.id
                                        elif isinstance(node.func.value, ast.Attribute) and isinstance(node.func.value.value, ast.Name):
                                            val_name = f"{node.func.value.value.id}.{node.func.value.attr}"
                                        call_id = f"{val_name}.{node.func.attr}" if val_name else node.func.attr

                                    # Check critical code execution
                                    if call_id in (
                                        "os.system",
                                        "os.popen",
                                        "eval",
                                        "exec",
                                        "base64.b64decode",
                                        "urllib.request.urlopen",
                                    ):
                                        findings.append(
                                            {
                                                "id": "PYTHON_SETUP_PY_CODE_EXEC",
                                                "severity": "CRITICAL",
                                                "file": rel_path,
                                                "call": call_id,
                                                "lineno": getattr(node, "lineno", 1),
                                                "description": (
                                                    f"Direct arbitrary code execution call '{call_id}' "
                                                    f"detected in {rel_path}."
                                                ),
                                            }
                                        )
                                    elif call_id.startswith("subprocess."):
                                        has_shell_true = any(
                                            kw.arg == "shell"
                                            and (
                                                (isinstance(kw.value, ast.Constant) and bool(kw.value.value))
                                                or (isinstance(kw.value, ast.Name) and kw.value.id == "True")
                                            )
                                            for kw in node.keywords
                                        )
                                        if has_shell_true:
                                            findings.append(
                                                {
                                                    "id": "PYTHON_SETUP_PY_CODE_EXEC",
                                                    "severity": "CRITICAL",
                                                    "file": rel_path,
                                                    "call": f"{call_id}(shell=True)",
                                                    "lineno": getattr(node, "lineno", 1),
                                                    "description": (
                                                        f"Dangerous shell=True subprocess execution detected in {rel_path}."
                                                    ),
                                                }
                                            )
                                        else:
                                            findings.append(
                                                {
                                                    "id": "PYTHON_SETUP_PY_SUBPROCESS",
                                                    "severity": "WARNING",
                                                    "file": rel_path,
                                                    "call": call_id,
                                                    "lineno": getattr(node, "lineno", 1),
                                                    "description": (
                                                        f"Subprocess call '{call_id}' detected in setup.py build script."
                                                    ),
                                                }
                                            )
                        except (SyntaxError, ValueError):
                            pass

                        if not parsed_ast:
                            # Regex fallback on SyntaxError
                            if re.search(
                                r"\b(os\.system|os\.popen|eval|exec|base64\.b64decode|urllib\.request\.urlopen)\b",
                                text,
                            ) or re.search(r"subprocess\.[a-zA-Z0-9_]+\(.*shell\s*=\s*True", text):
                                findings.append(
                                    {
                                        "id": "PYTHON_SETUP_PY_CODE_EXEC",
                                        "severity": "CRITICAL",
                                        "file": rel_path,
                                        "description": (
                                            f"Arbitrary code execution pattern detected in {rel_path} (regex fallback)."
                                        ),
                                    }
                                )
                            elif re.search(r"subprocess\.[a-zA-Z0-9_]+\(", text):
                                findings.append(
                                    {
                                        "id": "PYTHON_SETUP_PY_SUBPROCESS",
                                        "severity": "WARNING",
                                        "file": rel_path,
                                        "description": (
                                            f"Subprocess call detected in {rel_path} (regex fallback)."
                                        ),
                                    }
                                )
                    except Exception:  # noqa: BLE001
                        pass

                # 3. Build Wrapper Tampering (gradlew, mvnw, *-wrapper.properties)
                elif name in ("gradle-wrapper.properties", "maven-wrapper.properties"):
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                        for line in text.splitlines():
                            line_s = line.strip()
                            if line_s.startswith("distributionUrl") and "=" in line_s:
                                dist_url = line_s.split("=", 1)[1].strip().replace("\\:", ":")
                                parsed = urllib.parse.urlparse(dist_url)
                                host = (parsed.hostname or "").lower()
                                is_trusted = any(
                                    host == th or host.endswith("." + th) for th in TRUSTED_WRAPPER_HOSTS
                                )
                                if not is_trusted or parsed.scheme != "https":
                                    has_wrapper_risk = True
                                    findings.append(
                                        {
                                            "id": "UNTRUSTED_WRAPPER_DISTRIBUTION_URL",
                                            "severity": "CRITICAL",
                                            "file": rel_path,
                                            "distribution_url": dist_url,
                                            "description": (
                                                f"Wrapper distributionUrl points to untrusted host '{host}' "
                                                f"or unencrypted transport ({parsed.scheme}) in {rel_path}."
                                            ),
                                        }
                                    )
                    except Exception:  # noqa: BLE001
                        pass

                elif name in ("gradlew", "mvnw"):
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                        cleaned_wrapper = re.sub(
                            r"^\s*eval\s+(?:[\"']?set\s+--|splitJvmOpts\b|`echo\s+args\$i`=).*$",
                            "",
                            text,
                            flags=re.MULTILINE,
                        )
                        for pat in SUSPICIOUS_WRAPPER_PATTERNS:
                            if pat in cleaned_wrapper:
                                has_wrapper_risk = True
                                findings.append(
                                    {
                                        "id": "TAMPERED_BUILD_WRAPPER_SCRIPT",
                                        "severity": "CRITICAL",
                                        "file": rel_path,
                                        "pattern": pat,
                                        "description": (
                                            f"Wrapper script {rel_path} contains suspicious execution pattern '{pat}'."
                                        ),
                                    }
                                )
                                break
                    except Exception:  # noqa: BLE001
                        pass

                # 4. Autotools / M4 Hook Risk (configure.ac, Makefile.am, *.m4 - Jia Tan xz vector)
                elif name in ("configure.ac", "Makefile.am") or name.endswith(".m4"):
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                        # Jia Tan xz byte translation substitution table pattern
                        has_tr = 'tr "\\t \\-_" " \\t_\\-"' in text or r'tr "\t \-_" " \t_\-"' in text
                        # Slicing binary inputs into decompression or shell
                        has_pipe_exec = bool(
                            re.search(
                                r"(?:head|tail)\s+-[cn]\s+[0-9]+.*?\|\s*(?:xz|gzip|sh|bash)\b",
                                text,
                            )
                        )
                        # Base64 piped into execution
                        has_b64_pipe = bool(
                            re.search(r"base64\s+-d.*?\|\s*(?:sh|bash|eval)\b", text)
                        )

                        if has_tr or has_pipe_exec or has_b64_pipe:
                            findings.append(
                                {
                                    "id": "SUSPICIOUS_AUTOTOOLS_M4_HOOK",
                                    "severity": "CRITICAL",
                                    "file": rel_path,
                                    "description": (
                                        f"Suspicious Autotools/M4 payload extraction or obfuscated execution hook "
                                        f"detected in {rel_path} (CVE-2024-3094 vector)."
                                    ),
                                }
                            )
                    except Exception:  # noqa: BLE001
                        pass

                # 5. Gradle Config Phase Execution (build.gradle, build.gradle.kts)
                elif name in ("build.gradle", "build.gradle.kts"):
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                        if "Runtime.getRuntime().exec" in text or "ProcessBuilder(" in text:
                            findings.append(
                                {
                                    "id": "GRADLE_CONFIG_EXEC_HOOK",
                                    "severity": "HIGH",
                                    "file": rel_path,
                                    "description": (
                                        f"Arbitrary system execution during Gradle configuration phase detected in {rel_path}."
                                    ),
                                }
                            )
                    except Exception:  # noqa: BLE001
                        pass

                # 6. Spring Boot Config Hijack Risk (application.properties / application.yml / application.xml)
                elif name in ("application.properties", "application.yml", "application.yaml", "application.xml"):
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                        has_detect_exec_override = bool(
                            re.search(
                                r"(?:^|\s)detect\.[a-zA-Z0-9_.\-]*path\s*[:=]",
                                text,
                                re.IGNORECASE | re.MULTILINE,
                            )
                            or re.search(
                                r"(?:^|\s)blackduck\.(?:url|api\.token|proxy\.host|trust\.cert)\s*[:=]",
                                text,
                                re.IGNORECASE | re.MULTILINE,
                            )
                            or (
                                re.search(r"^\s*detect\s*:", text, re.MULTILINE)
                                and re.search(r"^\s+path\s*:", text, re.MULTILINE)
                            )
                        )
                        if has_detect_exec_override:
                            findings.append(
                                {
                                    "id": "SPRING_BOOT_CONFIG_HIJACK_RISK",
                                    "severity": "CRITICAL",
                                    "file": rel_path,
                                    "description": (
                                        f"Spring Boot configuration file {rel_path} overrides Black Duck Detect "
                                        "executable paths or server settings (detect.*.path / blackduck.url). "
                                        "Because Detect is a Spring Boot application, running Detect from this "
                                        "directory automatically loads this file and can trigger arbitrary code "
                                        "execution or token exfiltration."
                                    ),
                                }
                            )
                        elif rel_path in (
                            "application.properties",
                            "application.yml",
                            "application.yaml",
                            "application.xml",
                            "config/application.properties",
                            "config/application.yml",
                            "config/application.yaml",
                            "config/application.xml",
                        ):
                            findings.append(
                                {
                                    "id": "SPRING_BOOT_WORKING_DIR_COLLISION",
                                    "severity": "WARNING",
                                    "file": rel_path,
                                    "description": (
                                        f"Spring Boot config {rel_path} in workspace root/config may be ingested "
                                        "by Detect if Detect is invoked from this working directory. Run Detect "
                                        "from an empty working directory with --detect.source.path."
                                    ),
                                }
                            )
                    except Exception:  # noqa: BLE001
                        pass

            except OSError:
                continue

    # Determine overall verdict
    if any(f.get("severity") == "CRITICAL" for f in findings):
        verdict = "CRITICAL_UNTRUSTED_EXECUTION_RISK"
    elif any(f.get("severity") in ("HIGH", "WARNING") for f in findings):
        verdict = "WARNING_REVIEW_BUILD_HOOKS"
    else:
        verdict = "SAFE"

    # Suggest safe Detect arguments
    if has_npm_risk:
        safe_detect_arguments.append("--detect.npm.arguments=--ignore-scripts")
    if has_wrapper_risk:
        safe_detect_arguments.append('--detect.gradle.build.command="--no-daemon"')
    if verdict in ("CRITICAL_UNTRUSTED_EXECUTION_RISK", "WARNING_REVIEW_BUILD_HOOKS"):
        safe_detect_arguments.append("--detect.detector.buildless=true")

    advisory = (
        "PRE-DETECT EXECUTION SAFETY GUARD: Workspace was analyzed for pre-execution build risks. "
        f"Verdict: {verdict}. "
        + (
            f"Found {len(findings)} risky build hooks. Run Detect inside an isolated ephemeral runner or pass safe flags."
            if findings
            else "No untrusted lifecycle scripts or wrapper tampering detected."
        )
    )

    findings.sort(key=lambda x: (str(x.get("severity")), str(x.get("file")), str(x.get("id"))))

    return {
        "verdict": verdict,
        "findings": findings,
        "safe_detect_arguments": safe_detect_arguments,
        "advisory": advisory,
    }
