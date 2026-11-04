"""Client-side pre-scan analyzer and workspace tuner for Detect.

Analyzes workspace layout, classifies lockfiles vs. unpinned manifests,
recommends safe exclusions vs. conditional exclusions, detects host/container
RAM limits to prevent exit 137 OOM kills, runs preflight server health checks,
and evaluates pre-execution build risks and expected BOM completeness.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from sca_preflight.catalog import (
    ARCHIVE_EXTENSIONS,
    BD_CONFIRMATION_ADVISORY,
    BINARY_BANNER_BLOCKLIST,
    C_PREFIX_COMPONENT_MAP,
    CONDITIONAL_DIR_CANDIDATES,
    ECOSYSTEM_MAP,
    GENERIC_DIR_PREFIXES,
    GENERIC_MACRO_PREFIXES,
    JS_LOCKFILES,
    KNOWN_LOCKFILES,
    KNOWN_NON_BINARY_EXTENSIONS,
    KNOWN_UNPINNED_MANIFESTS,
    STANDARD_SAFE_EXCLUSIONS,
    PrescanReport,
    _normalize_component_name,
    _parse_c_version_header_bytes,
    _parse_cargo_toml_bytes,
    _parse_cmakelists_bytes,
    _parse_debian_control_bytes,
    _parse_nuspec_bytes,
    _parse_package_json_bytes,
    _parse_pkginfo_bytes,
    decode_manifest_bytes,
    export_learned_catalog,
    load_pareto_catalog,
    load_pareto_license_kb,
    load_pareto_vuln_kb,
    safe_parse_xml_bytes,
    sanitize_line,
)
from sca_preflight.completeness import (
    _count_lockfile_entries,
    _count_manifest_direct_deps,
    analyze_git_diff,
    build_expected_bom_baseline,
    check_baseline,
    compute_workspace_merkle_provenance,
    emit_supplemental_bdio,
    infer_project_archetypes,
    save_baseline,
    verify_detect_output,
)
from sca_preflight.dpi import (
    _inspect_single_file,
    _is_archive,
    extract_pe_version_strings,
    inspect_archives_and_binaries,
    inspect_build_execution_risks,
)
from sca_preflight.vuln_matcher import (
    extract_pinned_manifest_components,
    match_pareto_license_risks,
    match_pareto_vulnerabilities,
)

__all__ = [
    # catalog
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
    "safe_parse_xml_bytes",
    # dpi
    "_inspect_single_file",
    "_is_archive",
    "extract_pe_version_strings",
    "inspect_archives_and_binaries",
    "inspect_build_execution_risks",
    # vuln_matcher
    "extract_pinned_manifest_components",
    "match_pareto_license_risks",
    "match_pareto_vulnerabilities",
    # completeness
    "_count_lockfile_entries",
    "_count_manifest_direct_deps",
    "analyze_git_diff",
    "build_expected_bom_baseline",
    "check_baseline",
    "compute_workspace_merkle_provenance",
    "emit_supplemental_bdio",
    "infer_project_archetypes",
    "save_baseline",
    "verify_detect_output",
    # prescan
    "build_executive_summary",
    "build_file_accounting_and_ledger",
    "compute_scanner_memory_mb",
    "detect_available_ram_mb",
    "detect_java_runtime",
    "generate_ai_brief_html",
    "generate_ai_brief_markdown",
    "main",
    "merge_existing_detect_args",
    "preflight_server_check",
    "scan_workspace",
]

COMMA_SEPARATED_DETECT_PROPERTIES = frozenset(
    {
        "--detect.excluded.directories",
        "--detect.tools",
        "--detect.excluded.detector.types",
        "--detect.included.detector.types",
        "--detect.gradle.excluded.configurations",
        "--detect.maven.excluded.scopes",
    }
)


def merge_existing_detect_args(
    recommended_args: list[str],
    existing_args_str: str | None = None,
) -> dict[str, Any]:
    """Merge recommended Detect arguments with customer's existing arguments additively."""
    existing_map: dict[str, str] = {}
    if existing_args_str:
        for tok in re.findall(r"(--(?:detect|blackduck)\.[a-zA-Z0-9._\-]+=[^\s'\"]+)", existing_args_str):
            k, v = tok.split("=", 1)
            existing_map[k.strip()] = v.strip()

    merged_args: list[str] = []
    baseline_safe_args: list[str] = []
    optional_tweaks: list[dict[str, str]] = []
    already_configured: list[str] = []
    additive_merge_notes: list[str] = []
    seen_keys: set[str] = set()

    for arg in recommended_args:
        if "=" not in arg:
            merged_args.append(arg)
            continue
        k, v = arg.split("=", 1)
        seen_keys.add(k)
        is_already_satisfied = False
        if k in COMMA_SEPARATED_DETECT_PROPERTIES and k in existing_map:
            exist_items = [x.strip() for x in existing_map[k].split(",") if x.strip()]
            rec_items = [x.strip() for x in v.split(",") if x.strip()]
            combined: list[str] = list(exist_items)
            added: list[str] = []
            for item in rec_items:
                if item not in combined:
                    combined.append(item)
                    added.append(item)
            merged_val = ",".join(combined)
            effective_arg = f"{k}={merged_val}"
            if not added:
                is_already_satisfied = True
                already_configured.append(
                    f"{k}={existing_map[k]} (verified: already includes recommended '{v}')"
                )
            else:
                additive_merge_notes.append(
                    f"Additively concatenated {k}: existing '{existing_map[k]}' + '{','.join(added)}' -> '{merged_val}'"
                )
        elif k in existing_map:
            effective_arg = f"{k}={existing_map[k]}"
            if existing_map[k] == v or (
                v.isdigit() and existing_map[k].isdigit() and int(existing_map[k]) >= int(v)
            ):
                is_already_satisfied = True
                already_configured.append(
                    f"{k}={existing_map[k]} (verified: satisfies recommended {k}={v}; suppressed from Section 2.2 noise)"
                )
            else:
                effective_arg = arg
        else:
            effective_arg = arg

        merged_args.append(effective_arg)
        if is_already_satisfied or k in (
            "--detect.blackduck.signature.scanner.memory",
            "--detect.blackduck.signature.scanner.parallel.processors",
            "--detect.excluded.directories",
            "--blackduck.offline.mode",
            "--detect.tools",
        ):
            baseline_safe_args.append(effective_arg)
        else:
            reason = "Expands BOM coverage beyond default root-only / package-manager settings."
            tradeoff = "Increases scan traversal time; opt-in when fuller BOM coverage is needed."
            if k == "--detect.detector.search.depth":
                reason = (
                    f"Discovers nested manifests/lockfiles down to directory depth {v} "
                    "(default is 0, which stops at root and skips standalone/non-reactor subdirectories or buildless nested modules)."
                )
                tradeoff = "Increases detector filesystem walk and subproject inspector invocations across nested folders."
            elif k == "--detect.detector.search.continue":
                reason = (
                    "Continues running child directory detectors even after a parent manifest is found "
                    "(default is false; needed for non-reactor subprojects, mixed Maven/Gradle trees, or buildless mode)."
                )
                tradeoff = "Runs package manager inspectors on every nested subproject; can slow down large multi-module monorepos."
            elif k == "--detect.binary.scan.search.depth":
                reason = (
                    f"Discovers binary/archive artifacts down to directory depth {v} when BINARY_SCAN (BDBA) is enabled "
                    "with --detect.binary.scan.file.name.patterns (default is 0; does not affect SIGNATURE_SCAN)."
                )
                tradeoff = "Applies only when BINARY_SCAN is enabled; uploads matching nested archives to the BDBA worker."
            elif k == "--detect.blackduck.signature.scanner.individual.file.matching":
                reason = "Computes single-file SHA-1 checksums for standalone binaries (.so, .dll, .exe, .o) omitted by default NONE."
                tradeoff = "Adds per-file SHA-1 matching overhead during Signature Scanning."
            elif k == "--detect.excluded.directories.search.depth":
                reason = f"Extends excluded-directory pruning down to depth {v} (default is 4)."
                tradeoff = "Minimal overhead; prevents deep build/cache folders from being signature-scanned."
            elif k in ("--detect.excluded.detector.types", "--detect.gradle.excluded.configurations"):
                reason = "Prevents false detector failures or test-only dependency pollution (additive comma-separated list)."
                tradeoff = "Skips excluded detector types or test configurations by design."
            optional_tweaks.append(
                {
                    "argument": effective_arg,
                    "property": k,
                    "unlocks": reason,
                    "tradeoff": tradeoff,
                }
            )

    # Preserve any customer-supplied flags not already in recommended_args
    for ek, ev in existing_map.items():
        if ek in seen_keys:
            continue
        if ek == "--detect.tools":
            tools_list = [x.strip() for x in ev.split(",") if x.strip()]
            upper_tools = {x.upper() for x in tools_list}
            if "DETECTOR" in upper_tools and "SIGNATURE_SCAN" not in upper_tools and "ALL" not in upper_tools:
                tools_list.append("SIGNATURE_SCAN")
                merged_val = ",".join(tools_list)
                eff = f"{ek}={merged_val}"
                additive_merge_notes.append(
                    f"Additively concatenated {ek}: existing '{ev}' + 'SIGNATURE_SCAN' -> '{merged_val}'"
                )
                merged_args.append(eff)
                baseline_safe_args.append(eff)
                continue
        eff_existing = f"{ek}={ev}"
        merged_args.append(eff_existing)
        baseline_safe_args.append(eff_existing)
        already_configured.append(f"{eff_existing} (preserved from existing customer config)")

    return {
        "effective_recommended_arguments": merged_args,
        "baseline_safe_arguments": baseline_safe_args,
        "optional_coverage_tweaks": optional_tweaks,
        "already_configured_by_customer": already_configured,
        "additive_merge_notes": additive_merge_notes,
    }


def build_file_accounting_and_ledger(report: dict[str, Any]) -> dict[str, Any]:
    """Build per-object 4-bucket conservation-of-mass accounting and Bucket 2a file ledger."""
    prov = report.get("scan_input_provenance") or {}
    dpi = report.get("deep_packet_inspection") or {}
    ph = report.get("pareto_hints") or {}

    total_dirs = int(report.get("total_dirs_scanned") or 0)
    total_files = int(report.get("total_files_scanned") or 0)
    total_bytes = int(report.get("total_workspace_bytes") or 0)
    total_mb = round(total_bytes / (1024 * 1024), 2)

    safe_excl = list(report.get("safe_exclusions") or [])
    dep_paths: list[str] = list(prov.get("dependency_input_paths") or [])
    dep_bytes = int(prov.get("dependency_inputs_bytes") or 0)
    dep_mb = round(dep_bytes / (1024 * 1024), 2)

    files_hashed = int(prov.get("files_hashed_count") or total_files)
    early_stop_skipped = max(0, total_files - files_hashed)

    # Index findings by file path
    lockfiles_by_path = {str(x.get("path")): x for x in (report.get("lockfiles") or [])}
    manifests_by_path = {str(x.get("path")): x for x in (report.get("unpinned_manifests") or [])}
    imd_by_path: dict[str, list[dict[str, Any]]] = {}
    for imd in dpi.get("internal_manifest_discoveries") or []:
        p = str(imd.get("path") or imd.get("file_path") or imd.get("archive_path") or "").split("!/")[0]
        if p:
            imd_by_path.setdefault(p, []).append(imd)

    smells_by_path: dict[str, list[dict[str, Any]]] = {}
    for sm in dpi.get("disaster_smells") or []:
        p = str(sm.get("location") or sm.get("file_path") or "").split("!/")[0]
        if p:
            smells_by_path.setdefault(p, []).append(sm)

    attr_by_path = {str(a.get("path")): a for a in (ph.get("attribution_files") or [])}
    docker_by_path: dict[str, list[str]] = {}
    for d in ph.get("docker_base_images") or []:
        dp = str(d.get("path") or "")
        if dp:
            docker_by_path.setdefault(dp, []).append(str(d.get("full_spec") or ""))

    candidate_ev_paths = (
        set(dep_paths)
        | set(lockfiles_by_path.keys())
        | set(manifests_by_path.keys())
        | set(imd_by_path.keys())
        | set(smells_by_path.keys())
        | set(attr_by_path.keys())
    )
    vulns_by_path: dict[str, list[dict[str, Any]]] = {}
    for v in report.get("actionable_vulnerabilities") or []:
        ev_list = list(v.get("all_evidence_sources") or [str(v.get("evidence_source") or "")])
        for ev in ev_list:
            ev_path = str(ev).split(":", 1)[-1].split(" (+", 1)[0].split("!/", 1)[0].strip()
            if ev_path in candidate_ev_paths:
                vulns_by_path.setdefault(ev_path, []).append(v)

    lic_by_path: dict[str, list[dict[str, Any]]] = {}
    for lr in report.get("actionable_license_risks") or []:
        ev_list = list(lr.get("all_evidence_sources") or [str(lr.get("evidence_source") or "")])
        for ev in ev_list:
            ev_path = str(ev).split(":", 1)[-1].split(" (+", 1)[0].split("!/", 1)[0].strip()
            if ev_path in candidate_ev_paths:
                lic_by_path.setdefault(ev_path, []).append(lr)

    all_actionable_paths = sorted(
        candidate_ev_paths | set(vulns_by_path.keys()) | set(lic_by_path.keys())
    )
    dep_count = len(all_actionable_paths)
    prov_only_count = max(0, files_hashed - dep_count)
    prov_only_bytes = max(0, total_bytes - dep_bytes)
    prov_only_mb = round(max(0.0, total_mb - dep_mb), 2) if total_bytes >= dep_bytes else round(prov_only_bytes / (1024 * 1024), 2)

    ledger: list[dict[str, Any]] = []
    for p in all_actionable_paths:
        if not p:
            continue
        depth = p.count("/")
        name = Path(p).name
        lower = name.lower()

        bucket_sub = "2a-ii Native Build / Config"
        prescan_notes: list[str] = []
        detect_notes: str = "SILENTLY IGNORED by DETECTOR (relies on Signature Scanner)."

        if p in lockfiles_by_path:
            lf = lockfiles_by_path[p]
            bucket_sub = "2a-i Lockfile"
            cnt = lf.get("count", 0)
            enc = lf.get("encoding", "utf-8")
            prescan_notes.append(f"Pinned lockfile ({cnt} locked component(s), encoding={enc}); hashed into L1.")
            if enc in ("utf-16-le", "utf-16-be"):
                detect_notes = f"SILENTLY CORRUPTED / 0% BOM MATCH ({enc} encoding breaks default UTF-8 parser)."
            elif depth > 0:
                detect_notes = f"SILENTLY IGNORED by DETECTOR at default --detect.detector.search.depth=0 (located at depth {depth})."
            else:
                detect_notes = "Processed by DETECTOR at root depth=0."
        elif p in manifests_by_path:
            mf = manifests_by_path[p]
            cnt = mf.get("count", 0)
            enc = mf.get("encoding", "utf-8")
            pinned_by_sib = bool(mf.get("pinned_by_sibling_lockfile"))
            in_reactor = bool(mf.get("in_maven_reactor"))
            has_modules = bool(mf.get("has_maven_modules"))
            if pinned_by_sib:
                bucket_sub = "2a-i Manifest (Lockfile-Paired)"
                prescan_notes.append(
                    f"Package manifest ({cnt} direct dep(s), paired with sibling lockfile, encoding={enc}, depth={depth}); hashed into L1."
                )
                if enc in ("utf-16-le", "utf-16-be"):
                    detect_notes = f"SILENTLY CORRUPTED / 0% BOM MATCH ({enc} encoding breaks default UTF-8 parser)."
                elif depth > 0:
                    detect_notes = f"SILENTLY IGNORED by DETECTOR at default --detect.detector.search.depth=0 (located at depth {depth})."
                else:
                    detect_notes = "Processed by DETECTOR at root depth=0 alongside sibling lockfile."
            elif name == "pom.xml" and in_reactor:
                bucket_sub = "2a-i Maven Reactor Module"
                prescan_notes.append(
                    f"Maven child module POM ({cnt} direct dep(s), declared in parent <modules>, depth={depth}); hashed into L1."
                )
                detect_notes = (
                    f"Traversed at depth=0 ONLY if parent Maven CLI reactor succeeds (mvn dependency:tree); "
                    f"SILENTLY IGNORED at default depth=0 in buildless mode (requires --detect.detector.search.depth>={depth} and --detect.detector.search.continue=true)."
                )
            elif name == "pom.xml" and depth == 0 and has_modules:
                bucket_sub = "2a-i Root Aggregator POM"
                prescan_notes.append(
                    f"Root Maven aggregator POM ({cnt} direct dep(s), declares child <modules>, encoding={enc}); hashed into L1."
                )
                detect_notes = (
                    "Processed by DETECTOR at root depth=0 (Maven CLI traverses declared <modules>, "
                    "but skips standalone non-reactor POMs and Gradle subprojects unless depth and continue=true are set)."
                )
            else:
                bucket_sub = "2a-i Unpinned Manifest"
                prescan_notes.append(f"Unpinned manifest ({cnt} direct dep(s), encoding={enc}, depth={depth}); hashed into L1.")
                if enc in ("utf-16-le", "utf-16-be"):
                    detect_notes = f"SILENTLY CORRUPTED / 0% BOM MATCH ({enc} encoding breaks default UTF-8 parser)."
                elif depth > 0:
                    detect_notes = (
                        f"SILENTLY IGNORED by DETECTOR at default --detect.detector.search.depth=0 (located at depth {depth}); "
                        f"if depth>={depth} is set without build tools installed, risks Exit Code 5/15 (FAILURE_ACCURACY_NOT_MET)."
                    )
                else:
                    detect_notes = "Processed by DETECTOR at root depth=0 (requires package manager CLI or --detect.accuracy.required=NONE)."
        elif p in attr_by_path:
            af = attr_by_path[p]
            bucket_sub = "2a-iv Legal / Attribution"
            spdx = ", ".join(af.get("spdx_licenses") or []) or "no SPDX tag"
            prescan_notes.append(f"Inspected license/attribution text ({spdx}); hashed into L1.")
            detect_notes = "SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled."
        elif p in docker_by_path:
            bucket_sub = "2a-ii Containerfile"
            imgs = ", ".join(docker_by_path[p])
            prescan_notes.append(f"Extracted base image declaration(s): {imgs}; hashed into L1.")
            detect_notes = "SILENTLY IGNORED by standard source DETECTOR scan (requires CONTAINER_SCAN on built image tar)."
        elif any(lower.endswith(ext_a) for ext_a in ARCHIVE_EXTENSIONS) or lower.endswith((".so", ".dll", ".dylib", ".exe", ".bin")) or ".so." in lower:
            is_shaded = len(imd_by_path.get(p, [])) > 1 or "shaded" in lower or "fat" in lower or "uber" in lower
            bucket_sub = "2a-iii Shaded / Fat Archive" if is_shaded else "2a-iii Archive / Binary"
            prescan_notes.append("Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1.")
            if lower.endswith((".so", ".dll", ".dylib", ".exe", ".bin")) or ".so." in lower:
                detect_notes = "SILENTLY IGNORED by Signature Scanner default --individualFileMatching=NONE (omits single-file SHA-1 checksums)."
            elif is_shaded:
                detect_notes = (
                    "BLIND-SPOT TRAP: Ignored by DETECTOR; Signature Scanner hashes outer archive only and misses shaded/repackaged inner classes unless deep inspection or BDBA is enabled."
                )
            else:
                detect_notes = (
                    "Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA."
                )
        elif lower.endswith(".h") or lower == "version.dat":
            bucket_sub = "2a-ii Native Version Header"
            prescan_notes.append("Parsed C/C++ version header macros; hashed into L1.")
            detect_notes = "SILENTLY IGNORED by DETECTOR (no Conan/vcpkg lockfile; relies on whole-directory SIGNATURE_SCAN or BDBA)."
        else:
            bucket_sub = "2a-ii Native Build Script"
            prescan_notes.append("Inspected for native find_package/pkg_check_modules hints and build-execution hooks; hashed into L1.")
            detect_notes = "SILENTLY IGNORED by DETECTOR (no C/C++ package lockfile)."

        if p in imd_by_path:
            for imd in imd_by_path[p]:
                c = imd.get("component") or imd.get("name")
                v = imd.get("version")
                st = imd.get("source_type")
                if c and v:
                    prescan_notes.append(f"Extracted `{c} {v}` ({st}).")

        if p in vulns_by_path:
            v_strs = list(
                dict.fromkeys(
                    f"{v.get('cve_id')} (CVSS {v.get('cvss')}{', CISA-KEV' if v.get('cisa_kev') else ''})"
                    for v in vulns_by_path[p]
                )
            )
            prescan_notes.append(f"Matched vulnerability: {', '.join(v_strs)}.")

        if p in lic_by_path:
            l_strs = list(
                dict.fromkeys(
                    f"{lr.get('rule_id')} ({lr.get('license_id')})" for lr in lic_by_path[p]
                )
            )
            prescan_notes.append(f"Matched license risk: {', '.join(l_strs)}.")

        if p in smells_by_path:
            s_strs = list(
                dict.fromkeys(str(sm.get("id") or sm.get("name")) for sm in smells_by_path[p])
            )
            prescan_notes.append(f"Flagged blind-spot trap: {', '.join(s_strs)}.")

        has_high_signal = bool(p in vulns_by_path or p in lic_by_path or p in smells_by_path)
        has_med_signal = bool(
            p in lockfiles_by_path
            or (p in manifests_by_path and int(manifests_by_path[p].get("count", 0)) > 0)
            or p in imd_by_path
            or p in docker_by_path
        )
        sort_prio = 0 if has_high_signal else (1 if has_med_signal else 2)

        ledger.append(
            {
                "path": p,
                "depth": depth,
                "bucket": bucket_sub,
                "prescan_action": " ".join(prescan_notes),
                "default_detect_action": detect_notes,
                "_sort_prio": sort_prio,
            }
        )

    ledger.sort(key=lambda r: (int(r.pop("_sort_prio", 2)), str(r.get("path", ""))))

    all_vulns_list = list(report.get("actionable_vulnerabilities") or [])
    all_lic_list = list(report.get("actionable_license_risks") or [])
    actionable_path_set = set(all_actionable_paths)
    b2a_vuln_count = 0
    b2b_snip_vuln_count = 0
    b2b_snip_verified_count = 0
    for v in all_vulns_list:
        ev_list = list(v.get("all_evidence_sources") or [str(v.get("evidence_source") or "")])
        in_b2a = any(
            str(ev).split(":", 1)[-1].split(" (+", 1)[0].split("!/", 1)[0].strip() in actionable_path_set
            for ev in ev_list
        )
        if in_b2a:
            b2a_vuln_count += 1
        else:
            b2b_snip_vuln_count += 1
        if v.get("snippet_verified") and "snippet_location" in v:
            snip_loc_str = str(v.get("snippet_location") or "")
            if snip_loc_str and "!/" not in snip_loc_str and snip_loc_str not in actionable_path_set:
                b2b_snip_verified_count += 1

    if b2b_snip_vuln_count > 0:
        b2b_prescan_action = (
            f"Hashed {prov_only_count} source/doc files into Layer 2 (L2), scanned for unpatched code snippets "
            f"({b2b_snip_vuln_count} standalone unversioned code-snippet CVE hit(s)) and embedded private keys "
            "(0 package manifest declarations)."
        )
    elif b2b_snip_verified_count > 0:
        b2b_prescan_action = (
            f"Hashed {prov_only_count} first-party source/doc files into Layer 2 (L2), scanned for unpatched code snippets "
            f"({b2b_snip_verified_count} source-snippet verification(s)) and embedded private keys "
            "(0 third-party BOM declarations)."
        )
    else:
        b2b_prescan_action = (
            f"Hashed {prov_only_count} first-party source/doc files into Layer 2 (L2), scanned for unpatched code snippets "
            "and embedded private keys (0 third-party BOM declarations)."
        )

    return {
        "total_dirs_scanned": total_dirs,
        "total_files_scanned": total_files,
        "total_workspace_mb": total_mb,
        "bucket_1_excluded_dirs": {
            "count": len(safe_excl),
            "directories": safe_excl,
            "prescan_action": f"Saw {len(safe_excl)} non-shipping folder(s) ({', '.join(safe_excl) if safe_excl else 'none'}), skipped traversal, and added to --detect.excluded.directories.",
            "default_detect_action": "Skips .git by default, but traverses .venv, venv, or unlocked node_modules unless explicitly excluded.",
        },
        "bucket_2a_actionable_l1_files": {
            "count": len(all_actionable_paths),
            "size_mb": dep_mb,
            "prescan_action": (
                f"Hashed 100% into Layer 1 (L1) and extracted BOM baselines, C/C++ header versions, archive/binary metadata, "
                f"and {b2a_vuln_count} CVE / {len(all_lic_list)} license hit(s)."
            ),
            "default_detect_action": (
                "DETECTOR only processes root (depth=0) package manifests; SILENTLY IGNORES depth>=1 manifests, UTF-16 manifests, "
                "C/C++ version headers, CMake/Makefiles, and standalone binaries (--individualFileMatching=NONE)."
            ),
        },
        "bucket_2b_provenance_only_l2_files": {
            "count": prov_only_count,
            "size_mb": prov_only_mb,
            "prescan_action": b2b_prescan_action,
            "default_detect_action": "Ignored by DETECTOR; Signature Scanner hashes directory structure as a whole.",
        },
        "bucket_3_early_stop_unhashed_files": {
            "count": early_stop_skipped,
            "prescan_action": (
                "0 files skipped (100% hashed)."
                if early_stop_skipped == 0
                else f"Skipped L2 content hashing on {early_stop_skipped} deep source files beyond 5,000-file cap (L0 and L1 still 100% complete)."
            ),
            "default_detect_action": "Signature Scanner hashes all files; >10,000 files or >1 GB in one scan risks server queue timeouts.",
        },
        "actionable_files_ledger": ledger,
    }


def detect_available_ram_mb(memory_limit_mb_override: int | None = None) -> tuple[int, str]:
    """Detect available host or container RAM in megabytes and detection source."""
    if memory_limit_mb_override is not None and memory_limit_mb_override > 0:
        return memory_limit_mb_override, "user_override"

    # 1. cgroup v2 container limit
    cg2_limit = Path("/sys/fs/cgroup/memory.max")
    if cg2_limit.is_file():
        try:
            val = cg2_limit.read_text(encoding="utf-8").strip()
            if val != "max":
                bytes_limit = int(val)
                mb = bytes_limit // (1024 * 1024)
                if mb > 0:
                    return mb, "cgroup_v2"
        except (ValueError, OSError):
            pass

    # 1b. cgroup v2 process slice resolution via /proc/self/cgroup
    proc_cg = Path("/proc/self/cgroup")
    if proc_cg.is_file():
        try:
            for line in proc_cg.read_text(encoding="utf-8").splitlines():
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[0] == "0":
                    rel_cg = parts[2].lstrip("/")
                    if rel_cg:
                        slice_limit = Path(f"/sys/fs/cgroup/{rel_cg}/memory.max")
                        if slice_limit.is_file():
                            val = slice_limit.read_text(encoding="utf-8").strip()
                            if val != "max":
                                bytes_limit = int(val)
                                mb = bytes_limit // (1024 * 1024)
                                if mb > 0:
                                    return mb, "cgroup_v2"
        except (ValueError, OSError):
            pass

    # 2. cgroup v1 container limit
    cg1_limit = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if cg1_limit.is_file():
        try:
            val = cg1_limit.read_text(encoding="utf-8").strip()
            bytes_limit = int(val)
            if 0 < bytes_limit < 9_000_000_000_000_000_000:
                mb = bytes_limit // (1024 * 1024)
                if mb > 0:
                    return mb, "cgroup_v1"
        except (ValueError, OSError):
            pass

    # 3. Linux /proc/meminfo MemAvailable
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        try:
            for line in meminfo.read_text(encoding="utf-8").splitlines():
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        kb = int(parts[1])
                        return kb // 1024, "proc_meminfo_available"
        except (ValueError, OSError):
            pass

    # 4. macOS sysctl hw.memsize
    if platform.system() == "Darwin":
        try:
            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip()
            return int(out) // (1024 * 1024), "darwin_sysctl"
        except (subprocess.SubprocessError, ValueError, OSError):
            pass

    # 5. POSIX sysconf fallback
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if isinstance(pages, int) and isinstance(page_size, int) and pages > 0 and page_size > 0:
            return (pages * page_size) // (1024 * 1024), "posix_sysconf"
    except (ValueError, OSError, AttributeError):
        pass

    # Default fallback assumption (4 GB)
    return 4096, "default_fallback"


def compute_scanner_memory_mb(
    available_ram_mb: int,
    parallel_processors: int = 1,
) -> tuple[int, list[str]]:
    """Compute safe Detect signature scanner memory allocation."""
    warnings: list[str] = []
    parallel_processors = max(1, parallel_processors)

    # Invariant: scanner_memory * parallel_processors + 2048 MB <= available_ram_mb
    os_overhead_mb = 2048
    min_required_mb = os_overhead_mb + 512 * parallel_processors

    if available_ram_mb < min_required_mb:
        scanner_memory_mb = max(256, (available_ram_mb - 512) // parallel_processors) if available_ram_mb > 512 else 256
        warnings.append(
            f"CRITICAL: Available RAM ({available_ram_mb} MB) is below the minimum safe requirement "
            f"({min_required_mb} MB) for {parallel_processors} scanner JVM(s) (2048 MB OS reserve + "
            f"512 MB per processor). Signature scanner configured to {scanner_memory_mb} MB per processor, "
            "putting runner at extreme risk of exit 137 (OOM killed). "
            "Recommend reducing --detect.blackduck.signature.scanner.parallel.processors=1 or increasing runner RAM."
        )
    else:
        allocable_total = available_ram_mb - os_overhead_mb
        scanner_memory_mb = max(512, allocable_total // parallel_processors)
        if scanner_memory_mb < 1024:
            warnings.append(
                f"NOTICE: Signature scanner memory per processor ({scanner_memory_mb} MB) "
                f"is modest due to {parallel_processors} parallel processor(s). For large codebases, "
                "consider reducing parallel processors to 1 or increasing runner RAM."
            )

    return scanner_memory_mb, warnings


def detect_java_runtime() -> dict[str, Any]:
    """Check for Java runtime via DETECT_JAVA_PATH, JAVA_HOME, or PATH."""
    java_bin_name = "java.exe" if platform.system() == "Windows" else "java"
    java_path: str | None = None
    detection_source: str | None = None

    # 1. DETECT_JAVA_PATH
    env_detect_java = os.environ.get("DETECT_JAVA_PATH")
    if env_detect_java:
        p = Path(env_detect_java)
        if p.is_file() and os.access(p, os.X_OK):
            java_path = str(p)
            detection_source = "DETECT_JAVA_PATH"

    # 2. JAVA_HOME/bin/java
    if not java_path:
        env_java_home = os.environ.get("JAVA_HOME")
        if env_java_home:
            p = Path(env_java_home) / "bin" / java_bin_name
            if p.is_file() and os.access(p, os.X_OK):
                java_path = str(p)
                detection_source = "JAVA_HOME"

    # 3. PATH via shutil.which("java")
    if not java_path:
        which_java = shutil.which("java")
        if which_java:
            java_path = which_java
            detection_source = "PATH"

    java_version: str | None = None
    if java_path:
        try:
            res = subprocess.run(
                [java_path, "-version"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            ver_output = res.stderr or res.stdout
            first_line = ver_output.splitlines()[0] if ver_output else ""
            java_version = first_line.strip()
        except (subprocess.SubprocessError, OSError):
            java_version = "unknown"

    return {
        "java_found": java_path is not None,
        "java_path": java_path,
        "detection_source": detection_source,
        "version": java_version,
    }


def preflight_server_check(
    bd_url: str,
    api_token: str | None = None,
    proxy_url: str | None = None,
    timeout_sec: float = 5.0,
    opener: urllib.request.OpenerDirector | None = None,
) -> dict[str, Any]:
    """Verify HTTPS connectivity, TLS trust chain, server version, and API token validity."""
    parsed = urllib.parse.urlparse(bd_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {
            "status": "error",
            "connected": False,
            "error": f"Invalid server URL format: {bd_url}. Must include scheme (https://).",
            "server_version": None,
            "token_valid": False,
        }

    base_url = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    if opener is None:
        handlers: list[urllib.request.BaseHandler] = []
        if proxy_url:
            handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        req_opener = urllib.request.build_opener(*handlers)
    else:
        req_opener = opener

    # 1. Server Version & Connectivity Check
    version_url = f"{base_url}/api/current-version"
    server_version: str | None = None
    tls_error: str | None = None
    connect_error: str | None = None

    try:
        req = urllib.request.Request(
            version_url,
            headers={"Accept": "application/json", "User-Agent": "bd-ops-prescan/1.2.0"},
            method="GET",
        )
        with req_opener.open(req, timeout=timeout_sec) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            server_version = str(data.get("version", "unknown"))
    except urllib.error.URLError as err:
        reason = getattr(err, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError) or "certificate verify failed" in str(err):
            tls_error = (
                f"TLS certificate verification failed: {err}. "
                "If traffic passes through an enterprise TLS inspection proxy, "
                "ensure corporate root CA is trusted in the runtime environment "
                "(export REQUESTS_CA_BUNDLE or NODE_EXTRA_CA_CERTS) or specify "
                "--blackduck.trust.cert=true during local pre-production testing."
            )
        else:
            connect_error = f"Connection failed to {version_url}: {err}"
    except Exception as exc:  # noqa: BLE001
        connect_error = f"Unexpected error connecting to {version_url}: {exc}"

    if tls_error:
        return {
            "status": "tls_failure",
            "connected": False,
            "error": tls_error,
            "server_version": None,
            "token_valid": False,
        }

    if connect_error:
        return {
            "status": "connection_failure",
            "connected": False,
            "error": connect_error,
            "server_version": None,
            "token_valid": False,
        }

    # 2. Token Authentication Check (if token provided)
    token_valid = False
    auth_error: str | None = None
    if api_token:
        auth_url = f"{base_url}/api/tokens/authenticate"
        try:
            auth_req = urllib.request.Request(
                auth_url,
                headers={
                    "Authorization": f"token {api_token}",
                    "Accept": "application/json",
                    "User-Agent": "bd-ops-prescan/1.2.0",
                },
                method="POST",
            )
            with req_opener.open(auth_req, timeout=timeout_sec) as auth_resp:
                if auth_resp.status in (200, 204):
                    token_valid = True
                else:
                    auth_error = f"Authentication returned HTTP status {auth_resp.status}"
        except urllib.error.HTTPError as http_err:
            auth_error = f"Authentication rejected (HTTP {http_err.code}): {http_err.reason}"
        except Exception as exc:  # noqa: BLE001
            auth_error = f"Authentication request error: {exc}"

    return {
        "status": "ok" if (not api_token or token_valid) else "auth_failed",
        "connected": True,
        "server_version": server_version,
        "token_checked": bool(api_token),
        "token_valid": token_valid,
        "auth_error": auth_error,
    }


def build_executive_summary(report: PrescanReport) -> dict[str, Any]:
    """Build an executive summary of workspace pre-scan findings."""
    total_files = int(report.get("total_files_scanned", 0))
    lockfiles_count = len(report.get("lockfiles", []))
    manifests_count = len(report.get("unpinned_manifests", []))
    vulns_count = len(report.get("actionable_vulnerabilities", []))
    smells_count = len(report.get("deep_packet_inspection", {}).get("disaster_smells", []))
    build_risk = str(report.get("build_execution_risks", {}).get("verdict", "SAFE"))
    warnings_count = len(report.get("warnings", []))

    status = (
        "ACTION_REQUIRED"
        if (vulns_count > 0 or smells_count > 0 or build_risk == "CRITICAL_UNTRUSTED_EXECUTION_RISK")
        else "HEALTHY"
    )
    return {
        "status": status,
        "files_scanned": total_files,
        "lockfiles_count": lockfiles_count,
        "unpinned_manifests_count": manifests_count,
        "actionable_vulnerabilities_count": vulns_count,
        "disaster_smells_count": smells_count,
        "build_execution_risk": build_risk,
        "warnings_count": warnings_count,
        "advisory": BD_CONFIRMATION_ADVISORY,
    }


def scan_workspace(
    workspace_path: str | Path,
    max_depth: int = 12,
    memory_limit_mb_override: int | None = None,
    parallel_processors: int = 1,
    archive_threshold_mb: float = 50.0,
    offline_mode: bool = False,
    custom_catalog_path: str | Path | None = None,
    max_workers: int | None = None,
    git_diff_base_ref: str | None = None,
    repo_only: bool = False,
    existing_detect_args: str | None = None,
) -> PrescanReport:
    """Scan workspace directory to classify manifests, exclusions, and memory parameters."""
    root = Path(workspace_path).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Workspace directory not found: {root}")

    visited_inodes: set[tuple[int, int]] = set()
    found_lockfiles: list[dict[str, Any]] = []
    found_unpinned_manifests: list[dict[str, Any]] = []
    discovered_safe_dirs: set[str] = set()
    discovered_conditional_dirs: set[str] = set()
    oversized_archives: list[dict[str, Any]] = []
    docker_base_images: list[dict[str, Any]] = []
    native_dependencies: list[dict[str, Any]] = []
    binary_version_artifacts: list[dict[str, Any]] = []
    attribution_files: list[dict[str, Any]] = []
    total_files_scanned = 0
    total_dirs_scanned = 0
    total_workspace_bytes = 0
    has_standalone_binaries = False
    node_modules_parents: set[Path] = set()
    js_lockfile_dirs: set[Path] = set()
    manifest_dirs: set[Path] = set()
    max_manifest_depth = 0
    max_binary_depth = 0
    max_exclusion_depth = 0
    warnings: list[str] = []
    zero_dep_pyproject_paths: list[str] = []
    has_yocto_bitbake = False
    dts_files_count = 0
    spdx3_files: list[str] = []
    bitbake_recipe_discoveries: list[dict[str, str]] = []
    native_build_scripts_count = 0

    # Symlink cycle protection on root
    root_stat = root.stat()
    visited_inodes.add((root_stat.st_dev, root_stat.st_ino))

    stack: list[tuple[Path, int]] = [(root, 0)]

    while stack:
        current_dir, depth = stack.pop()
        total_dirs_scanned += 1

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
                    dir_depth = depth + 1
                    if name in STANDARD_SAFE_EXCLUSIONS:
                        discovered_safe_dirs.add(name)
                        max_exclusion_depth = max(max_exclusion_depth, dir_depth)
                        continue

                    if name == "node_modules":
                        node_modules_parents.add(current_dir)
                        max_exclusion_depth = max(max_exclusion_depth, dir_depth)
                        continue

                    if name in CONDITIONAL_DIR_CANDIDATES or name in ("sstate-cache", "downloads"):
                        discovered_conditional_dirs.add(name)
                        max_exclusion_depth = max(max_exclusion_depth, dir_depth)

                    if depth < max_depth and inode_key not in visited_inodes:
                        visited_inodes.add(inode_key)
                        stack.append((Path(entry.path), depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    if name == "GROUND_TRUTH_MANIFEST.json":
                        continue
                    total_files_scanned += 1
                    total_workspace_bytes += entry_stat.st_size
                    rel_path = str(Path(entry.path).relative_to(root))
                    size_mb = round(entry_stat.st_size / (1024 * 1024), 2)

                    if name.endswith((".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".apklib")) or ".so." in name:
                        has_standalone_binaries = True

                    if _is_archive(name) or name.endswith((".whl", ".so", ".dll", ".dylib", ".exe", ".bin", ".jar", ".war")) or ".so." in name:
                        max_binary_depth = max(max_binary_depth, depth)

                    if name in KNOWN_LOCKFILES or (
                        name == "status" and ("opkg/" in rel_path.lower() or "dpkg/" in rel_path.lower())
                    ):
                        manifest_dirs.add(current_dir)
                        lf_cnt = _count_lockfile_entries(Path(entry.path), name)
                        try:
                            _, lf_enc = decode_manifest_bytes(Path(entry.path).read_bytes()[:512])
                        except OSError:
                            lf_enc = "utf-8"
                        if lf_enc in ("utf-16-le", "utf-16-be"):
                            warnings.append(
                                f"NON_UTF8_MANIFEST_WARNING: Lockfile '{rel_path}' is encoded in {lf_enc} instead of UTF-8. "
                                "Black Duck Detect expects UTF-8 and may emit null-byte-corrupted BDIO identifiers ('\\u0000') "
                                "causing 0% BOM match rates unless converted to UTF-8."
                            )
                        found_lockfiles.append(
                            {
                                "path": rel_path,
                                "filename": name,
                                "size_mb": size_mb,
                                "depth": depth,
                                "count": lf_cnt,
                                "encoding": lf_enc,
                            }
                        )
                        if depth > max_manifest_depth:
                            max_manifest_depth = depth
                        if name in JS_LOCKFILES:
                            js_lockfile_dirs.add(current_dir)
                    elif name in KNOWN_UNPINNED_MANIFESTS or name.endswith(".csproj"):
                        manifest_dirs.add(current_dir)
                        mf_cnt = _count_manifest_direct_deps(Path(entry.path), name)
                        try:
                            _, mf_enc = decode_manifest_bytes(Path(entry.path).read_bytes()[:512])
                        except OSError:
                            mf_enc = "utf-8"
                        if mf_enc in ("utf-16-le", "utf-16-be"):
                            warnings.append(
                                f"NON_UTF8_MANIFEST_WARNING: Manifest '{rel_path}' is encoded in {mf_enc} instead of UTF-8 "
                                "(common with Windows PowerShell 'pip freeze > requirements.txt'). Default UTF-8 manifest "
                                "parsers emit null-byte-corrupted BDIO identifiers ('\\u0000') when reading UTF-16 files, "
                                f"causing 0% of dependencies in '{rel_path}' to match in the BOM unless converted to UTF-8."
                            )
                        found_unpinned_manifests.append(
                            {
                                "path": rel_path,
                                "filename": name,
                                "size_mb": size_mb,
                                "depth": depth,
                                "count": mf_cnt,
                                "encoding": mf_enc,
                            }
                        )
                        if depth > max_manifest_depth:
                            max_manifest_depth = depth

                        if name == "pyproject.toml":
                            try:
                                toml_text = Path(entry.path).read_text(encoding="utf-8")
                                toml_data = tomllib.loads(toml_text)
                                proj = toml_data.get("project")
                                has_proj_deps = False
                                if isinstance(proj, dict) and "dependencies" in proj:
                                    deps = proj.get("dependencies")
                                    if isinstance(deps, list) and len(deps) > 0:
                                        has_proj_deps = True

                                tool = toml_data.get("tool")
                                has_poetry_deps = False
                                if isinstance(tool, dict):
                                    poetry = tool.get("poetry")
                                    if isinstance(poetry, dict):
                                        pdeps = poetry.get("dependencies")
                                        if isinstance(pdeps, (dict, list)) and len(pdeps) > 0:
                                            has_poetry_deps = True

                                if not has_proj_deps and not has_poetry_deps:
                                    zero_dep_pyproject_paths.append(rel_path)
                            except (tomllib.TOMLDecodeError, OSError, KeyError, TypeError):
                                pass
                        elif name == "go.mod":
                            v_dir = current_dir / "vendor"
                            v_mod_txt = v_dir / "modules.txt"
                            if v_dir.is_dir() and not v_mod_txt.exists():
                                rel_dir = str(current_dir.relative_to(root)) if current_dir != root else "."
                                warnings.append(
                                    f"Go module in '{rel_dir}' has a 'vendor/' directory without 'vendor/modules.txt'. "
                                    "'go list -m -json' will fail with 'go: inconsistent vendoring' unless you set GOFLAGS=-mod=readonly or run 'go mod vendor'."
                                )

                    if name in ("oe-init-build-env", "layer.conf", "bblayers.conf") or name.endswith((".bb", ".bbappend")):
                        has_yocto_bitbake = True
                        if name.endswith(".bb"):
                            m_bb = re.match(r"^([a-zA-Z0-9_.\-+]+)_([0-9]+\.[0-9a-zA-Z_.\-+]+)\.bb$", name)
                            if m_bb:
                                bitbake_recipe_discoveries.append(
                                    {
                                        "path": rel_path,
                                        "file_path": rel_path,
                                        "source_type": "bitbake_recipe",
                                        "type": "bitbake_recipe",
                                        "component": m_bb.group(1),
                                        "version": m_bb.group(2),
                                    }
                                )
                    if name.endswith((".dts", ".dtsi")):
                        dts_files_count += 1
                    if name.endswith((".spdx.json", ".spdx")):
                        try:
                            spdx_head = Path(entry.path).read_bytes()[:2048].decode("utf-8", errors="replace")
                            if "https://spdx.org/rdf/3." in spdx_head or "SPDX-3." in spdx_head or '"3.0.' in spdx_head:
                                spdx3_files.append(rel_path)
                        except OSError:
                            pass

                    if _is_archive(name) and size_mb >= archive_threshold_mb:
                        oversized_archives.append(
                            {
                                "path": rel_path,
                                "filename": name,
                                "size_mb": size_mb,
                                "recommendation": (
                                    "Oversized archive detected (>= 50MB). Consider excluding from signature "
                                    "scanner or utilizing BINARY_SCAN to prevent client timeout and excessive hash load."
                                ),
                            }
                        )

                    # Pareto 80/20 Heuristic Scans:
                    # 1. Dockerfile / Containerfile base image hints
                    if name in ("Dockerfile", "Containerfile") or name.startswith(
                        ("Dockerfile.", "Containerfile.")
                    ):
                        native_build_scripts_count += 1
                        try:
                            doc_lines = (
                                Path(entry.path)
                                .read_text(encoding="utf-8", errors="replace")
                                .splitlines()
                            )
                            for line in doc_lines:
                                sline = line.strip()
                                if not sline or sline.startswith("#"):
                                    continue
                                m_from = re.match(
                                    r"^FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)",
                                    sline,
                                    re.IGNORECASE,
                                )
                                if m_from:
                                    full_img = m_from.group(1).strip()
                                    if full_img.lower() != "scratch":
                                        img_name, img_tag = (
                                            full_img.split(":", 1)
                                            if ":" in full_img
                                            else (full_img, "latest")
                                        )
                                        docker_base_images.append(
                                            {
                                                "path": rel_path,
                                                "image": img_name,
                                                "tag": img_tag,
                                                "full_spec": full_img,
                                            }
                                        )
                        except OSError:
                            pass

                    # 2. C/C++ & Native Build hints
                    if (
                        name in ("CMakeLists.txt", "configure.ac", "meson.build")
                        or name.startswith("Makefile")
                    ):
                        if name.lower() in ("cmakelists.txt", "makefile", "configure.ac", "meson.build"):
                            native_build_scripts_count += 1
                        try:
                            build_text = Path(entry.path).read_text(
                                encoding="utf-8", errors="replace"
                            )
                            for fp in re.findall(r"find_package\s*\(\s*([A-Za-z0-9_]+)", build_text):
                                native_dependencies.append(
                                    {
                                        "path": rel_path,
                                        "type": "cmake_find_package",
                                        "name": fp,
                                    }
                                )
                            for pcm in re.findall(
                                r"pkg_check_modules\s*\([^)]*\b([a-zA-Z0-9_\-]+)\b", build_text
                            ):
                                native_dependencies.append(
                                    {
                                        "path": rel_path,
                                        "type": "pkg_config",
                                        "name": pcm,
                                    }
                                )
                        except OSError:
                            pass
                    elif name.endswith((".c", ".h", ".cpp", ".hpp", ".cc", ".cxx")):
                        try:
                            src_text = Path(entry.path).read_text(
                                encoding="utf-8", errors="replace"
                            )
                            for inc in re.findall(r"#include\s*<([^>]+)>", src_text):
                                inc_lower = inc.lower()
                                matched_pkg: str | None = None
                                for prefix in (
                                    "openssl/",
                                    "curl/",
                                    "boost/",
                                    "libxml/",
                                    "google/protobuf/",
                                    "gtest/",
                                    "cjson/",
                                    "json-c/",
                                    "sodium/",
                                ):
                                    if inc_lower.startswith(prefix):
                                        matched_pkg = prefix.rstrip("/")
                                        break
                                if not matched_pkg:
                                    for kf in (
                                        "zlib.h",
                                        "sqlite3.h",
                                        "pcre.h",
                                        "pcre2.h",
                                        "uv.h",
                                        "jansson.h",
                                        "lz4.h",
                                        "zstd.h",
                                        "expat.h",
                                    ):
                                        if inc_lower == kf:
                                            matched_pkg = kf.removesuffix(".h")
                                            break
                                if matched_pkg:
                                    native_dependencies.append(
                                        {
                                            "path": rel_path,
                                            "type": "header_include",
                                            "header": inc,
                                            "name": matched_pkg,
                                        }
                                    )
                        except OSError:
                            pass

                    # 3. Archive & Shared Library Filename Hints
                    if _is_archive(name) or name.endswith((".whl", ".so", ".dll")) or ".so." in name:
                        m_ver = re.match(
                            r"^([a-zA-Z0-9_\.\-]+?)[-_](\d+\.[0-9a-zA-Z_\.\-]+)\.(jar|war|whl|tgz|tar\.gz|so(?:\.\d+)*|dll)$",
                            name,
                        )
                        if m_ver:
                            binary_version_artifacts.append(
                                {
                                    "path": rel_path,
                                    "filename": name,
                                    "name_hint": m_ver.group(1),
                                    "version_hint": m_ver.group(2),
                                    "size_mb": size_mb,
                                }
                            )
                        else:
                            binary_version_artifacts.append(
                                {
                                    "path": rel_path,
                                    "filename": name,
                                    "name_hint": name,
                                    "version_hint": "unversioned",
                                    "size_mb": size_mb,
                                }
                            )

                    # 4. Legal / Attribution File Inventory
                    if (
                        name.upper().startswith(
                            ("LICENSE", "NOTICE", "COPYING", "THIRD_PARTY", "THIRD-PARTY", "LICENCE")
                        )
                        and Path(name).suffix.lower() in ("", ".txt", ".md", ".rst", ".html", ".htm", ".rtf")
                    ):
                        try:
                            lic_text = Path(entry.path).read_text(
                                encoding="utf-8", errors="replace"
                            )
                            spdx_ids = re.findall(
                                r"SPDX-License-Identifier:\s*([^\n\r]+)", lic_text
                            )
                            cr_notices = re.findall(
                                r"Copyright\s+(?:\(c\)|©)?\s*([^\n\r]+)", lic_text, re.IGNORECASE
                            )
                            attribution_files.append(
                                {
                                    "path": rel_path,
                                    "filename": name,
                                    "spdx_licenses": [s.strip() for s in spdx_ids if s.strip()],
                                    "copyright_notices": [
                                        c.strip()[:80] for c in cr_notices if c.strip()
                                    ],
                                }
                            )
                        except OSError:
                            pass
            except OSError:
                continue

    # Classify safe exclusions vs. conditional exclusions
    safe_exclusions: list[str] = sorted(STANDARD_SAFE_EXCLUSIONS.intersection(discovered_safe_dirs))
    conditional_exclusions: list[dict[str, Any]] = []

    if node_modules_parents:
        unlocked_parents = [p for p in node_modules_parents if p not in js_lockfile_dirs]
        if not unlocked_parents:
            safe_exclusions.append("node_modules")
            safe_exclusions.sort()
        else:
            rel_unlocked = [str(p.relative_to(root)) if p != root else "." for p in unlocked_parents]
            conditional_exclusions.append(
                {
                    "directory": "node_modules",
                    "reason": (
                        "node_modules directory found without a sibling JavaScript lockfile "
                        f"(package-lock.json, yarn.lock, pnpm-lock.yaml) in parent directory: {', '.join(sorted(rel_unlocked))}. "
                        "Excluding node_modules when unpinned or vendored dependencies are present "
                        "may prevent Detect package manager tools from resolving accurate dependencies."
                    ),
                    "actionable_advice": (
                        "If dependencies are fully vendored and unmanaged, keep node_modules included; "
                        "if dependencies are managed via package manager, generate a lockfile first."
                    ),
                }
            )

    for cond_dir in sorted(discovered_conditional_dirs):
        conditional_exclusions.append(
            {
                "directory": cond_dir,
                "reason": (
                    f"Directory '{cond_dir}' commonly contains build artifacts or third-party code. "
                    "Excluding during buildless scans or when vendored dependencies reside here "
                    "can cause false negatives in BOM composition."
                ),
                "actionable_advice": (
                    f"Exclude '{cond_dir}' via --detect.excluded.directories only if binaries/libraries "
                    "are scanned separately or verified build output."
                ),
            }
        )

    # Zero-dependency pyproject advisory
    if zero_dep_pyproject_paths:
        warnings.append(
            f"Zero-dependency pyproject.toml detected in {', '.join(zero_dep_pyproject_paths)}. "
            "Detect Setuptools detector fails with SETUP_TOOLS_NO_DEPENDENCIES when dependencies are omitted. "
            "Adding --detect.excluded.detector.types=SETUPTOOLS to recommended arguments."
        )

    # Pair manifests with sibling lockfiles in the same directory and resolve Maven reactor <modules>
    lockfiles_by_dir_and_name: set[tuple[str, str]] = {
        (str(Path(str(lf.get("path", ""))).parent), str(lf.get("filename", "")))
        for lf in found_lockfiles
    }
    sibling_lockfile_pairs: dict[str, tuple[str, ...]] = {
        "go.mod": ("go.sum",),
        "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"),
        "Cargo.toml": ("Cargo.lock",),
        "pyproject.toml": ("poetry.lock", "uv.lock", "Pipfile.lock"),
        "Pipfile": ("Pipfile.lock",),
        "Gemfile": ("Gemfile.lock",),
        "composer.json": ("composer.lock",),
        "mix.exs": ("mix.lock",),
        "pubspec.yaml": ("pubspec.lock",),
        "Podfile": ("Podfile.lock",),
        "Package.swift": ("Package.resolved",),
    }
    reactor_child_pom_paths: set[str] = set()
    for mf in found_unpinned_manifests:
        mf_path_str = str(mf.get("path", "")).replace("\\", "/")
        mf_parent = str(Path(mf_path_str).parent)
        mf_name = str(mf.get("filename", ""))
        sib_candidates = sibling_lockfile_pairs.get(mf_name, ())
        if any((mf_parent, sib) in lockfiles_by_dir_and_name for sib in sib_candidates):
            mf["pinned_by_sibling_lockfile"] = True
        if mf_name == "pom.xml":
            full_pom = root / mf_path_str
            try:
                pom_elem = safe_parse_xml_bytes(full_pom.read_bytes())
                if pom_elem is not None:
                    mods_found: list[str] = []
                    for elem in pom_elem.iter():
                        t_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        if t_name == "module" and elem.text and elem.text.strip():
                            mod_rel = elem.text.strip().strip("/")
                            child_pom = (
                                f"{mod_rel}/pom.xml"
                                if mf_parent in (".", "")
                                else f"{mf_parent}/{mod_rel}/pom.xml"
                            )
                            mods_found.append(child_pom)
                            reactor_child_pom_paths.add(child_pom)
                    if mods_found:
                        mf["has_maven_modules"] = True
            except OSError:
                pass
    for mf in found_unpinned_manifests:
        if str(mf.get("filename", "")) == "pom.xml":
            mf_path_str = str(mf.get("path", "")).replace("\\", "/")
            if mf_path_str in reactor_child_pom_paths:
                mf["in_maven_reactor"] = True

    # Unpinned manifest accuracy advisory (only for manifests not paired with a sibling lockfile, or needing CLI)
    truly_unpinned = [
        m for m in found_unpinned_manifests if not m.get("pinned_by_sibling_lockfile")
    ]
    if truly_unpinned:
        sample_paths = ", ".join(str(m.get("path", "")) for m in truly_unpinned[:3])
        more_sfx = (
            f", +{len(truly_unpinned) - 3} more"
            if len(truly_unpinned) > 3
            else ""
        )
        warnings.append(
            f"Unpinned package manifests detected ({sample_paths}{more_sfx}). Detect 10 defaults to --detect.accuracy.required=ALL (HIGH), "
            "which will exit with Code 5 (FAILURE_DETECTOR: Accuracy Not Met) or Exit Code 15 (FAILURE_ACCURACY_NOT_MET) "
            "if package manager executables (pip, npm, go, mvn, gradle, cargo, dotnet, bazel, conan, bundle) or installed "
            "environments are missing unless --detect.accuracy.required=NONE is passed for buildless/unbuilt runs."
        )

    # Java runtime check
    java_runtime = detect_java_runtime()
    if not java_runtime["java_found"] and not repo_only:
        warnings.append(
            "No local Java runtime found (checked DETECT_JAVA_PATH, JAVA_HOME, and PATH). "
            "Note: While the downloaded Signature Scanner (scan.cli.zip) bundles its own embedded JRE, "
            "the Detect bootstrapper (detect.sh / detect.jar) does not and requires a host Java 11, 17, or 21 runtime to execute."
        )

    # Available memory calculation
    effective_mem_override = (
        memory_limit_mb_override
        if memory_limit_mb_override is not None
        else (6144 if repo_only else None)
    )
    available_ram_mb, ram_detection_source = detect_available_ram_mb(effective_mem_override)
    scanner_memory_mb, memory_warnings = compute_scanner_memory_mb(
        available_ram_mb, parallel_processors
    )
    for mw in memory_warnings:
        if mw not in warnings:
            warnings.append(mw)

    detect_properties: list[str] = []
    if offline_mode:
        detect_properties.append("--blackduck.offline.mode=true")
        detect_properties.append("--detect.tools=DETECTOR")

    if max_manifest_depth > 0:
        detect_properties.append(f"--detect.detector.search.depth={max_manifest_depth}")

    if zero_dep_pyproject_paths:
        detect_properties.append("--detect.excluded.detector.types=SETUPTOOLS")

    detect_properties.extend(
        [
            f"--detect.blackduck.signature.scanner.memory={scanner_memory_mb}",
            f"--detect.blackduck.signature.scanner.parallel.processors={parallel_processors}",
        ]
    )
    if safe_exclusions:
        detect_properties.append(f"--detect.excluded.directories={','.join(safe_exclusions)}")

    # 1. Empirical -hv: detector search continue for nested subprojects
    has_nested_manifests = False
    for d1 in manifest_dirs:
        for d2 in manifest_dirs:
            if d1 != d2 and (d2.is_relative_to(d1) if hasattr(d2, "is_relative_to") else str(d2).startswith(str(d1) + "/")):
                has_nested_manifests = True
                break
        if has_nested_manifests:
            break

    if has_nested_manifests:
        detect_properties.append("--detect.detector.search.continue=true")
        warnings.append(
            "Nested package manifests detected across parent/child directories. "
            "Detect defaults to --detect.detector.search.continue=false, which skips child detectors "
            "(missing standalone non-reactor subprojects, mixed ecosystems, and buildless nested modules). "
            "Added --detect.detector.search.continue=true to recommended arguments to ensure all nested subprojects are resolved."
        )

    # 2. Empirical -hv: binary scan search depth
    if max_binary_depth > 0:
        detect_properties.append(f"--detect.binary.scan.search.depth={max_binary_depth}")
        warnings.append(
            f"Binary/archive artifacts found at depth {max_binary_depth}. "
            f"Detect defaults --detect.binary.scan.search.depth=0; added "
            f"--detect.binary.scan.search.depth={max_binary_depth} to recommended arguments for BINARY_SCAN."
        )

    # 3. Empirical -hv: excluded directories search depth
    if max_exclusion_depth > 4:
        detect_properties.append(f"--detect.excluded.directories.search.depth={max_exclusion_depth}")
        warnings.append(
            f"Excluded directory found at depth {max_exclusion_depth} (exceeds Detect default depth 4). "
            f"Added --detect.excluded.directories.search.depth={max_exclusion_depth} to recommended arguments "
            "so Signature Scanner excludes deeply nested directories."
        )

    # 4. Scanning Best Practices: Individual File Matching for standalone binaries (.so, .dll, .exe, .bin, .o)
    if has_standalone_binaries:
        detect_properties.append("--detect.blackduck.signature.scanner.individual.file.matching=BINARY")
        warnings.append(
            "Standalone binary files (.so, .dll, .exe, .bin, .o) detected. Since 2020.2.0 "
            "(Scanning Best Practices), Signature Scanner defaults --individualFileMatching=NONE and omits "
            "single-file SHA-1 checksums in generated BDIO archives for standalone binaries. Added "
            "--detect.blackduck.signature.scanner.individual.file.matching=BINARY so standard SCA "
            "servers match unmodified binaries by file checksum."
        )

    # 5. Scanning Best Practices: >1 GB or >10,000 files Signature Scan split recommendation
    if total_files_scanned > 10000 or total_workspace_bytes > 1024 * 1024 * 1024:
        total_gb = round(total_workspace_bytes / (1024**3), 2)
        warnings.append(
            f"MONOREPO_SCAN_SPLIT_RECOMMENDATION: Workspace contains {total_files_scanned} files ({total_gb} GB), "
            "exceeding the Black Duck Scanning Best Practices threshold (>10,000 files or >1 GB) for a single "
            "Signature Scan. Split Signature Scans across top-level subfolders mapped to the same Project Version "
            "via --detect.code.location.name."
        )

    # 6. Scanning Best Practices: Ephemeral CI / commit-ID / build-ID scan path warning
    if re.search(
        r"(?:/tmp/|/var/folders/|build[-_]\d+|job[-_]\d+|/[0-9a-f]{7,40}(?:/|$)|runner[-_]work)",
        str(root),
        re.IGNORECASE,
    ):
        warnings.append(
            f"EPHEMERAL_SCAN_PATH_WARNING: Workspace path '{root}' appears to contain a transient CI build, "
            "commit ID, or temporary directory name. By default, Detect derives code.location.name from "
            "<hostname> + <full path>, which creates a new persisted scan on every CI build, bloating PostgreSQL "
            "and leaving deleted dependencies stuck in the aggregated BOM. Set an explicit static scan name via "
            "--detect.code.location.name=<project>-<branch>-HEAD."
        )

    if has_yocto_bitbake:
        warnings.append(
            "YOCTO_BITBAKE_CALIBRATION_WARNING: OpenEmbedded / Yocto (BitBake) layer or recipes detected. "
            "Black Duck Detect's BitBake detector will NOT run unless '--detect.bitbake.build.env.name=oe-init-build-env' "
            "and '--detect.bitbake.package.names=<target_image>' are explicitly passed in an initialized build shell. "
            "Pass '--detect.bitbake.dependency.types.excluded=BUILD' to exclude host-native build tools (*-native, gcc-cross), "
            "exclude 'sstate-cache,downloads,tmp' from Signature Scanning, or use 'bd-scan-yocto-via-sbom' for unbuilt/SPDX workflows."
        )
    if dts_files_count > 0:
        warnings.append(
            f"DEVICE_TREE_SIGNATURE_WARNING: Found {dts_files_count} hardware Device Tree file(s) (.dts/.dtsi). "
            "In Black Duck Signature and Snippet scans, .dts/.dtsi files frequently match upstream Linux kernel trees "
            "and trigger false-positive GPL-2.0 copyleft alerts on board support packages unless scoped or excluded."
        )
    if spdx3_files:
        warnings.append(
            f"SPDX_3_IMPORT_ERROR_WARNING: SPDX 3.0 file(s) detected ({', '.join(spdx3_files[:3])}). "
            "Black Duck SCA SBOM import currently fails with ERR051017 when ingesting SPDX 3.0.x files; "
            "export SBOMs as SPDX 2.2/2.3 JSON or CycloneDX 1.4-1.6 before uploading."
        )

    has_gradle_manifest = any(
        m.get("filename") in ("build.gradle", "build.gradle.kts") for m in found_unpinned_manifests
    ) or any(lf.get("filename") == "gradle.lockfile" for lf in found_lockfiles)
    if has_gradle_manifest:
        detect_properties.append(
            "--detect.gradle.excluded.configurations=*test*,*Test*,testCompileClasspath,testRuntimeClasspath"
        )
        warnings.append(
            "GRADLE_NON_RUNTIME_CONFIG_WARNING: Gradle build manifests detected. In Detect 11.x+, "
            "Gradle configuration graph traversal pulls non-runtime test configurations into the production BOM by default. "
            "Added --detect.gradle.excluded.configurations=*test*,*Test*,testCompileClasspath,testRuntimeClasspath to recommended arguments."
        )

    if docker_base_images:
        warnings.append(
            f"DOCKER_INSPECTOR_EOL_WARNING: Dockerfile/Containerfile detected ({len(docker_base_images)} base image declaration(s)). "
            "Black Duck Docker Inspector (--detect.tools=DOCKER / detect-docker-inspector.jar) reached End-of-Life in July 2026 "
            "and fails with exit code 255 on modern container layers. Use --detect.tools=CONTAINER_SCAN with "
            "--detect.container.scan.file.path=<image.tar> instead of --detect.tools=DOCKER."
        )

    expected_bom_baseline = build_expected_bom_baseline(
        root=root,
        lockfiles=found_lockfiles,
        manifests=found_unpinned_manifests,
    )

    exp_min_total = int(expected_bom_baseline.get("expected_min_total_components", 0))
    exp_locs = int(expected_bom_baseline.get("expected_code_locations", 0))
    if total_files_scanned > 2000 or exp_min_total > 200 or exp_locs > 10 or oversized_archives:
        warnings.append(
            f"SCASS_ASYNC_TIMEOUT_WARNING: High-volume workspace ({total_files_scanned} files, >= {exp_min_total} expected BOM components "
            f"across {exp_locs} code locations). In Black Duck 2025.x-2026.x (SCASS / Matching-as-a-Service), Detect exits 0 immediately "
            "after upload while server-side BOM computation can queue or time out with ERR021002. Pass --detect.wait.for.results=true "
            "(and --detect.report.timeout=1800) if CI gates require confirmed BOM completion."
        )

    catalog = load_pareto_catalog(custom_catalog_path)
    deep_packet_inspection = inspect_archives_and_binaries(
        root, catalog=catalog, max_depth=max_depth, max_workers=max_workers
    )
    if bitbake_recipe_discoveries:
        deep_packet_inspection.setdefault("internal_manifest_discoveries", []).extend(
            bitbake_recipe_discoveries
        )

    for smell in deep_packet_inspection.get("disaster_smells", []):
        loc = smell.get("location") or smell.get("file_path", "")
        warnings.append(
            f"BLIND-SPOT TRAP [{smell.get('severity', 'HIGH')}]: {smell.get('name')} detected in {loc} - {smell.get('description', '')}"
        )

    pareto_hints = {
        "docker_base_images": docker_base_images,
        "native_dependencies": native_dependencies,
        "binary_version_artifacts": binary_version_artifacts,
        "attribution_files": attribution_files,
        "native_build_scripts_count": native_build_scripts_count,
    }

    total_workspace_mb = round(total_workspace_bytes / (1024 * 1024), 2)
    report: dict[str, Any] = {
        "workspace_root": str(root),
        "total_dirs_scanned": total_dirs_scanned,
        "total_files_scanned": total_files_scanned,
        "total_workspace_bytes": total_workspace_bytes,
        "total_workspace_mb": total_workspace_mb,
        "max_manifest_depth": max_manifest_depth,
        "lockfiles": found_lockfiles,
        "unpinned_manifests": found_unpinned_manifests,
        "safe_exclusions": safe_exclusions,
        "conditional_exclusions": conditional_exclusions,
        "oversized_archives": oversized_archives,
        "expected_bom_baseline": expected_bom_baseline,
        "pareto_hints": pareto_hints,
        "deep_packet_inspection": deep_packet_inspection,
        "memory": {
            "available_ram_mb": available_ram_mb,
            "detection_source": ram_detection_source,
            "parallel_processors": parallel_processors,
            "recommended_scanner_memory_mb": scanner_memory_mb,
            "warnings": memory_warnings,
        },
        "java_runtime": java_runtime,
        "warnings": warnings,
        "recommended_detect_arguments": detect_properties,
    }

    # Inspect build execution risks (Jia Tan xz / Lazarus guard)
    build_risks = inspect_build_execution_risks(root, max_depth=max_depth)
    report["build_execution_risks"] = build_risks
    if build_risks.get("verdict") == "CRITICAL_UNTRUSTED_EXECUTION_RISK":
        b_findings = list(build_risks.get("findings", []))
        findings_count = len(b_findings)
        sample_b = ", ".join(
            f"{f.get('id', 'RISK')} in {f.get('file', 'unknown')}" for f in b_findings[:3]
        )
        more_b = f", +{findings_count - 3} more" if findings_count > 3 else ""
        warnings.append(
            f"CRITICAL: Untrusted build execution risk detected in workspace ({findings_count} finding(s): {sample_b}{more_b}). "
            "Running package manager detectors with active build scripts may execute malicious code."
        )

    report["project_archetypes"] = infer_project_archetypes(report)
    for arch in report["project_archetypes"]:
        for aw in arch.get("warnings", []):
            if aw not in report["warnings"]:
                report["warnings"].append(aw)

    report["actionable_vulnerabilities"] = match_pareto_vulnerabilities(
        report, custom_kb_path=custom_catalog_path
    )
    report["actionable_license_risks"] = match_pareto_license_risks(
        report, custom_kb_path=custom_catalog_path
    )

    # 7. Multi-Instance Aggregator & Black Duck Web UI 10-Location Display Cap Warning
    instance_locations: dict[str, set[str]] = {}
    for imd in deep_packet_inspection.get("internal_manifest_discoveries", []):
        cname = str(imd.get("component") or imd.get("name") or "").strip()
        cver = str(imd.get("version") or "").strip()
        loc = str(imd.get("archive_path") or imd.get("file_path") or "").strip()
        if cname and loc:
            key = f"{cname}:{cver}" if cver else cname
            instance_locations.setdefault(key, set()).add(loc)
    for bsd in deep_packet_inspection.get("binary_symbol_discoveries", []):
        cname = str(bsd.get("component") or "").strip()
        cver = str(bsd.get("version") or "").strip()
        loc = str(bsd.get("file_path") or "").strip()
        if cname and loc:
            key = f"{cname}:{cver}" if cver else cname
            instance_locations.setdefault(key, set()).add(loc)
    for smell in deep_packet_inspection.get("disaster_smells", []):
        sname = str(smell.get("id") or smell.get("name") or "").strip()
        loc = str(smell.get("location") or smell.get("file_path") or "").strip()
        if sname and sname != "EMBEDDED_PRIVATE_KEY_HEADER" and loc:
            # Strip inner !/ entry suffix so each physical JAR/file counts once per location
            phys_loc = loc.split("!/")[0]
            instance_locations.setdefault(sname, set()).add(phys_loc)
    for bva in binary_version_artifacts:
        nhint = str(bva.get("name_hint") or "").strip()
        vhint = str(bva.get("version_hint") or "").strip()
        loc = str(bva.get("path") or "").strip()
        if nhint and vhint and vhint != "unversioned" and loc:
            key = f"{nhint}:{vhint}"
            instance_locations.setdefault(key, set()).add(loc)

    multi_instance_components: list[dict[str, Any]] = []
    for comp_key, locs in sorted(instance_locations.items()):
        if len(locs) > 1:
            sorted_locs = sorted(locs)
            exceeds_cap = len(sorted_locs) > 10
            multi_instance_components.append(
                {
                    "component": comp_key,
                    "instance_count": len(sorted_locs),
                    "exceeds_bd_ui_10_instance_cap": exceeds_cap,
                    "locations": sorted_locs,
                }
            )
            if exceeds_cap:
                report["warnings"].append(
                    f"MULTI_INSTANCE_UI_CAP_WARNING: '{comp_key}' was discovered in {len(sorted_locs)} separate "
                    "locations across the source tree, exceeding the Black Duck SCA Web UI default 10-location "
                    f"display cap. Remediating only the 10 paths shown in the Web UI will leave {len(sorted_locs) - 10} "
                    f"instance(s) unpatched in production. All {len(sorted_locs)} local paths: {', '.join(sorted_locs)}"
                )
    report["multi_instance_components"] = multi_instance_components

    if git_diff_base_ref:
        report["git_diff_analysis"] = analyze_git_diff(root, git_diff_base_ref)

    arg_plan = merge_existing_detect_args(detect_properties, existing_detect_args)
    vendor_lic_count = sum(
        1
        for a in attribution_files
        if str(a.get("path", "")).replace("\\", "/").startswith("vendor/")
    )
    if vendor_lic_count > 0:
        arg_plan["optional_coverage_tweaks"].append(
            {
                "argument": "--detect.blackduck.signature.scanner.license.search=true",
                "property": "--detect.blackduck.signature.scanner.license.search",
                "unlocks": (
                    f"Scans {vendor_lic_count} vendored legal/attribution notice(s) under vendor/ "
                    "(default is false, which skips embedded license text inside vendored source trees)."
                ),
                "tradeoff": "Increases Signature Scanner text-search time across vendored source files.",
            }
        )
    effective_detect_props = list(arg_plan["effective_recommended_arguments"])
    report["recommended_detect_arguments"] = effective_detect_props
    report["detect_argument_plan"] = arg_plan

    report["scan_input_provenance"] = compute_workspace_merkle_provenance(
        root, effective_detect_props, max_depth=max_depth, max_workers=max_workers
    )
    report["file_accounting"] = build_file_accounting_and_ledger(report)
    report["advisory_notice"] = BD_CONFIRMATION_ADVISORY
    report["executive_summary"] = build_executive_summary(report)

    return report


def generate_ai_brief_markdown(report: PrescanReport | dict[str, Any]) -> str:
    """Generate a single, DLP-sanitized, token-budgeted AI-first Markdown report (LLM_INGESTION_REPORT.md)."""
    ws_root_str = str(report.get("workspace_root", "workspace"))
    ws_name = Path(ws_root_str).name
    prov = report.get("scan_input_provenance") or {}
    multilayer_sig = str(prov.get("multilayer_codebase_signature", "unknown"))
    topo_sha256 = str(prov.get("topology_skeleton_sha256", "unknown"))
    tree_merkle = str(prov.get("workspace_tree_merkle_sha256", "unknown"))
    dep_merkle = str(prov.get("dependency_inputs_merkle_sha256", "unknown"))
    cfg_sha256 = str(prov.get("effective_detect_config_sha256", "unknown"))
    bd_ui_arg = str(prov.get("bd_ui_version_notes_arg", ""))

    vulns = list(report.get("actionable_vulnerabilities") or [])
    lic_risks = list(report.get("actionable_license_risks") or [])
    dpi = report.get("deep_packet_inspection") or {}
    smells = list(dpi.get("disaster_smells") or [])
    raw_warnings = list(report.get("warnings") or [])
    warnings = [
        sanitize_line(str(w).replace(ws_root_str, f"<WORKSPACE_ROOT>/{ws_name}"))
        for w in raw_warnings
    ]
    rec_args = list(report.get("recommended_detect_arguments") or [])
    arg_plan = report.get("detect_argument_plan") or merge_existing_detect_args(rec_args)
    acct = report.get("file_accounting") or build_file_accounting_and_ledger(report)
    base = report.get("expected_bom_baseline") or {}
    verif = report.get("detect_verification")

    total_ws_mb = report.get("total_workspace_mb", 0.0)
    dep_inputs_count = int(prov.get("dependency_inputs_hashed_count") or 0)
    files_hashed_count = int(prov.get("files_hashed_count") or report.get("total_files_scanned") or 0)
    files_disc_count = int(prov.get("files_discovered_count") or report.get("total_files_scanned") or 0)
    cov_pct = prov.get("coverage_pct", 100.0)
    archives_inspected_count = len(dpi.get("archive_metadata") or []) + len(dpi.get("tarball_metadata") or [])
    binaries_inspected_count = len(dpi.get("binary_inspection") or [])
    internal_manifests_count = (
        len(dpi.get("internal_manifest_discoveries") or [])
        + sum(
            len(a.get("maven_coordinates") or [])
            + (1 if a.get("manifest_attributes") else 0)
            for a in (dpi.get("archive_metadata") or [])
        )
        + sum(
            1
            for t in (dpi.get("tarball_metadata") or [])
            if t.get("top_level_prefix")
        )
    )
    ph = report.get("pareto_hints") or {}
    attr_files_count = len(ph.get("attribution_files") or [])
    native_scripts_count = int(ph.get("native_build_scripts_count") or 0)
    all_manifests = list(report.get("unpinned_manifests") or [])
    truly_unpinned_count = sum(1 for m in all_manifests if not m.get("pinned_by_sibling_lockfile"))
    paired_manifests_count = len(all_manifests) - truly_unpinned_count
    manifest_pass1_str = (
        f"`{paired_manifests_count}` lockfile-paired manifest(s), `{truly_unpinned_count}` unpinned manifest(s)"
        if paired_manifests_count > 0
        else f"`{truly_unpinned_count}` unpinned manifest(s)"
    )

    b1 = acct.get("bucket_1_excluded_dirs") or {}
    b2a = acct.get("bucket_2a_actionable_l1_files") or {}
    b2b = acct.get("bucket_2b_provenance_only_l2_files") or {}
    b3 = acct.get("bucket_3_early_stop_unhashed_files") or {}
    ledger = list(acct.get("actionable_files_ledger") or [])

    lines: list[str] = [
        "---",
        "schema: sca-ops-ai-brief/v1",
        f"workspace_name: {ws_name}",
        "dlp_sanitized: true",
        "host_paths_stripped: true",
        f"multilayer_codebase_signature: {multilayer_sig}",
        f"topology_skeleton_sha256: {topo_sha256}",
        f"workspace_tree_merkle_sha256: {tree_merkle}",
        f"dependency_inputs_merkle_sha256: {dep_merkle}",
        f"effective_detect_config_sha256: {cfg_sha256}",
        f"coverage_pct: {cov_pct}",
        f"early_stop_triggered: {str(bool(prov.get('early_stop_triggered', False))).lower()}",
        f"total_dirs_scanned: {report.get('total_dirs_scanned', 0)}",
        f"total_files_scanned: {report.get('total_files_scanned', 0)}",
        f"total_workspace_mb: {total_ws_mb}",
        f"bucket_1_excluded_dirs_count: {b1.get('count', 0)}",
        f"bucket_2a_actionable_l1_files_count: {b2a.get('count', dep_inputs_count)}",
        f"bucket_2b_provenance_only_l2_files_count: {b2b.get('count', 0)}",
        f"bucket_3_early_stop_unhashed_files_count: {b3.get('count', 0)}",
        f"dependency_inputs_hashed_count: {dep_inputs_count}",
        f"lockfiles_count: {len(report.get('lockfiles') or [])}",
        f"lockfile_paired_manifests_count: {paired_manifests_count}",
        f"unpinned_manifests_count: {truly_unpinned_count}",
        f"expected_min_bom_components: {base.get('expected_min_total_components', 0)}",
        f"actionable_vulnerabilities_count: {len(vulns)}",
        f"actionable_license_risks_count: {len(lic_risks)}",
        f"blind_spot_traps_count: {len(smells)}",
        f"operational_warnings_count: {len(warnings)}",
        "---",
        "",
        f"# AI-First SCA Pre-Flight, Provenance & Risk Brief (`{ws_name}`)",
        "",
        "> **LLM Ingestion Instructions**: Point your enterprise AI assistant (Copilot, Claude, ChatGPT Enterprise) at this single file. All host paths are stripped to relative workspace paths and all integer totals are pre-computed in the YAML header above.",
        "",
        "## 1. Workspace Input & Config Hashes (L0 / L1 / L2 / CFG)",
        "",
        "| Provenance Layer | SHA-256 Digest / Signature | Operational Meaning |",
        "| :--- | :--- | :--- |",
        f"| **Compact Workspace Signature** | `{multilayer_sig}` | Single-line composite fingerprint (`L0` Folder Tree + `L1` Dependency Inputs + `L2` Source Tree + `CFG` Detect Flags + depth/coverage watermark). |",
        f"| **Layer 0: Folder Tree Hash (`L0`)** | `{topo_sha256}` | Zero-file-read breadth-first directory skeleton (relative folders, file counts, extension mix, byte totals). Instantaneous across monorepos. |",
        f"| **Layer 1: Dependency Input Hash (`L1`)** | `{dep_merkle}` | Multithreaded hash of 100% of {dep_inputs_count} dependency-bearing inputs (manifests, lockfiles, Dockerfiles, and sparse-fingerprinted archives/binaries). If unchanged across commits, BOM inputs are identical. |",
        f"| **Layer 2: Source File Hash (`L2`)** | `{tree_merkle}` | Breadth-first multithreaded source digest covering {files_hashed_count}/{files_disc_count} files ({cov_pct}%, max depth {prov.get('max_depth_reached', 0)}). |",
        f"| **Effective Detect Config (`CFG`)** | `{cfg_sha256}` | Canonical digest of the sorted recommended Detect CLI properties. |",
        f"| **SCA Web UI Provenance Flag** | `{bd_ui_arg}` | Pass this flag to Detect to stamp exact input/config provenance into the Project Version Notes UI. |",
        "",
        f"### What `sca-prescan` Actually Inspected (`{report.get('total_dirs_scanned', 0)}` dirs, `{report.get('total_files_scanned', 0)}` files, `{total_ws_mb}` MB)",
        f"- **Pass 1 (Directory, Manifest & Encoding Walk)**: Traversed `{report.get('total_dirs_scanned', 0)}` directories and `{report.get('total_files_scanned', 0)}` files (`{total_ws_mb}` MB), classified `{len(report.get('lockfiles') or [])}` lockfile(s), {manifest_pass1_str}, and `{native_scripts_count}` native/container build script(s), verified manifest character encodings (`UTF-8` vs `UTF-16LE/BE`), and measured max directory depths for detectors, binaries, and exclusions.",
        f"- **Pass 2 (In-Memory Archive, Binary & Header Inspection)**: Inspected `{archives_inspected_count}` archive(s) and `{binaries_inspected_count}` compiled binary file(s) in memory without disk extraction, parsed `{internal_manifests_count}` internal version headers/manifests (`META-INF/maven`, `MANIFEST.MF`, `PKG-INFO`, C `zlib.h`/`opensslv.h`/`VERSION.dat`), and checked `{attr_files_count}` legal/SPDX attribution file(s).",
        f"- **Pass 3 (3-Layer Cryptographic Provenance Hashing)**: Hashed `{report.get('total_dirs_scanned', 0)}` directory skeletons (`L0`, 0 file reads), 100% of `{dep_inputs_count}` dependency-bearing inputs (`L1`), and `{files_hashed_count}/{files_disc_count}` source files (`L2`, `{cov_pct}%` coverage).",
        "- **Pass 4 (100% Offline Version-Range & Rugpull Matching)**: Evaluated all discovered `(component, version)` pairs offline against the built-in Pareto CVE (`pareto_vuln_kb.json`) and license-rugpull (`pareto_license_kb.json`) catalogs (`0` outbound network calls).",
        "",
        f"### File & Byte Disposition Accounting (`{b2a.get('count', 0)} + {b2b.get('count', 0)} + {b3.get('count', 0)} = {report.get('total_files_scanned', 0)}` files)",
        "",
        "| Bucket | Count / Size | What `sca-prescan` Did With These Objects | What Default Detect (`depth=0`) Does With Them |",
        "| :--- | :---: | :--- | :--- |",
        f"| **Bucket 1: Excluded Non-Shipping Dirs** | `{b1.get('count', 0)}` dir(s) | {b1.get('prescan_action', '')} | {b1.get('default_detect_action', '')} |",
        f"| **Bucket 2a: Actionable BOM, Vuln & Calibration Files (`L1`)** | `{b2a.get('count', 0)}` file(s) (`{b2a.get('size_mb', 0.0)}` MB) | {b2a.get('prescan_action', '')} | {b2a.get('default_detect_action', '')} |",
        f"| **Bucket 2b: Source & Doc Provenance Only (`L2 - L1`)** | `{b2b.get('count', 0)}` file(s) (`{b2b.get('size_mb', 0.0)}` MB) | {b2b.get('prescan_action', '')} | {b2b.get('default_detect_action', '')} |",
        f"| **Bucket 3: Unhashed Beyond Monorepo Early-Stop Cap** | `{b3.get('count', 0)}` file(s) | {b3.get('prescan_action', '')} | {b3.get('default_detect_action', '')} |",
        "",
    ]

    if ledger:
        lines.extend(
            [
                f"### Actionable Files Processed in Bucket 2a (`{len(ledger)}` file(s): `sca-prescan` vs. Default Detect)",
                "",
                "| File Path (Depth) | Bucket Sub-Type | What `sca-prescan` Extracted & Did | What Default Detect (`depth=0`) Does |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for row in ledger[:50]:
            lines.append(
                f"| `{row.get('path')}` (`d={row.get('depth')}`) | `{row.get('bucket')}` | {row.get('prescan_action')} | {row.get('default_detect_action')} |"
            )
        if len(ledger) > 50:
            lines.append(
                f"| _... and {len(ledger) - 50} more Bucket 2a file(s) omitted for brevity_ | | | |"
            )
        lines.append("")

    baseline_safe_args = list(arg_plan.get("baseline_safe_arguments") or [])
    optional_tweaks = list(arg_plan.get("optional_coverage_tweaks") or [])
    already_cfg = list(arg_plan.get("already_configured_by_customer") or [])
    add_notes = list(arg_plan.get("additive_merge_notes") or [])

    lines.extend(
        [
            "## 2. Tuned Detect CLI Invocation & Configuration Calibration",
            "",
            "### 2.1 Baseline Safe Invocation (Default Detect Policy + Safe Runner Hygiene)",
            "> **Stated Vendor Policy**: Run Detect with default settings (`--detect.tools=ALL`, `--detect.detector.search.depth=0`) first for predictable scan speed, adding only safe runner memory sizing, `.git`/`.venv` directory exclusions, and the Project Version Notes provenance stamp below. Comma-separated properties (`--detect.excluded.directories`, `--detect.tools`) should always be **additively concatenated** to any existing pipeline values.",
            "",
            "```bash",
            "java -jar detect.jar \\",
        ]
    )
    for idx, arg in enumerate(baseline_safe_args):
        lines.append(f"  {arg}" + (" \\" if idx < len(baseline_safe_args) - 1 or bd_ui_arg else ""))
    if bd_ui_arg:
        lines.append(f"  '{bd_ui_arg}'")
    lines.append("```")
    lines.append("")

    if optional_tweaks:
        lines.extend(
            [
                "### 2.2 Optional Fuller-BOM & Buildless Tweaks (Trade-Offs Explained)",
                "",
                "| Optional Detect Flag | What Hidden Files / Failures It Unlocks in This Repo | Performance & BOM Trade-Off |",
                "| :--- | :--- | :--- |",
            ]
        )
        for tw in optional_tweaks:
            lines.append(
                f"| `{tw.get('argument')}` | {tw.get('unlocks')} | {tw.get('tradeoff')} |"
            )
        lines.append("")

    if already_cfg or add_notes:
        lines.append("### 2.3 Customer Existing-Config Alignment & Additive Merges")
        for ac in already_cfg:
            lines.append(f"- **Already Configured**: `{ac}`")
        for an in add_notes:
            lines.append(f"- **Additive Merge**: {an}")
        lines.append("")

    lines.extend(
        [
            "### Operational & Calibration Signals",
        ]
    )
    if warnings:
        for w in warnings:
            lines.append(f"- {w}")
    else:
        lines.append("- None (workspace cleanly calibrated).")

    lines.extend(
        [
            "",
            "## 3. Expected BOM Baseline & Post-Scan Completeness Gate",
            "",
            f"- **Expected Minimum BOM Components**: `>= {base.get('expected_min_total_components', 0)}` across `{base.get('expected_code_locations', 0)}` code location(s)",
            f"- **Baseline Summary**: {base.get('summary_statement', 'N/A')}",
        ]
    )
    active_subs = [s for s in base.get("subprojects", []) if s.get("expected_min_components", 0) > 0]
    for sub in active_subs[:20]:
        lines.append(
            f"  - `[{sub.get('ecosystem')}] {sub.get('directory')}`: `>= {sub.get('expected_min_components')}` component(s) ({sub.get('reason')})"
        )
    if len(active_subs) > 20:
        lines.append(f"  - _... and {len(active_subs) - 20} more subproject(s) omitted for brevity_")
    if verif:
        verif_summary = sanitize_line(
            str(verif.get("summary", "")).replace(ws_root_str, f"<WORKSPACE_ROOT>/{ws_name}")
        )
        lines.extend(
            [
                f"- **Post-Scan BDIO Verdict**: `{verif.get('verdict')}`",
                f"- **Observed BDIO Components**: `{verif.get('actual_total_components')}` (Expected Baseline: `>= {verif.get('expected_min_total_components')}`)",
                f"- **Verification Summary**: {verif_summary}",
            ]
        )

    lines.extend(
        [
            "",
            f"## 4. Actionable High-Severity Vulnerabilities ({len(vulns)})",
            "",
            "> **Scope Note (Free 5-Second Worst-of-the-Worst Check, Not a Full SCA Database)**: `sca-prescan`'s main job is tuning your Detect CLI flags and catching BOM blind spots before your scan starts. As a free 5-second side dish while walking the tree, it also checks an offline hit-list (`3,910` version/range rules + `32` unpatched code-snippet and shaded-bytecode patterns) focused strictly on **must-catch disasters**: actively exploited **CISA-KEV** flaws, **recent 2025-2026 critical advisories** (including pre-NVD `GHSA`/`GO`/`RUSTSEC` advisories), `CVSS 9.8-10.0` RCEs, and major open-source license rugpulls (`AGPL-3.0`, `SSPL-1.0`, `RSALv2`, `BSL-1.1`). When version strings are missing or stripped from shaded uber-JARs, it checks source files and in-memory `.class` constant pools directly (`[UNPATCHED-SNIPPET-VERIFIED]` / `[PATCH-GUARD-DETECTED]`). Always rely on your full SCA server and AST/SAST tools for comprehensive vulnerability coverage.",
            "",
        ]
    )
    if vulns:
        lines.extend(
            [
                "| CVE ID | CVSS | KEV | Component & Version | Evidence Source | Actionable Remedy |",
                "| :--- | :---: | :---: | :--- | :--- | :--- |",
            ]
        )
        for v in vulns:
            kev = "YES" if v.get("cisa_kev") else "NO"
            lines.append(
                f"| `{v.get('cve_id')}` | {v.get('cvss')} | {kev} | `{v.get('component')} {v.get('installed_version')}` | `{v.get('evidence_source')}` | {v.get('actionable_remedy')} |"
            )
    else:
        lines.append("_No high-severity Pareto vulnerabilities matched._")

    lines.extend(
        [
            "",
            f"## 5. High-Severity License & Rugpull Risks ({len(lic_risks)})",
            "",
        ]
    )
    if lic_risks:
        lines.extend(
            [
                "| Rule ID | Severity | Component & Version | License / Transition | Evidence Source | Safe Version / Remedy |",
                "| :--- | :---: | :--- | :--- | :--- | :--- |",
            ]
        )
        for lr in lic_risks:
            prev = f" (from {lr['previous_license']})" if lr.get("previous_license") else ""
            lines.append(
                f"| `{lr.get('rule_id')}` | `{lr.get('severity')}` | `{lr.get('component')} {lr.get('installed_version')}` | `{lr.get('license_id')}`{prev} | `{lr.get('evidence_source')}` | {lr.get('safe_version_hint')} |"
            )
    else:
        lines.append("_No high-severity license or rugpull risks matched._")

    rendered = "\n".join(lines)
    rendered = (
        rendered.replace("Black Duck SCA", "SCA")
        .replace("In Black Duck ", "In SCA Server ")
        .replace("Black Duck ", "")
    )
    return rendered.replace("\u2014", "-").replace("\u2013", "-")


def generate_ai_brief_html(report: PrescanReport | dict[str, Any]) -> str:
    """Generate a self-contained semantic HTML5 report with embedded JSON-LD for browser + LLM parity."""
    ws_root_str = str(report.get("workspace_root", "workspace"))
    ws_name = Path(ws_root_str).name
    prov = report.get("scan_input_provenance") or {}
    acct = report.get("file_accounting") or build_file_accounting_and_ledger(report)
    rec_args = list(report.get("recommended_detect_arguments") or [])
    arg_plan = report.get("detect_argument_plan") or merge_existing_detect_args(rec_args)
    vulns = list(report.get("actionable_vulnerabilities") or [])
    lic_risks = list(report.get("actionable_license_risks") or [])
    raw_warnings = list(report.get("warnings") or [])
    warnings = [
        sanitize_line(str(w).replace(ws_root_str, f"<WORKSPACE_ROOT>/{ws_name}"))
        for w in raw_warnings
    ]
    base = report.get("expected_bom_baseline") or {}

    b1 = acct.get("bucket_1_excluded_dirs") or {}
    b2a = acct.get("bucket_2a_actionable_l1_files") or {}
    b2b = acct.get("bucket_2b_provenance_only_l2_files") or {}
    b3 = acct.get("bucket_3_early_stop_unhashed_files") or {}
    ledger = list(acct.get("actionable_files_ledger") or [])

    # Build valid Schema.org TechArticle JSON-LD and full machine-readable JSON copy
    schema_ld_obj = {
        "@context": "https://schema.org",
        "@type": "TechArticle",
        "headline": f"SCA Pre-Flight, File Disposition & Risk Brief ({ws_name})",
        "description": (
            f"Deterministic SCA pre-flight audit for {ws_name}: "
            f"{report.get('total_dirs_scanned', 0)} dirs, {report.get('total_files_scanned', 0)} files "
            f"({report.get('total_workspace_mb', 0.0)} MB), {b2a.get('count', 0)} Bucket 2a actionable inputs."
        ),
        "identifier": str(prov.get("multilayer_codebase_signature", "")),
    }
    schema_ld_str = json.dumps(schema_ld_obj, indent=2).replace("</script>", "<\\/script>")

    sanitized_json_obj = {
        "schema": "sca-ops-ai-brief/v1",
        "workspace_name": ws_name,
        "dlp_sanitized": True,
        "host_paths_stripped": True,
        "scan_input_provenance": prov,
        "file_accounting": acct,
        "detect_argument_plan": arg_plan,
        "expected_bom_baseline": base,
        "actionable_vulnerabilities": vulns,
        "actionable_license_risks": lic_risks,
        "operational_warnings": warnings,
    }
    embedded_json_str = json.dumps(sanitized_json_obj, indent=2).replace("</script>", "<\\/script>")

    def _fmt_code(text: str) -> str:
        parts = text.split("`")
        out: list[str] = []
        for idx_p, part in enumerate(parts):
            if idx_p % 2 == 1:
                out.append(f"<code>{html.escape(part)}</code>")
            else:
                out.append(html.escape(part))
        return "".join(out)

    def _badge(text: str) -> str:
        esc = _fmt_code(text)
        if "SILENTLY IGNORED" in text or "SILENTLY CORRUPTED" in text or "FAILS" in text or "BLIND-SPOT TRAP" in text:
            return f'<span class="badge badge-danger">{esc}</span>'
        return esc

    ledger_rows_html = []
    for row in ledger:
        ledger_rows_html.append(
            f"<tr>"
            f"<td><code>{html.escape(str(row.get('path', '')))}</code> <span class=\"muted\">(d={row.get('depth', 0)})</span></td>"
            f"<td><span class=\"badge badge-info\">{html.escape(str(row.get('bucket', '')))}</span></td>"
            f"<td>{_fmt_code(str(row.get('prescan_action', '')))}</td>"
            f"<td>{_badge(str(row.get('default_detect_action', '')))}</td>"
            f"</tr>"
        )

    tweak_rows_html = []
    for tw in arg_plan.get("optional_coverage_tweaks") or []:
        tweak_rows_html.append(
            f"<tr>"
            f"<td><code>{html.escape(str(tw.get('argument', '')))}</code></td>"
            f"<td>{_fmt_code(str(tw.get('unlocks', '')))}</td>"
            f"<td>{_fmt_code(str(tw.get('tradeoff', '')))}</td>"
            f"</tr>"
        )

    vuln_rows_html = []
    for v in vulns:
        kev = '<span class="badge badge-danger">YES (KEV)</span>' if v.get("cisa_kev") else "NO"
        vuln_rows_html.append(
            f"<tr>"
            f"<td><code>{html.escape(str(v.get('cve_id', '')))}</code></td>"
            f"<td><strong>{html.escape(str(v.get('cvss', '')))}</strong></td>"
            f"<td>{kev}</td>"
            f"<td><code>{html.escape(str(v.get('component', '')))} {html.escape(str(v.get('installed_version', '')))}</code></td>"
            f"<td><code>{html.escape(str(v.get('evidence_source', '')))}</code></td>"
            f"<td>{_fmt_code(str(v.get('actionable_remedy', '')))}</td>"
            f"</tr>"
        )

    lic_rows_html = []
    for lr in lic_risks:
        lic_rows_html.append(
            f"<tr>"
            f"<td><code>{html.escape(str(lr.get('rule_id', '')))}</code></td>"
            f"<td><span class=\"badge badge-warn\">{html.escape(str(lr.get('severity', '')))}</span></td>"
            f"<td><code>{html.escape(str(lr.get('component', '')))} {html.escape(str(lr.get('installed_version', '')))}</code></td>"
            f"<td><code>{html.escape(str(lr.get('license_id', '')))}</code></td>"
            f"<td><code>{html.escape(str(lr.get('evidence_source', '')))}</code></td>"
            f"<td>{_fmt_code(str(lr.get('safe_version_hint', '')))}</td>"
            f"</tr>"
        )

    baseline_cmd_lines = ["java -jar detect.jar \\"]
    b_args = list(arg_plan.get("baseline_safe_arguments") or [])
    bd_ui_arg = str(prov.get("bd_ui_version_notes_arg", ""))
    for idx, a in enumerate(b_args):
        baseline_cmd_lines.append(f"  {a}" + (" \\" if idx < len(b_args) - 1 or bd_ui_arg else ""))
    if bd_ui_arg:
        baseline_cmd_lines.append(f"  '{bd_ui_arg}'")
    baseline_cmd_str = html.escape("\n".join(baseline_cmd_lines))

    warnings_li = "\n".join(f"<li>{_fmt_code(w)}</li>" for w in warnings) or "<li>None</li>"

    active_subs = [s for s in base.get("subprojects", []) if s.get("expected_min_components", 0) > 0]
    subs_li_list = [
        f"<li><code>[{html.escape(str(s.get('ecosystem', '')))}] {html.escape(str(s.get('directory', '')))}</code>: "
        f"<code>&gt;= {html.escape(str(s.get('expected_min_components', 0)))}</code> component(s) ({_fmt_code(str(s.get('reason', '')))})</li>"
        for s in active_subs[:20]
    ]
    if len(active_subs) > 20:
        subs_li_list.append(f"<li><em>... and {len(active_subs) - 20} more subproject(s) omitted for brevity</em></li>")
    subs_ul_html = f"<ul>{''.join(subs_li_list)}</ul>" if subs_li_list else ""

    raw_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SCA Pre-Flight &amp; File Disposition Report ({html.escape(ws_name)})</title>
  <script type="application/ld+json">
{schema_ld_str}
  </script>
  <script type="application/json" id="sca-ops-ai-brief-json">
{embedded_json_str}
  </script>
  <style>
    :root {{
      --bg: #f8fafc; --card: #ffffff; --text: #0f172a; --muted: #475569;
      --border: #e2e8f0; --accent: #1d4ed8; --danger-bg: #fee2e2; --danger-fg: #991b1b;
      --warn-bg: #fef3c7; --warn-fg: #92400e; --info-bg: #e0f2fe; --info-fg: #075985;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg); color: var(--text); line-height: 1.55;
      display: grid; grid-template-columns: 260px 1fr; min-height: 100vh;
    }}
    nav.toc {{
      position: sticky; top: 0; height: 100vh; overflow-y: auto;
      background: #0f172a; color: #f8fafc; padding: 1.5rem 1rem; border-right: 1px solid var(--border);
    }}
    nav.toc h2 {{ font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; margin-top: 0; }}
    nav.toc ul {{ list-style: none; padding: 0; margin: 0; }}
    nav.toc li {{ margin-bottom: 0.6rem; }}
    nav.toc a {{ color: #e2e8f0; text-decoration: none; font-size: 0.9rem; }}
    nav.toc a:hover {{ color: #60a5fa; text-decoration: underline; }}
    main {{ max-width: 1400px; padding: 2rem 2.5rem; }}
    article section {{
      background: var(--card); border: 1px solid var(--border); border-radius: 8px;
      padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }}
    h1 {{ margin-top: 0; font-size: 1.7rem; }}
    h2 {{ margin-top: 0; font-size: 1.25rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
    table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.92rem; }}
    th, td {{ border: 1px solid var(--border); padding: 0.6rem 0.75rem; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; font-weight: 600; }}
    code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.86rem; }}
    pre {{ background: #0f172a; color: #f8fafc; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }}
    .badge-danger {{ background: var(--danger-bg); color: var(--danger-fg); }}
    .badge-warn {{ background: var(--warn-bg); color: var(--warn-fg); }}
    .badge-info {{ background: var(--info-bg); color: var(--info-fg); }}
    .muted {{ color: var(--muted); font-size: 0.85rem; }}
  </style>
</head>
<body>
  <nav class="toc" aria-label="Table of Contents">
    <h2>SCA Pre-Flight TOC</h2>
    <ul>
      <li><a href="#provenance">1. Codebase Signature (L0/L1/L2)</a></li>
      <li><a href="#accounting">2. 4-Bucket File &amp; Byte Accounting</a></li>
      <li><a href="#ledger">3. Actionable Bucket 2a File Ledger</a></li>
      <li><a href="#cli-calibration">4. Baseline vs. Optional Detect CLI</a></li>
      <li><a href="#bom-baseline">5. Expected BOM Baseline</a></li>
      <li><a href="#vulnerabilities">6. High-Severity Vulnerabilities ({len(vulns)})</a></li>
      <li><a href="#licenses">7. License &amp; Rugpull Risks ({len(lic_risks)})</a></li>
      <li><a href="#embedded-json">8. Embedded JSON Copy (For LLMs)</a></li>
    </ul>
  </nav>
  <main>
    <article>
      <header>
        <h1>SCA Pre-Flight, File Disposition &amp; Risk Brief (<code>{html.escape(ws_name)}</code>)</h1>
        <p class="muted">Generated by <code>sca-prescan</code> | Scanned: <strong>{report.get('total_dirs_scanned', 0)}</strong> dirs, <strong>{report.get('total_files_scanned', 0)}</strong> files (<strong>{report.get('total_workspace_mb', 0.0)} MB</strong>) | Embedded JSON payload included in <code>#sca-ops-ai-brief-json</code> for 100% LLM ingestion parity.</p>
      </header>

      <section id="provenance">
        <h2>1. Workspace Input &amp; Config Hashes (<code>L0 / L1 / L2 / CFG</code>)</h2>
        <table>
          <thead><tr><th>Layer</th><th>Digest / Signature</th><th>Operational Meaning</th></tr></thead>
          <tbody>
            <tr><td><strong>Compact Signature</strong></td><td><code>{html.escape(str(prov.get('multilayer_codebase_signature', '')))}</code></td><td>Composite fingerprint stamped into Project Version Notes UI.</td></tr>
            <tr><td><strong>Layer 0 (<code>L0</code>)</strong></td><td><code>{html.escape(str(prov.get('topology_skeleton_sha256', '')))}</code></td><td>Zero-file-read folder skeleton ({report.get('total_dirs_scanned', 0)} dirs).</td></tr>
            <tr><td><strong>Layer 1 (<code>L1</code>)</strong></td><td><code>{html.escape(str(prov.get('dependency_inputs_merkle_sha256', '')))}</code></td><td>100% of {b2a.get('count', 0)} Bucket 2a dependency-bearing files ({b2a.get('size_mb', 0.0)} MB).</td></tr>
            <tr><td><strong>Layer 2 (<code>L2</code>)</strong></td><td><code>{html.escape(str(prov.get('workspace_tree_merkle_sha256', '')))}</code></td><td>Top-down source tree ({prov.get('files_hashed_count', 0)}/{prov.get('files_discovered_count', 0)} files, {prov.get('coverage_pct', 100.0)}%).</td></tr>
          </tbody>
        </table>
      </section>

      <section id="accounting">
        <h2>2. 4-Bucket File &amp; Byte Disposition Accounting (<code>{b2a.get('count', 0)} + {b2b.get('count', 0)} + {b3.get('count', 0)} = {report.get('total_files_scanned', 0)}</code> files)</h2>
        <table>
          <thead><tr><th>Bucket</th><th>Count / Size</th><th>What <code>sca-prescan</code> Did With These Objects</th><th>What Default Detect (<code>depth=0</code>) Does With Them</th></tr></thead>
          <tbody>
            <tr><td><strong>Bucket 1: Excluded Dirs</strong></td><td>{b1.get('count', 0)} dir(s)</td><td>{_fmt_code(str(b1.get('prescan_action', '')))}</td><td>{_fmt_code(str(b1.get('default_detect_action', '')))}</td></tr>
            <tr><td><strong>Bucket 2a: Actionable BOM / Vuln / Calibration Files (<code>L1</code>)</strong></td><td><strong>{b2a.get('count', 0)} file(s)</strong> ({b2a.get('size_mb', 0.0)} MB)</td><td>{_fmt_code(str(b2a.get('prescan_action', '')))}</td><td>{_badge(str(b2a.get('default_detect_action', '')))}</td></tr>
            <tr><td><strong>Bucket 2b: Source &amp; Doc Provenance Only (<code>L2 - L1</code>)</strong></td><td>{b2b.get('count', 0)} file(s) ({b2b.get('size_mb', 0.0)} MB)</td><td>{_fmt_code(str(b2b.get('prescan_action', '')))}</td><td>{_fmt_code(str(b2b.get('default_detect_action', '')))}</td></tr>
            <tr><td><strong>Bucket 3: Monorepo Early-Stop Cap</strong></td><td>{b3.get('count', 0)} file(s)</td><td>{_fmt_code(str(b3.get('prescan_action', '')))}</td><td>{_fmt_code(str(b3.get('default_detect_action', '')))}</td></tr>
          </tbody>
        </table>
      </section>

      <section id="ledger">
        <h2>3. Actionable Files Processed in Bucket 2a ({len(ledger)} file(s): <code>sca-prescan</code> vs. Default Detect)</h2>
        <table>
          <thead><tr><th>File Path (Depth)</th><th>Bucket Sub-Type</th><th>What <code>sca-prescan</code> Extracted &amp; Did</th><th>What Default Detect (<code>depth=0</code>) Does</th></tr></thead>
          <tbody>
            {''.join(ledger_rows_html) if ledger_rows_html else '<tr><td colspan="4">None</td></tr>'}
          </tbody>
        </table>
      </section>

      <section id="cli-calibration">
        <h2>4. Baseline Safe Invocation vs. Optional Fuller-BOM Tweaks</h2>
        <p><strong>4.1 Baseline Safe Invocation (Follows Stated Vendor Default-Settings Policy)</strong>: Keeps Detect at default <code>--detect.tools=ALL</code> and <code>--detect.detector.search.depth=0</code> for predictable scan performance, adding only runner RAM sizing, safe directory exclusions, and the provenance stamp. Always <strong>additively concatenate</strong> comma-separated flags (<code>--detect.excluded.directories</code>) with existing pipeline settings.</p>
        <pre><code>{baseline_cmd_str}</code></pre>
        <h3>4.2 Optional Fuller-BOM &amp; Buildless Tweaks (Trade-Offs Explained)</h3>
        <table>
          <thead><tr><th>Optional Flag</th><th>What Hidden Files / Failures It Unlocks</th><th>Performance &amp; BOM Trade-Off</th></tr></thead>
          <tbody>
            {''.join(tweak_rows_html) if tweak_rows_html else '<tr><td colspan="3">No optional depth/detector overrides needed.</td></tr>'}
          </tbody>
        </table>
        <h3>4.3 Operational &amp; Calibration Warnings</h3>
        <ul>{warnings_li}</ul>
      </section>

      <section id="bom-baseline">
        <h2>5. Expected BOM Baseline &amp; Post-Scan Completeness Gate</h2>
        <p><strong>Expected Minimum BOM Components</strong>: <code>&gt;= {html.escape(str(base.get('expected_min_total_components', 0)))}</code> across <code>{html.escape(str(base.get('expected_code_locations', 0)))}</code> code location(s)</p>
        <p><strong>Baseline Summary</strong>: {_fmt_code(str(base.get('summary_statement', 'N/A')))}</p>
        {subs_ul_html}
      </section>

      <section id="vulnerabilities">
        <h2>6. Actionable High-Severity Vulnerabilities ({len(vulns)})</h2>
        <p class="muted"><strong>Scope Note (Free 5-Second Worst-of-the-Worst Check, Not a Full SCA Database)</strong>: <code>sca-prescan</code>'s main job is tuning your Detect CLI flags and catching BOM blind spots before your scan starts. As a free 5-second side dish while walking the tree, it also checks an offline hit-list (<code>3,910</code> version/range rules + <code>32</code> unpatched code-snippet and shaded-bytecode patterns) focused strictly on <strong>must-catch disasters</strong>: actively exploited <strong>CISA-KEV</strong> flaws, <strong>recent 2025-2026 critical advisories</strong> (including pre-NVD <code>GHSA</code>/<code>GO</code>/<code>RUSTSEC</code> advisories), <code>CVSS 9.8-10.0</code> RCEs, and major open-source license rugpulls (<code>AGPL-3.0</code>, <code>SSPL-1.0</code>, <code>RSALv2</code>, <code>BSL-1.1</code>). When version strings are missing or stripped from shaded uber-JARs, it checks source files and in-memory <code>.class</code> constant pools directly (<code>[UNPATCHED-SNIPPET-VERIFIED]</code> / <code>[PATCH-GUARD-DETECTED]</code>). Always rely on your full SCA server and AST/SAST tools for comprehensive vulnerability coverage.</p>
        <table>
          <thead><tr><th>CVE ID</th><th>CVSS</th><th>KEV</th><th>Component &amp; Version</th><th>Evidence Source</th><th>Actionable Remedy</th></tr></thead>
          <tbody>
            {''.join(vuln_rows_html) if vuln_rows_html else '<tr><td colspan="6">No high-severity Pareto vulnerabilities matched.</td></tr>'}
          </tbody>
        </table>
      </section>

      <section id="licenses">
        <h2>7. High-Severity License &amp; Rugpull Risks ({len(lic_risks)})</h2>
        <table>
          <thead><tr><th>Rule ID</th><th>Severity</th><th>Component &amp; Version</th><th>License</th><th>Evidence Source</th><th>Safe Version / Remedy</th></tr></thead>
          <tbody>
            {''.join(lic_rows_html) if lic_rows_html else '<tr><td colspan="6">No high-severity license or rugpull risks matched.</td></tr>'}
          </tbody>
        </table>
      </section>

      <section id="embedded-json">
        <h2>8. Embedded Machine-Readable JSON Copy (<code>#sca-ops-ai-brief-json</code>)</h2>
        <p>This HTML file embeds valid Schema.org <code>TechArticle</code> JSON-LD alongside a complete, DLP-sanitized JSON copy inside <code>&lt;script type="application/json" id="sca-ops-ai-brief-json"&gt;</code> in the document <code>&lt;head&gt;</code> so enterprise LLMs and automation scripts can parse exact counts and SHA-256 digests directly from this single HTML file.</p>
      </section>
    </article>
  </main>
</body>
</html>
"""
    return (
        raw_html.replace("Black Duck SCA", "SCA")
        .replace("In Black Duck ", "In SCA Server ")
        .replace("Black Duck ", "")
        .replace("\u2014", "-")
        .replace("\u2013", "-")
    )


def main() -> int:
    """CLI entrypoint for sca-prescan."""
    parser = argparse.ArgumentParser(
        description="Client-side Detect workspace pre-flight analyzer and tuner."
    )
    parser.add_argument(
        "--workspace",
        "-w",
        default=".",
        help="Path to target workspace directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=12,
        help="Maximum directory traversal depth (default: 12).",
    )
    parser.add_argument(
        "--parallel-processors",
        type=int,
        default=1,
        help="Configured Detect parallel signature scanner processors (default: 1).",
    )
    parser.add_argument(
        "--memory-limit-mb",
        type=int,
        default=None,
        help="Explicit available RAM override in MB (disables auto-detection).",
    )
    parser.add_argument(
        "--archive-threshold-mb",
        type=float,
        default=50.0,
        help="Threshold in MB to flag oversized archives (default: 50.0).",
    )
    parser.add_argument(
        "--bd-url",
        default=None,
        help="SCA server URL for preflight connectivity check (e.g. https://sca.corp.local).",
    )
    parser.add_argument(
        "--bd-token",
        default=None,
        help="SCA API token to validate authentication prior to scan.",
    )
    parser.add_argument(
        "--proxy-url",
        default=None,
        help="HTTP/HTTPS proxy URL for preflight checks.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Configure recommended arguments for offline scan mode (--blackduck.offline.mode=true --detect.tools=DETECTOR).",
    )
    parser.add_argument(
        "--verify-detect-output",
        default=None,
        help="Path to Detect run directory or diagnostic zip to verify against expected BOM baseline.",
    )
    parser.add_argument(
        "--custom-catalog",
        default=None,
        help="Path to customer-specific custom component and disaster-smell overlay catalog JSON.",
    )
    parser.add_argument(
        "--export-learned-catalog",
        default=None,
        help="Path to export discovered BDIO components as a reusable customer overlay catalog JSON.",
    )
    parser.add_argument(
        "--save-baseline",
        default=None,
        help="Path to save scan baseline JSON to guard against Friday-afternoon silencer regressions.",
    )
    parser.add_argument(
        "--check-baseline",
        default=None,
        help="Path to saved baseline JSON to check against current scan for component/location drift.",
    )
    parser.add_argument(
        "--emit-supplemental-bdio",
        default=None,
        help="Path to emit supplemental BDIO 2.x archive for discovered prescan components.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Number of worker threads for parallel file inspection (default: min(8, cpu_count)).",
    )
    parser.add_argument(
        "--git-diff",
        default=None,
        help="Base git ref to analyze dependency delta and silencer injections (e.g. origin/main, HEAD~1).",
    )
    parser.add_argument(
        "--ai-brief",
        default=None,
        help="Path to write DLP-sanitized, token-budgeted AI-first Markdown report (LLM_INGESTION_REPORT.md).",
    )
    parser.add_argument(
        "--html-report",
        default=None,
        help="Path to write self-contained semantic HTML5 report with embedded JSON-LD.",
    )
    parser.add_argument(
        "--existing-detect-args",
        default=None,
        help="Existing customer Detect CLI flags to additively merge comma-separated settings and suppress duplicate warnings.",
    )
    parser.add_argument(
        "--repo-only",
        action="store_true",
        help="Audit repository contents only (skip local host Java/cgroup RAM checks when running in an external cleanroom sandbox).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in machine-readable JSON format.",
    )

    args = parser.parse_args()

    try:
        report = scan_workspace(
            workspace_path=args.workspace,
            max_depth=args.max_depth,
            memory_limit_mb_override=args.memory_limit_mb,
            parallel_processors=args.parallel_processors,
            archive_threshold_mb=args.archive_threshold_mb,
            offline_mode=args.offline,
            custom_catalog_path=args.custom_catalog,
            max_workers=args.threads,
            git_diff_base_ref=args.git_diff,
            repo_only=args.repo_only,
            existing_detect_args=args.existing_detect_args,
        )
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"Error scanning workspace: {exc}\n")
        return 1

    if args.bd_url:
        server_report = preflight_server_check(
            bd_url=args.bd_url,
            api_token=args.bd_token,
            proxy_url=args.proxy_url,
        )
        report["server_preflight"] = server_report

    verification: dict[str, Any] | None = None
    if args.verify_detect_output:
        try:
            verification = verify_detect_output(report, args.verify_detect_output)
            report["detect_verification"] = verification
            report["actionable_vulnerabilities"] = match_pareto_vulnerabilities(
                report,
                bdio_components=verification.get("components", []),
                custom_kb_path=args.custom_catalog,
            )
            report["actionable_license_risks"] = match_pareto_license_risks(
                report,
                bdio_components=verification.get("components", []),
                custom_kb_path=args.custom_catalog,
            )
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Error verifying Detect output: {exc}\n")
            return 1

    if args.export_learned_catalog:
        comps_to_export: list[dict[str, Any]] = []
        if verification:
            comps_to_export.extend(verification.get("components", []))
        if not comps_to_export:
            for a in (
                report.get("deep_packet_inspection", {}).get("filename_version_assertions", [])
            ):
                comps_to_export.append(
                    {"name": a.get("artifact_name"), "version": a.get("asserted_version")}
                )
        try:
            export_learned_catalog(comps_to_export, args.export_learned_catalog)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Error exporting learned catalog: {exc}\n")
            return 1

    if args.save_baseline:
        try:
            save_baseline(report, args.save_baseline)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Error saving baseline {args.save_baseline}: {exc}\n")
            return 1

    baseline_drift: dict[str, Any] | None = None
    if args.check_baseline:
        try:
            baseline_drift = check_baseline(report, args.check_baseline)
            report["baseline_drift"] = baseline_drift
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Error checking baseline {args.check_baseline}: {exc}\n")
            return 1

    if args.emit_supplemental_bdio:
        try:
            emit_supplemental_bdio(report, args.emit_supplemental_bdio)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(
                f"Error emitting supplemental BDIO {args.emit_supplemental_bdio}: {exc}\n"
            )
            return 1

    if args.ai_brief:
        try:
            brief_path = Path(args.ai_brief)
            brief_path.parent.mkdir(parents=True, exist_ok=True)
            brief_path.write_text(generate_ai_brief_markdown(report), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Error writing AI brief {args.ai_brief}: {exc}\n")
            return 1

    if args.html_report:
        try:
            html_path = Path(args.html_report)
            html_path.parent.mkdir(parents=True, exist_ok=True)
            html_path.write_text(generate_ai_brief_html(report), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Error writing HTML report {args.html_report}: {exc}\n")
            return 1

    if args.json:
        json_out = (
            json.dumps(report, indent=2)
            .replace("Black Duck SCA", "SCA")
            .replace("In Black Duck ", "In SCA Server ")
            .replace("Black Duck ", "")
        )
        sys.stdout.write(json_out + "\n")
    else:
        sys.stdout.write("=== SCA Detect Pre-Scan Workspace Analysis ===\n")
        sys.stdout.write(f"Workspace: {report['workspace_root']}\n")
        sys.stdout.write(
            f"Scanned: {report['total_dirs_scanned']} dirs, {report['total_files_scanned']} files ({report.get('total_workspace_mb', 0.0)} MB)\n"
        )
        java_r = report.get("java_runtime", {})
        sys.stdout.write(f"Java Runtime: {'Found' if java_r.get('java_found') else 'Missing'}")
        if java_r.get("java_path"):
            sys.stdout.write(f" ({java_r.get('java_path')})")
        if java_r.get("version"):
            sys.stdout.write(f" - {java_r.get('version')}")
        sys.stdout.write("\n\n")

        if report.get("max_manifest_depth", 0) > 0:
            sys.stdout.write(f"Max Manifest Depth: {report['max_manifest_depth']}\n\n")

        sys.stdout.write(f"Lockfiles Identified ({len(report['lockfiles'])}):\n")
        for lf in report["lockfiles"]:
            sys.stdout.write(f"  - {lf['path']} ({lf['size_mb']} MB)\n")
        if not report["lockfiles"]:
            sys.stdout.write("  (None found)\n")

        sys.stdout.write(f"\nUnpinned Manifests ({len(report['unpinned_manifests'])}):\n")
        for up in report["unpinned_manifests"]:
            sys.stdout.write(f"  - {up['path']} ({up['size_mb']} MB)\n")
        if not report["unpinned_manifests"]:
            sys.stdout.write("  (None found)\n")

        sys.stdout.write(f"\nSafe Exclusions to Apply ({len(report['safe_exclusions'])}):\n")
        for safe in report["safe_exclusions"]:
            sys.stdout.write(f"  - {safe}\n")

        if report["conditional_exclusions"]:
            sys.stdout.write(f"\nConditional Exclusions ({len(report['conditional_exclusions'])}):\n")
            for cond in report["conditional_exclusions"]:
                sys.stdout.write(f"  * {cond['directory']}: {cond['reason']}\n")

        if report["oversized_archives"]:
            sys.stdout.write(f"\nOversized Archives ({len(report['oversized_archives'])}):\n")
            for oa in report["oversized_archives"]:
                sys.stdout.write(f"  ! {oa['path']} ({oa['size_mb']} MB)\n")

        mem = report["memory"]
        sys.stdout.write("\nMemory Tuning:\n")
        sys.stdout.write(
            f"  Available RAM: {mem['available_ram_mb']} MB (source: {mem['detection_source']})\n"
        )
        sys.stdout.write(f"  Recommended Scanner Memory: {mem['recommended_scanner_memory_mb']} MB\n")
        for warn in mem["warnings"]:
            sys.stdout.write(f"  ! {warn}\n")

        if report.get("warnings"):
            sys.stdout.write(f"\nOperational Warnings ({len(report['warnings'])}):\n")
            for warn in report["warnings"]:
                sys.stdout.write(f"  ! {warn}\n")

        sys.stdout.write("\nRecommended Detect Arguments:\n")
        for arg in report["recommended_detect_arguments"]:
            sys.stdout.write(f"  {arg}\n")

        if "scan_input_provenance" in report:
            sip = report["scan_input_provenance"]
            sys.stdout.write("\nScan Input & Config Provenance (L0 / L1 / L2 / CFG Hashes):\n")
            sys.stdout.write(f"  Workspace Tree Merkle SHA-256:    {sip['workspace_tree_merkle_sha256']}\n")
            sys.stdout.write(f"  Dependency Inputs Merkle SHA-256: {sip['dependency_inputs_merkle_sha256']}\n")
            sys.stdout.write(f"  Effective Detect Config SHA-256:  {sip['effective_detect_config_sha256']}\n")
            sys.stdout.write(f"  BD Web UI Notes Stamp:            {sip['bd_ui_version_notes_arg']}\n")

        if "expected_bom_baseline" in report:
            base = report["expected_bom_baseline"]
            sys.stdout.write("\nExpected BOM Baseline (Anti-False-Negative Gate):\n")
            sys.stdout.write(f"  {base['summary_statement']}\n")
            for sub in base.get("subprojects", []):
                if sub.get("expected_min_components", 0) > 0:
                    sys.stdout.write(
                        f"    * [{sub['ecosystem']}] {sub['directory']}: >= {sub['expected_min_components']} component(s) ({sub['reason']})\n"
                    )

        if "pareto_hints" in report:
            ph = report["pareto_hints"]
            has_ph = any(ph.get(k) for k in ph)
            if has_ph:
                sys.stdout.write("\nPareto Pre-Scan Hints (80/20 Heuristic):\n")
                if ph.get("docker_base_images"):
                    sys.stdout.write(f"  Docker Base Images ({len(ph['docker_base_images'])}):\n")
                    for dimg in ph["docker_base_images"]:
                        sys.stdout.write(f"    - {dimg['full_spec']} ({dimg['path']})\n")
                if ph.get("native_dependencies"):
                    sys.stdout.write(f"  Native C/C++ Dependency Hints ({len(ph['native_dependencies'])}):\n")
                    for nd in ph["native_dependencies"][:8]:
                        sys.stdout.write(f"    - {nd['name']} ({nd['type']} in {nd['path']})\n")
                    if len(ph["native_dependencies"]) > 8:
                        sys.stdout.write(f"    ... and {len(ph['native_dependencies']) - 8} more\n")
                if ph.get("binary_version_artifacts"):
                    sys.stdout.write(f"  Binary Artifacts ({len(ph['binary_version_artifacts'])}):\n")
                    for ba in ph["binary_version_artifacts"]:
                        sys.stdout.write(f"    - {ba['filename']} ({ba['size_mb']} MB)\n")
                if ph.get("attribution_files"):
                    sys.stdout.write(f"  Attribution & Legal Files ({len(ph['attribution_files'])}):\n")
                    for af in ph["attribution_files"]:
                        spdx_str = f" [SPDX: {', '.join(af['spdx_licenses'])}]" if af.get("spdx_licenses") else ""
                        sys.stdout.write(f"    - {af['filename']} ({af['path']}){spdx_str}\n")

        if verification is not None:
            sys.stdout.write("\n" + "=" * 80 + "\n")
            sys.stdout.write("Detect Scan Provenance & Post-Scan Comparison Report\n")
            sys.stdout.write("=" * 80 + "\n")

            prov = verification.get("provenance_summary", {})
            wt = prov.get("workspace_telemetry", {})
            sys.stdout.write("Workspace & Scan Telemetry Summary:\n")
            sys.stdout.write(
                f"  Workspace: {wt.get('total_dirs_scanned', 0)} dirs, {wt.get('total_files_scanned', 0)} files "
                f"({wt.get('total_archives', 0)} archive(s) totaling {wt.get('total_archives_mb', 0.0)} MB)\n"
            )
            sys.stdout.write(
                f"  Manifests: {wt.get('lockfiles_count', 0)} lockfiles, {wt.get('unpinned_manifests_count', 0)} unpinned manifests\n"
            )
            sys.stdout.write(
                f"  Pareto Hints: {wt.get('binary_version_artifacts_count', 0)} binary archive(s), "
                f"{wt.get('docker_base_images_count', 0)} Docker base image(s), "
                f"{wt.get('native_dependencies_count', 0)} native C/C++ dependency hint(s)\n"
            )
            ops = prov.get("detect_operations", [])
            if ops:
                sys.stdout.write(f"  Detect Operations ({len(ops)}):\n")
                for op in ops:
                    dur_str = f"{op['duration_sec']}s" if op.get("duration_sec") is not None else "N/A"
                    sys.stdout.write(f"    - {op['description']}: {dur_str} ({op['status']})\n")

            sys.stdout.write("\nBOM Completeness Verification:\n")
            sys.stdout.write(f"  Verdict: {verification['verdict']}\n")
            sys.stdout.write(
                f"  Actual Total Components: {verification['actual_total_components']} "
                f"(Expected Baseline: >= {verification['expected_min_total_components']})\n"
            )
            sys.stdout.write(
                f"  Actual Code Locations: {verification['actual_code_locations']} "
                f"(Expected Baseline: >= {verification['expected_code_locations']})\n"
            )
            bdio_files = verification.get("bdio_files", [])
            sys.stdout.write(f"  BDIO Files Inspected ({len(bdio_files)}):\n")
            for bf in bdio_files:
                sys.stdout.write(f"    - {bf}\n")
            if not bdio_files:
                sys.stdout.write("    (None found)\n")

            sys.stdout.write("  Subproject Breakdown:\n")
            for s in verification.get("subproject_results", []):
                mark = "*" if s["status"] == "PASS" else "!"
                det_note = (
                    f" - {s['detector_status']}"
                    if s["detector_status"] not in ("NOT_RUN", "SUCCESS: PASSED")
                    else ""
                )
                sys.stdout.write(
                    f"    {mark} [{s['ecosystem']}] {s['directory']}: {s['status']} "
                    f"({s['actual_components']} component(s) extracted, expected >= {s['expected_min_components']}){det_note}\n"
                )

            silencers = verification.get("silencer_flags_audit", [])
            if silencers:
                sys.stdout.write("\n\"Valgrind-Silencer\" Flag Audit (Dev vs. AppSec/Admin Disconnect):\n")
                for sil in silencers:
                    sys.stdout.write(f"  ! [SILENCER] {sil['property']}={sil['value']}: {sil['impact']}\n")

            disconnects = verification.get("disconnect_audit", [])
            if disconnects:
                sys.stdout.write("\nPre-Scan vs. BDIO Disconnect Analysis:\n")
                sys.stdout.write("  \"Our Pre-Scan Found X, But the BDIO Only Had Y - Is That By Explicit Design?\"\n")
                for disc in disconnects:
                    sys.stdout.write(
                        f"  ! {disc['category']}: {disc['item']} - {disc['bdio_finding']} "
                        f"({disc['pre_scan_finding']}). Remedy: {disc['remedy']}\n"
                    )

            remedies = verification.get("recommended_remedy_arguments", [])
            if remedies:
                sys.stdout.write("\nRecommended Detect Arguments to Capture Full BOM:\n")
                for rem in remedies:
                    sys.stdout.write(f"  {rem}\n")

            issues = verification.get("detector_issues", [])
            if issues:
                sys.stdout.write(f"\nDetector Issues ({len(issues)}):\n")
                for iss in issues:
                    sys.stdout.write(f"    ! {iss}\n")

            sys.stdout.write(f"\nSummary: {verification['summary']}\n")

        if "server_preflight" in report:
            sp = report["server_preflight"]
            sys.stdout.write("\nServer Preflight Connectivity:\n")
            sys.stdout.write(f"  Status: {sp['status']}\n")
            if sp.get("server_version"):
                sys.stdout.write(f"  Server Version: {sp['server_version']}\n")
            if sp.get("token_checked"):
                sys.stdout.write(f"  API Token Valid: {sp['token_valid']}\n")
            if sp.get("auth_error"):
                sys.stdout.write(f"  Auth Error: {sp['auth_error']}\n")
            if sp.get("error"):
                sys.stdout.write(f"  Error: {sp['error']}\n")

        if "git_diff_analysis" in report:
            gda = report["git_diff_analysis"]
            sys.stdout.write("\nGit Diff Delta Mode Analysis:\n")
            sys.stdout.write(f"  Base Ref: {gda['base_ref']}\n")
            sys.stdout.write(f"  Verdict: {gda['verdict']}\n")
            sys.stdout.write(f"  Skip Full Detect Scan: {gda['skip_full_bd_scan_recommended']}\n")
            if gda.get("changed_manifests"):
                sys.stdout.write(f"  Changed Manifests ({len(gda['changed_manifests'])}):\n")
                for cm in gda["changed_manifests"]:
                    sys.stdout.write(f"    - {cm}\n")
            if gda.get("ci_silencer_additions"):
                sys.stdout.write(f"  CI Silencer Additions ({len(gda['ci_silencer_additions'])}):\n")
                for csa in gda["ci_silencer_additions"]:
                    sys.stdout.write(f"    ! {csa}\n")
            if gda.get("affected_subprojects"):
                sys.stdout.write(f"  Affected Subprojects: {', '.join(gda['affected_subprojects'])}\n")

        if report.get("actionable_vulnerabilities"):
            act_vulns = report["actionable_vulnerabilities"]
            sys.stdout.write(f"\nActionable Pareto Vulnerabilities ({len(act_vulns)}):\n")
            for av in act_vulns:
                kev_str = " [CISA-KEV]" if av.get("cisa_kev") else ""
                sys.stdout.write(
                    f"  ! [{av['cve_id']}] {av['component']} {av['installed_version']}{kev_str} (CVSS {av['cvss']})\n"
                )
                sys.stdout.write(f"    Remedy: {av['actionable_remedy']}\n")
                sys.stdout.write(f"    Evidence: {av['evidence_source']}\n")

        if report.get("actionable_license_risks"):
            lic_risks = report["actionable_license_risks"]
            sys.stdout.write(f"\nActionable License & Rugpull Risks ({len(lic_risks)}):\n")
            for lr in lic_risks:
                prev_str = f" (flipped from {lr['previous_license']})" if lr.get("previous_license") else ""
                sys.stdout.write(
                    f"  ! [{lr['severity']}] {lr['rule_id']}: {lr['component']} {lr['installed_version']} -> {lr['license_id']}{prev_str}\n"
                )
                sys.stdout.write(f"    Impact: {lr['summary']}\n")
                sys.stdout.write(f"    Remedy: {lr['safe_version_hint']}\n")
                sys.stdout.write(f"    Evidence: {lr['evidence_source']}\n")

    if baseline_drift is not None and baseline_drift["status"] == "BASELINE_DRIFT_FAIL":
        sys.stderr.write("BASELINE_DRIFT_FAIL: Detected scan drift against saved baseline:\n")
        for v in baseline_drift.get("violations", []):
            sys.stderr.write(f"  - {v}\n")
        return 1

    if verification is not None and verification["verdict"] != "COMPLETE_PASS":
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
