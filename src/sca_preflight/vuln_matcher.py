"""Pareto vulnerability matcher and pinned manifest dependency extraction.

Matches extracted workspace dependencies and binary assertions against the 7-axis
Pareto Actionable Vulnerability Knowledge Base, enforcing ecosystem compatibility
and providing Black Duck SCA confirmation guidance.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from sca_preflight.catalog import (
    ECOSYSTEM_MAP,
    PrescanReport,
    _normalize_component_name,
    decode_manifest_bytes,
    load_pareto_license_kb,
    load_pareto_vuln_kb,
    safe_parse_xml_bytes,
)

_SPRING_BOOT_PARENT_BOMS: dict[str, dict[str, str]] = {
    "2.4.3": {
        "spring-beans": "5.3.4",
        "spring-webmvc": "5.3.4",
        "spring-web": "5.3.4",
        "postgresql": "42.2.18",
        "snakeyaml": "1.27",
        "jackson-databind": "2.11.4",
    },
}


def _resolve_maven_prop(val: str, props: dict[str, str]) -> str:
    """Resolve ${...} Maven property placeholders up to 3 levels deep."""
    resolved = val.strip()
    for _ in range(3):
        if "${" not in resolved:
            break
        new_val = re.sub(
            r"\$\{([^}]+)\}",
            lambda m: props.get(m.group(1), m.group(0)),
            resolved,
        )
        if new_val == resolved:
            break
        resolved = new_val
    return resolved


def extract_pinned_manifest_components(
    root: Path,
    lockfiles: list[dict[str, Any]],
    manifests: list[dict[str, Any]],
) -> list[tuple[str, str, str]]:
    """Extract pinned (name, version, source) tuples from lockfiles and manifests, skipping devDependencies and test scope."""
    results: list[tuple[str, str, str]] = []
    gomod_dirs: set[str] = {
        str(Path(str(m.get("path", ""))).parent)
        for m in manifests
        if m.get("filename") == "go.mod"
    }

    # Process lockfiles
    for lf in lockfiles:
        rel_path = str(lf.get("path", ""))
        fname = lf.get("filename", "")
        fpath = root / rel_path
        if not fpath.is_file():
            continue

        try:
            if fname == "package-lock.json":
                raw_bytes = fpath.read_bytes()
                if len(raw_bytes) > 5 * 1024 * 1024:
                    continue
                data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                packages = data.get("packages", {})
                if isinstance(packages, dict) and packages:
                    for pkg_key, pkg_info in packages.items():
                        if not isinstance(pkg_info, dict):
                            continue
                        if pkg_info.get("dev") is True:
                            continue
                        pkg_ver = pkg_info.get("version")
                        if not pkg_ver:
                            continue
                        pkg_name = pkg_info.get("name")
                        if not pkg_name:
                            if pkg_key.startswith("node_modules/"):
                                pkg_name = pkg_key.split("node_modules/")[-1]
                            elif pkg_key == "":
                                continue
                            else:
                                pkg_name = Path(pkg_key).name
                        if pkg_name and pkg_ver:
                            results.append((str(pkg_name), str(pkg_ver), f"lockfile:{rel_path}"))
                else:
                    deps = data.get("dependencies", {})
                    if isinstance(deps, dict):
                        for dep_name, dep_info in deps.items():
                            if not isinstance(dep_info, dict):
                                continue
                            if dep_info.get("dev") is True:
                                continue
                            dep_ver = dep_info.get("version")
                            if dep_ver:
                                results.append((str(dep_name), str(dep_ver), f"lockfile:{rel_path}"))

            elif fname == "yarn.lock":
                raw_bytes = fpath.read_bytes()
                if len(raw_bytes) > 10 * 1024 * 1024:
                    continue
                text = raw_bytes.decode("utf-8", errors="replace")
                curr_pkgs: list[str] = []
                seen_yarn: set[tuple[str, str]] = set()
                for line in text.splitlines():
                    if not line or line.startswith("#"):
                        continue
                    if not line[0].isspace() and line.rstrip().endswith(":"):
                        curr_pkgs = []
                        header = line.rstrip()[:-1]
                        for raw_sel in header.split(","):
                            sel = raw_sel.strip().strip('"').strip("'")
                            if not sel or sel.startswith("__"):
                                continue
                            at_idx = sel.find("@", 1) if sel.startswith("@") else sel.find("@")
                            if at_idx > 0:
                                pkg_n = sel[:at_idx].strip()
                                if pkg_n and pkg_n not in curr_pkgs:
                                    curr_pkgs.append(pkg_n)
                    elif curr_pkgs:
                        sline = line.strip()
                        m_ver = re.match(
                            r'^version(?:\s+|:\s*)["\']?([0-9]+\.[0-9]+\.[0-9A-Za-z._\-+]+)["\']?$',
                            sline,
                        )
                        if m_ver:
                            y_ver = m_ver.group(1)
                            for p_n in curr_pkgs:
                                if (p_n, y_ver) not in seen_yarn:
                                    seen_yarn.add((p_n, y_ver))
                                    results.append((p_n, y_ver, f"lockfile:{rel_path}"))
                            curr_pkgs = []

            elif fname in ("Cargo.lock", "poetry.lock", "uv.lock"):
                raw_bytes = fpath.read_bytes()
                if len(raw_bytes) > 10 * 1024 * 1024:
                    continue
                text = raw_bytes.decode("utf-8", errors="replace")
                try:
                    data = tomllib.loads(text)
                    pkg_list = data.get("package", [])
                    if isinstance(pkg_list, list):
                        for pkg in pkg_list:
                            if isinstance(pkg, dict):
                                p_name = pkg.get("name")
                                p_ver = pkg.get("version")
                                if p_name and p_ver:
                                    results.append((str(p_name), str(p_ver), f"lockfile:{rel_path}"))
                except Exception:  # noqa: BLE001
                    curr_name: str | None = None
                    curr_ver: str | None = None
                    for line in text.splitlines():
                        line = line[:4096].strip()
                        if line == "[[package]]":
                            if curr_name and curr_ver:
                                results.append((curr_name, curr_ver, f"lockfile:{rel_path}"))
                            curr_name, curr_ver = None, None
                        elif line.startswith("name ="):
                            curr_name = line.split("=", 1)[1].strip().strip('"')
                        elif line.startswith("version ="):
                            curr_ver = line.split("=", 1)[1].strip().strip('"')
                    if curr_name and curr_ver:
                        results.append((curr_name, curr_ver, f"lockfile:{rel_path}"))

            elif fname == "Pipfile.lock":
                raw_bytes = fpath.read_bytes()
                if len(raw_bytes) > 5 * 1024 * 1024:
                    continue
                data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                def_deps = data.get("default", {})
                if isinstance(def_deps, dict):
                    for p_name, p_info in def_deps.items():
                        if isinstance(p_info, dict):
                            raw_v = str(p_info.get("version", "")).lstrip("=")
                            if p_name and raw_v:
                                results.append((str(p_name), raw_v, f"lockfile:{rel_path}"))

            elif fname == "pnpm-lock.yaml":
                raw_bytes = fpath.read_bytes()
                if len(raw_bytes) > 10 * 1024 * 1024:
                    continue
                text = raw_bytes.decode("utf-8", errors="replace")
                seen_pnpm: set[tuple[str, str]] = set()
                for line in text.splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    m_pnpm = re.match(
                        r"^['\"]?/?(@?[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9._\-]+)?)[@/]([0-9]+\.[0-9]+\.[0-9A-Za-z._\-]+?)(?:\(|['\"]?:|$)",
                        s,
                    )
                    if m_pnpm:
                        pn_name, pn_ver = m_pnpm.group(1), m_pnpm.group(2)
                        if (pn_name, pn_ver) not in seen_pnpm:
                            seen_pnpm.add((pn_name, pn_ver))
                            results.append((pn_name, pn_ver, f"lockfile:{rel_path}"))

            elif fname == "composer.lock":
                raw_bytes = fpath.read_bytes()
                if len(raw_bytes) > 5 * 1024 * 1024:
                    continue
                data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                for pkg in data.get("packages", []):
                    if isinstance(pkg, dict):
                        c_name = pkg.get("name")
                        c_ver = str(pkg.get("version", "")).lstrip("v")
                        if c_name and c_ver:
                            results.append((str(c_name), c_ver, f"lockfile:{rel_path}"))

            elif fname == "gradle.lockfile":
                text = fpath.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    s = line.strip()
                    if not s or s.startswith("#") or "empty=" in s:
                        continue
                    if "=" in s:
                        coord = s.split("=", 1)[0].strip()
                        parts = coord.split(":")
                        if len(parts) == 3 and parts[1] and parts[2]:
                            results.append((parts[1], parts[2], f"lockfile:{rel_path}"))

            elif fname == "go.sum":
                if str(Path(rel_path).parent) in gomod_dirs:
                    continue
                raw_bytes = fpath.read_bytes()
                if len(raw_bytes) > 5 * 1024 * 1024:
                    continue
                text = raw_bytes.decode("utf-8", errors="replace")
                seen_gosum: set[tuple[str, str]] = set()
                for line in text.splitlines():
                    line = line[:4096].strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        mod = parts[0]
                        ver = parts[1].split("/")[0]
                        if (mod, ver) not in seen_gosum:
                            seen_gosum.add((mod, ver))
                            results.append((mod, ver, f"lockfile:{rel_path}"))

            elif fname == "status":
                text = fpath.read_text(encoding="utf-8", errors="replace")
                opkg_pkg: str | None = None
                opkg_ver: str | None = None
                for line in text.splitlines():
                    sline = line.strip()
                    if not sline:
                        if opkg_pkg and opkg_ver:
                            results.append((opkg_pkg, opkg_ver, f"lockfile:{rel_path}"))
                        opkg_pkg = None
                        opkg_ver = None
                    elif sline.startswith("Package:"):
                        opkg_pkg = sline.split(":", 1)[1].strip()
                    elif sline.startswith("Version:"):
                        raw_opkg_ver = sline.split(":", 1)[1].strip()
                        # Strip epoch and revision (e.g., 1:1.2.11-r0 -> 1.2.11)
                        clean_ver = raw_opkg_ver.split(":", 1)[-1].split("-r", 1)[0]
                        opkg_ver = clean_ver
                if opkg_pkg and opkg_ver:
                    results.append((opkg_pkg, opkg_ver, f"lockfile:{rel_path}"))
        except Exception:  # noqa: BLE001
            continue

    # First pass for pom.xml files: gather workspace Maven properties and dependencyManagement
    global_maven_props: dict[str, str] = {}
    raw_dep_mgmt: dict[str, str] = {}
    parsed_poms: list[tuple[str, ET.Element, dict[str, str], str | None, str | None]] = []

    for mf in manifests:
        if mf.get("filename") != "pom.xml":
            continue
        rel_path = str(mf.get("path", ""))
        fpath = root / rel_path
        if not fpath.is_file():
            continue
        try:
            root_elem = safe_parse_xml_bytes(fpath.read_bytes())
            if root_elem is None:
                continue
            local_props: dict[str, str] = {}
            proj_art_id: str | None = None
            proj_ver: str | None = None
            parent_art_id: str | None = None
            parent_ver: str | None = None

            for child in root_elem:
                c_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                c_text = (child.text or "").strip()
                if c_tag == "artifactId" and c_text:
                    proj_art_id = c_text
                elif c_tag == "version" and c_text:
                    proj_ver = c_text
                elif c_tag == "parent":
                    for p_child in child:
                        p_tag = p_child.tag.split("}")[-1] if "}" in p_child.tag else p_child.tag
                        p_text = (p_child.text or "").strip()
                        if p_tag == "artifactId" and p_text:
                            parent_art_id = p_text
                        elif p_tag == "version" and p_text:
                            parent_ver = p_text
                elif c_tag == "properties":
                    for prop_elem in child:
                        prop_name = prop_elem.tag.split("}")[-1] if "}" in prop_elem.tag else prop_elem.tag
                        prop_val = (prop_elem.text or "").strip()
                        if prop_name and prop_val:
                            local_props[prop_name] = prop_val
                elif c_tag == "dependencyManagement":
                    for dm_elem in child.iter():
                        dm_tag = dm_elem.tag.split("}")[-1] if "}" in dm_elem.tag else dm_elem.tag
                        if dm_tag == "dependency":
                            dm_art: str | None = None
                            dm_ver: str | None = None
                            dm_scope: str | None = None
                            for d_child in dm_elem:
                                dc_tag = d_child.tag.split("}")[-1] if "}" in d_child.tag else d_child.tag
                                dc_text = (d_child.text or "").strip()
                                if dc_tag == "artifactId":
                                    dm_art = dc_text
                                elif dc_tag == "version":
                                    dm_ver = dc_text
                                elif dc_tag == "scope":
                                    dm_scope = dc_text.lower()
                            if dm_scope != "test" and dm_art and dm_ver:
                                raw_dep_mgmt.setdefault(dm_art, dm_ver)

            eff_ver = proj_ver or parent_ver
            if eff_ver:
                local_props.setdefault("project.version", eff_ver)
                local_props.setdefault("pom.version", eff_ver)
            if parent_ver:
                local_props.setdefault("project.parent.version", parent_ver)

            for k, v in local_props.items():
                if k not in global_maven_props or "/" not in rel_path:
                    global_maven_props[k] = v

            if parent_art_id in ("spring-boot-starter-parent", "spring-boot-dependencies") and parent_ver:
                bom_map = _SPRING_BOOT_PARENT_BOMS.get(parent_ver)
                if bom_map is None and re.match(r"^2\.(?:[0-5]\.|6\.[0-5])(?:$|[^0-9])", parent_ver):
                    bom_map = {
                        "spring-beans": "5.3.17",
                        "spring-webmvc": "5.3.17",
                        "spring-web": "5.3.17",
                        "snakeyaml": "1.29",
                    }
                if bom_map:
                    for b_art, b_ver in bom_map.items():
                        raw_dep_mgmt.setdefault(b_art, b_ver)

            parsed_poms.append((rel_path, root_elem, local_props, proj_art_id, eff_ver))
        except Exception:  # noqa: BLE001
            continue

    resolved_dep_mgmt: dict[str, str] = {
        k: _resolve_maven_prop(v, global_maven_props) for k, v in raw_dep_mgmt.items()
    }

    # Process manifests
    for mf in manifests:
        rel_path = str(mf.get("path", ""))
        fname = mf.get("filename", "")
        fpath = root / rel_path
        if not fpath.is_file():
            continue

        try:
            if fname == "requirements.txt":
                text, _ = decode_manifest_bytes(fpath.read_bytes())
                for line in text.splitlines():
                    line = line[:4096].strip()
                    if not line or line.startswith(("#", "-", "@", "git+")):
                        continue
                    if "==" in line:
                        p_name, p_ver = line.split("==", 1)
                        p_name = p_name.strip()
                        p_ver = p_ver.split(";")[0].split("#")[0].strip()
                        if p_name and p_ver:
                            results.append((p_name, p_ver, f"manifest:{rel_path}"))

            elif fname == "go.mod":
                text = fpath.read_text(encoding="utf-8", errors="replace")
                in_require = False
                mod_self_name: str | None = None
                for line in text.splitlines():
                    line = line[:4096].strip()
                    if line.startswith("module "):
                        m_parts = line.removeprefix("module ").strip().split()
                        if m_parts and not m_parts[0].startswith("//"):
                            mod_self_name = m_parts[0]
                        continue
                    if line.startswith("require ("):
                        in_require = True
                        continue
                    if in_require and line == ")":
                        in_require = False
                        continue
                    if in_require or line.startswith("require "):
                        line_content = line.removeprefix("require ").strip()
                        parts = line_content.split()
                        if len(parts) >= 2 and not parts[0].startswith("//"):
                            m_name = parts[0]
                            mod_ver = parts[1]
                            results.append((m_name, mod_ver, f"manifest:{rel_path}"))
                if mod_self_name:
                    for v_cand in (
                        fpath.parent / "version" / "VERSION",
                        fpath.parent / "VERSION",
                        root / "version" / "VERSION",
                        root / "VERSION",
                    ):
                        if v_cand.is_file():
                            try:
                                v_txt = v_cand.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                                if v_txt:
                                    v_first = v_txt[0].strip()
                                    if re.match(r"^v?\d+\.\d+\.\d+[0-9A-Za-z._\-]*$", v_first):
                                        results.append((mod_self_name, v_first, f"manifest:{rel_path}"))
                                        break
                            except OSError:
                                pass
            elif fname in ("build.gradle", "build.gradle.kts", "dependencies.gradle"):
                text = fpath.read_text(encoding="utf-8", errors="replace")
                gradle_vars: dict[str, str] = {}
                for m_gv in re.finditer(
                    r"\b([a-zA-Z0-9_]+)\s*[:=]\s*['\"]([0-9]+\.[0-9]+[0-9A-Za-z._\-]*)['\"]",
                    text,
                ):
                    gradle_vars[m_gv.group(1)] = m_gv.group(2)
                for m_gr in re.finditer(
                    r"['\"]([a-zA-Z0-9._\-]+):([a-zA-Z0-9._\-]+):([^'\"]+)['\"]",
                    text,
                ):
                    g_art = m_gr.group(2)
                    g_ver = m_gr.group(3).strip()
                    if g_ver.startswith("$"):
                        var_key = g_ver.lstrip("$").strip("{}").split(".")[-1]
                        g_ver = gradle_vars.get(var_key, "")
                    if g_ver and re.match(r"^\d+\.\d+", g_ver):
                        results.append((g_art, g_ver, f"manifest:{rel_path}"))
                # Spring Boot Gradle BOM DSL: library("Name", "1.2.3") { ... }
                if "library(" in text:
                    bom_import_map = {
                        "spring-framework-bom": ("spring-beans", "spring-webmvc"),
                        "jackson-bom": ("jackson-databind",),
                        "netty-bom": ("netty-codec-http2",),
                        "log4j-bom": ("log4j-core",),
                    }
                    for m_lib in re.finditer(
                        r'library\(\s*["\'][^"\']+["\']\s*,\s*["\']([0-9]+\.[0-9]+[0-9A-Za-z._\-]*)["\']\s*\)\s*\{(.*?)\n\t\}',
                        text,
                        re.DOTALL,
                    ):
                        l_ver = m_lib.group(1)
                        l_body = m_lib.group(2)
                        for m_mod in re.finditer(r'["\']([a-zA-Z0-9._\-]+)["\']', l_body):
                            tok = m_mod.group(1)
                            if tok in bom_import_map:
                                for mapped_art in bom_import_map[tok]:
                                    results.append((mapped_art, l_ver, f"manifest:{rel_path}"))
                            elif "-" in tok or tok in ("snakeyaml", "postgresql", "gson", "h2"):
                                results.append((tok, l_ver, f"manifest:{rel_path}"))
                for gp_cand in (fpath.parent / "gradle.properties", root / "gradle.properties"):
                    if gp_cand.is_file():
                        try:
                            gp_txt = gp_cand.read_text(encoding="utf-8", errors="replace")
                            for gp_line in gp_txt.splitlines():
                                gp_s = gp_line.strip()
                                if not gp_s or gp_s.startswith("#") or "=" not in gp_s:
                                    continue
                                k_gp, v_gp = [x.strip() for x in gp_s.split("=", 1)]
                                if k_gp == "pgjdbc.version" and v_gp:
                                    results.append(("postgresql", v_gp, f"manifest:{rel_path}"))
                                elif k_gp.endswith(".version") and re.match(r"^\d+\.\d+", v_gp):
                                    c_gp = k_gp.removesuffix(".version")
                                    results.append((c_gp, v_gp, f"manifest:{rel_path}"))
                        except OSError:
                            pass

            elif fname == "libs.versions.toml":
                text = fpath.read_text(encoding="utf-8", errors="replace")
                toml_data = tomllib.loads(text)
                vers_tbl = toml_data.get("versions", {})
                libs_tbl = toml_data.get("libraries", {})
                if isinstance(libs_tbl, dict):
                    for lib_val in libs_tbl.values():
                        if isinstance(lib_val, str) and lib_val.count(":") == 2:
                            _, l_art, l_ver = lib_val.split(":", 2)
                            results.append((l_art, l_ver, f"manifest:{rel_path}"))
                        elif isinstance(lib_val, dict):
                            mod_str = str(lib_val.get("module") or "")
                            l_art = mod_str.split(":")[-1] if ":" in mod_str else str(lib_val.get("name") or "")
                            v_obj = lib_val.get("version")
                            l_ver = ""
                            if isinstance(v_obj, str):
                                l_ver = v_obj
                            elif isinstance(v_obj, dict):
                                ref_k = str(v_obj.get("ref") or "")
                                if isinstance(vers_tbl, dict) and ref_k in vers_tbl:
                                    l_ver = str(vers_tbl[ref_k])
                                elif v_obj.get("strictly") or v_obj.get("require"):
                                    l_ver = str(v_obj.get("strictly") or v_obj.get("require"))
                            if l_art and l_ver:
                                results.append((l_art, l_ver, f"manifest:{rel_path}"))

            elif fname in ("conanfile.txt", "conanfile.py"):
                text = fpath.read_text(encoding="utf-8", errors="replace")
                for m_cn in re.finditer(
                    r"\b([a-zA-Z0-9_.\-]+)/(\d+\.\d+\.\d+[a-zA-Z0-9_.\-]*)",
                    text,
                ):
                    results.append((m_cn.group(1), m_cn.group(2), f"manifest:{rel_path}"))

            elif fname in ("Directory.Packages.props", "Directory.Build.props", "packages.config") or fname.endswith(".csproj"):
                root_elem = safe_parse_xml_bytes(fpath.read_bytes())
                if root_elem is not None:
                    cs_pkg_id: str | None = None
                    cs_ver: str | None = None
                    for elem in root_elem.iter():
                        e_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        if e_tag in ("PackageReference", "PackageVersion", "package"):
                            inc = elem.attrib.get("Include") or elem.attrib.get("Update") or elem.attrib.get("id")
                            ver_attr = elem.attrib.get("Version") or elem.attrib.get("version")
                            if not ver_attr:
                                for ch in elem:
                                    ch_t = ch.tag.split("}")[-1] if "}" in ch.tag else ch.tag
                                    if ch_t in ("Version", "version") and ch.text:
                                        ver_attr = ch.text.strip()
                            if inc and ver_attr and not ver_attr.startswith("$"):
                                results.append((inc.strip(), ver_attr.strip(), f"manifest:{rel_path}"))
                        elif e_tag in ("PackageId", "AssemblyName") and elem.text and not cs_pkg_id:
                            cs_pkg_id = elem.text.strip()
                        elif e_tag in ("VersionPrefix", "Version") and elem.text and not cs_ver:
                            cs_ver = elem.text.strip()
                    if not cs_pkg_id and fname.endswith(".csproj"):
                        cs_pkg_id = fname.removesuffix(".csproj")
                    if cs_pkg_id and cs_ver and not cs_ver.startswith("$"):
                        results.append((cs_pkg_id, cs_ver, f"manifest:{rel_path}"))
        except Exception:  # noqa: BLE001
            continue

    # Second pass for pom.xml files using resolved workspace properties and dependencyManagement
    for rel_path, root_elem, local_props, proj_art_id, eff_ver in parsed_poms:
        try:
            merged_props = {**global_maven_props, **local_props}
            if proj_art_id and eff_ver:
                res_proj_ver = _resolve_maven_prop(eff_ver, merged_props)
                if res_proj_ver and not res_proj_ver.startswith("$"):
                    results.append((proj_art_id, res_proj_ver, f"manifest:{rel_path}"))

            parent_map = {c: p for p in root_elem.iter() for c in p}
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
                    if in_mgmt:
                        continue

                    scope_val = None
                    art_id = None
                    ver_val = None
                    for child in elem:
                        c_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        c_text = (child.text or "").strip()
                        if c_tag == "scope":
                            scope_val = c_text.lower()
                        elif c_tag == "artifactId":
                            art_id = c_text
                        elif c_tag == "version":
                            ver_val = c_text
                    if scope_val == "test" or not art_id:
                        continue
                    resolved_ver = (
                        _resolve_maven_prop(ver_val, merged_props)
                        if ver_val
                        else resolved_dep_mgmt.get(art_id, "")
                    )
                    if resolved_ver and not resolved_ver.startswith("$"):
                        results.append((art_id, resolved_ver, f"manifest:{rel_path}"))
                    if art_id in ("spring-boot-starter-web", "spring-boot-starter"):
                        for st_comp in ("spring-beans", "spring-web", "snakeyaml", "jackson-databind"):
                            st_ver = resolved_dep_mgmt.get(st_comp)
                            if st_ver and not st_ver.startswith("$"):
                                results.append((st_comp, st_ver, f"manifest:{rel_path}"))
        except Exception:  # noqa: BLE001
            continue

    return results


_GENERIC_BARE_ARTIFACT_BLOCKLIST: frozenset[str] = frozenset(
    {
        "core",
        "common",
        "commons",
        "client",
        "server",
        "service",
        "services",
        "api",
        "util",
        "utils",
        "shared",
        "parent",
        "model",
        "models",
        "plugin",
        "plugins",
        "engine",
        "runtime",
        "console",
        "admin",
        "webapp",
        "web",
        "http",
        "portal",
        "gateway",
        "proxy",
        "broker",
        "router",
        "driver",
        "adapter",
        "bridge",
        "config",
        "security",
        "crypto",
        "auth",
        "oauth",
        "oauth2",
        "storage",
        "database",
        "db",
        "search",
        "analytics",
        "logging",
        "logger",
        "metrics",
        "monitor",
        "monitoring",
        "testing",
        "test",
        "support",
        "autoconfigure",
        "starter",
        "bom",
        "all",
        "sdk",
        "cli",
        "ui",
        "app",
        "main",
        "base",
        "kernel",
        "framework",
        "platform",
        "tools",
        "tool",
        "helper",
        "helpers",
        "handler",
        "handlers",
        "manager",
        "provider",
        "registry",
        "connector",
        "agent",
        "worker",
        "daemon",
        "node",
        "cluster",
        "protocol",
        "transport",
        "codec",
        "parser",
        "compiler",
        "builder",
        "generator",
        "validator",
        "filter",
        "interceptor",
        "context",
        "session",
        "cache",
        "queue",
        "stream",
        "events",
        "event",
        "messaging",
        "mail",
        "xml",
        "json",
        "yaml",
        "csv",
        "sql",
        "jdbc",
        "jpa",
        "orm",
        "rest",
        "graphql",
        "grpc",
        "ws",
        "websocket",
    }
)

_SEMVER_KEY_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[-._+]?([0-9A-Za-z.-]*))?$"
)


def _parse_version_key(v: str) -> tuple[int, int, int, int, int, str] | None:
    """Parse version string into a comparable tuple: (major, minor, patch, sub, rel_rank, suffix)."""
    s = v.strip().lstrip("vV")
    if not s or s.startswith("0.0.0-20"):
        return None
    m = _SEMVER_KEY_RE.match(s)
    if not m:
        return None
    maj = int(m.group(1) or 0)
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    sub = int(m.group(4) or 0)
    qual = (m.group(5) or "").lower().strip("-._+")
    if not qual or qual in ("final", "ga", "release"):
        rel_rank = 10
    elif any(qual.startswith(p) for p in ("alpha", "a", "dev", "pre", "snapshot")):
        rel_rank = 1
    elif any(qual.startswith(p) for p in ("beta", "b")):
        rel_rank = 2
    elif any(qual.startswith(p) for p in ("m", "milestone")):
        rel_rank = 3
    elif any(qual.startswith(p) for p in ("rc", "cr")):
        rel_rank = 4
    else:
        rel_rank = 10
    return (maj, minor, patch, sub, rel_rank, qual)


def _version_in_ranges(ver_str: str, ranges: list[dict[str, Any]]) -> bool:
    """Evaluate whether ver_str falls inside any [introduced, fixed) version range."""
    vk = _parse_version_key(ver_str)
    if vk is None:
        return False
    for r in ranges:
        if not isinstance(r, dict):
            continue
        intro = str(r.get("introduced") or "0").strip()
        fixed = str(r.get("fixed") or "").strip()
        fk = _parse_version_key(fixed)
        if fk is None:
            continue
        if intro and intro != "0":
            ik = _parse_version_key(intro)
            if ik is not None and vk < ik:
                continue
        else:
            # Lazy OSV introduced="0" guard: when fixed major >= 1, constrain to same major branch
            if fk[0] >= 1 and vk[0] != fk[0]:
                continue
        if vk < fk:
            return True
    return False


_DEFAULT_KB_INDEX_CACHE: tuple[int, dict[str, list[dict[str, Any]]]] | None = None


def _get_vuln_kb_index(
    kb_vulns: list[dict[str, Any]],
    custom_kb_path: str | Path | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Build or retrieve O(1) hash-table index mapping normalized component keys to KB rules."""
    global _DEFAULT_KB_INDEX_CACHE  # noqa: PLW0603
    if custom_kb_path is None and _DEFAULT_KB_INDEX_CACHE is not None:
        cached_len, cached_idx = _DEFAULT_KB_INDEX_CACHE
        if cached_len == len(kb_vulns):
            return cached_idx

    index: dict[str, list[dict[str, Any]]] = {}
    for entry in kb_vulns:
        aliases = list(entry.get("aliases") or entry.get("component_aliases") or [])
        target_comp = str(entry.get("component") or (aliases[0] if aliases else ""))
        all_names = [target_comp] + aliases
        entry_keys: set[str] = set()
        for alias in all_names:
            a_norm = _normalize_component_name(str(alias))
            if not a_norm:
                continue
            entry_keys.add(a_norm)
            if a_norm.startswith("lib") and len(a_norm) > 3:
                entry_keys.add(a_norm[3:])
            if ":" in a_norm:
                after_col = a_norm.split(":")[-1]
                if len(after_col) >= 6 and after_col not in _GENERIC_BARE_ARTIFACT_BLOCKLIST:
                    entry_keys.add(after_col)
        for k in entry_keys:
            index.setdefault(k, []).append(entry)

    if custom_kb_path is None:
        _DEFAULT_KB_INDEX_CACHE = (len(kb_vulns), index)
    return index


def _infer_candidate_ecosystem(source: str) -> str | None:
    """Infer package ecosystem from candidate evidence source."""
    if source.startswith(("lockfile:", "manifest:")):
        rel_path = source.split(":", 1)[1]
        fname = Path(rel_path).name
        if fname.endswith(".csproj"):
            return "NUGET"
        eco = ECOSYSTEM_MAP.get(fname)
        if eco == "GRADLE":
            return "MAVEN"
        if eco in ("OPKG", "BITBAKE"):
            return None
        return eco
    if source.startswith("archive_maven:"):
        return "MAVEN"
    if source.startswith("binary_go_dep:"):
        return "GO"
    if source.startswith("binary_rust_crate:"):
        return "CARGO"
    if source.startswith(("binary_catalog:", "binary_symbol_version:", "binary_banner:")):
        return "C_CPP"
    if source.startswith("internal_manifest:"):
        s_lower = source.lower()
        if "cmakelists" in s_lower or ".h" in s_lower:
            return "C_CPP"
        if "cargo" in s_lower:
            return "CARGO"
        if "package.json" in s_lower:
            return "NPM"
        if "pom" in s_lower:
            return "MAVEN"
    return None


_MAVEN_GROUP_ID_MAP: dict[str, str] = {
    "jenkins-core": "org.jenkins-ci.main",
    "log4j-core": "org.apache.logging.log4j",
    "spring-beans": "org.springframework",
    "spring-webmvc": "org.springframework",
    "spring-web": "org.springframework",
    "spring-core": "org.springframework",
    "spring-context": "org.springframework",
    "spring-security-web": "org.springframework.security",
    "spring-security-core": "org.springframework.security",
    "spring-cloud-function-context": "org.springframework.cloud",
    "spring-cloud-gateway-server": "org.springframework.cloud",
    "commons-text": "org.apache.commons",
    "commons-collections": "commons-collections",
    "commons-collections4": "org.apache.commons",
    "commons-fileupload": "commons-fileupload",
    "commons-io": "commons-io",
    "commons-configuration2": "org.apache.commons",
    "commons-compress": "org.apache.commons",
    "snakeyaml": "org.yaml",
    "postgresql": "org.postgresql",
    "activemq-client": "org.apache.activemq",
    "activemq-openwire-legacy": "org.apache.activemq",
    "bcprov-jdk15on": "org.bouncycastle",
    "bcprov-jdk18on": "org.bouncycastle",
    "fastjson": "com.alibaba",
    "struts2-core": "org.apache.struts",
    "tomcat-catalina": "org.apache.tomcat",
    "tomcat-embed-core": "org.apache.tomcat.embed",
    "itextpdf": "com.itextpdf",
    "mysql-connector-j": "com.mysql",
    "mysql-connector-java": "mysql",
    "jackson-databind": "com.fasterxml.jackson.core",
    "netty-codec-http": "io.netty",
    "netty-codec-http2": "io.netty",
    "netty-handler": "io.netty",
    "xstream": "com.thoughtworks.xstream",
    "shiro-core": "org.apache.shiro",
    "shiro-web": "org.apache.shiro",
    "velocity-engine-core": "org.apache.velocity",
    "freemarker": "org.freemarker",
    "gson": "com.google.code.gson",
    "guava": "com.google.guava",
    "protobuf-java": "com.google.protobuf",
    "jetty-http": "org.eclipse.jetty",
    "jetty-server": "org.eclipse.jetty",
    "h2": "com.h2database",
    "derby": "org.apache.derby",
    "hibernate-core": "org.hibernate.orm",
    "zookeeper": "org.apache.zookeeper",
    "kafka-clients": "org.apache.kafka",
    "woodstox-core": "com.fasterxml.woodstox",
    "jsoup": "org.jsoup",
    "pdfbox": "org.apache.pdfbox",
    "poi-ooxml": "org.apache.poi",
    "poi": "org.apache.poi",
    "xmlbeans": "org.apache.xmlbeans",
    "xercesimpl": "xerces",
    "xalan": "xalan",
    "dom4j": "org.dom4j",
    "okhttp": "com.squareup.okhttp3",
    "retrofit": "com.squareup.retrofit2",
    "grpc-netty-shaded": "io.grpc",
    "grpc-core": "io.grpc",
    "keycloak-core": "org.keycloak",
    "keycloak-services": "org.keycloak",
    "quartz": "org.quartz-scheduler",
    "c3p0": "com.mchange",
    "hikaricp": "com.zaxxer",
}


def _build_purl(
    component: str,
    version: str,
    ecosystem: str,
    aliases: list[Any] | None = None,
) -> str:
    """Build a canonical Package URL (pkg:type/namespace/name@version) for a component."""
    eco = ecosystem.upper()
    ver_part = "" if not version or " " in version else f"@{version.lstrip('v')}"
    if "MAVEN" in eco or "GRADLE" in eco:
        if ":" in component:
            gid, aid = component.split(":", 1)
            return f"pkg:maven/{gid}/{aid}{ver_part}"
        if aliases:
            for al in aliases:
                al_str = str(al)
                if ":" in al_str:
                    gid, aid = al_str.split(":", 1)
                    return f"pkg:maven/{gid}/{aid}{ver_part}"
        mapped_gid = _MAVEN_GROUP_ID_MAP.get(component) or _MAVEN_GROUP_ID_MAP.get(component.lower())
        if mapped_gid:
            return f"pkg:maven/{mapped_gid}/{component}{ver_part}"
        return f"pkg:maven/{component}/{component}{ver_part}"
    if "GO" in eco:
        go_ver = "" if not version or " " in version else (f"@{version}" if version.startswith("v") else f"@v{version}")
        return f"pkg:golang/{component}{go_ver}"
    if "PYTHON" in eco or "PIP" in eco or "PYPI" in eco:
        return f"pkg:pypi/{component.lower().replace('_', '-')}{ver_part}"
    if "NPM" in eco:
        return f"pkg:npm/{component}{ver_part}"
    if "CARGO" in eco or "RUST" in eco:
        return f"pkg:cargo/{component}{ver_part}"
    if "NUGET" in eco:
        return f"pkg:nuget/{component}{ver_part}"
    if "COMPOSER" in eco or "PACKAGIST" in eco:
        return f"pkg:composer/{component}{ver_part}"
    if "RUBY" in eco or "GEM" in eco:
        return f"pkg:gem/{component}{ver_part}"
    return f"pkg:generic/{component}{ver_part}"


def match_pareto_vulnerabilities(
    report: PrescanReport,
    bdio_components: list[dict[str, Any]] | None = None,
    custom_kb_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Match workspace dependencies and binaries against Pareto Vulnerability Knowledge Base.

    Enforces ecosystem compatibility when candidate has an explicit manifest ecosystem
    and attaches Black Duck SCA Server confirmation guidance to all findings.
    """
    kb_vulns = load_pareto_vuln_kb(custom_kb_path)
    if not kb_vulns:
        return []

    candidates: list[tuple[str, str, str]] = []

    # 1. Lockfiles and manifests
    root = Path(report.get("workspace_root", ".")).resolve()
    candidates.extend(
        extract_pinned_manifest_components(
            root,
            report.get("lockfiles", []),
            report.get("unpinned_manifests", []),
        )
    )

    # 2. Deep packet inspection
    dpi = report.get("deep_packet_inspection", {})

    for a in dpi.get("filename_version_assertions", []):
        aname = a.get("artifact_name")
        aver = a.get("asserted_version")
        if aname and aver and aver != "unversioned":
            candidates.append((str(aname), str(aver), f"assertion:{a.get('relative_path')}"))

    for arch in dpi.get("archive_metadata", []):
        aid = arch.get("artifact_id") or arch.get("group_id")
        aver = arch.get("version")
        if aid and aver and aver != "unversioned":
            candidates.append((str(aid), str(aver), f"archive:{arch.get('path')}"))
        for mc in arch.get("maven_coordinates", []):
            m_aid = mc.get("artifactId") or mc.get("artifact_id")
            m_ver = mc.get("version")
            if m_aid and m_ver:
                candidates.append((str(m_aid), str(m_ver), f"archive_maven:{arch.get('path')}"))

    for tm in dpi.get("tarball_metadata", []):
        top = tm.get("top_level_prefix")
        if isinstance(top, dict):
            t_name = top.get("name")
            t_ver = top.get("version")
            if t_name and t_ver and t_ver != "unversioned":
                candidates.append((str(t_name), str(t_ver), f"tarball:{tm.get('path')}"))

    for b in dpi.get("binary_inspection", []):
        for c in b.get("catalog_version_matches", []):
            if c.get("component") and c.get("version"):
                candidates.append((str(c["component"]), str(c["version"]), f"binary_catalog:{b.get('path')}"))
        for g in b.get("go_dependencies", []):
            if g.get("module") and g.get("version"):
                candidates.append((str(g["module"]), str(g["version"]), f"binary_go_dep:{b.get('path')}"))
        for r in b.get("rust_crates", []):
            rc_name = r.get("crate") or r.get("name")
            if rc_name and r.get("version"):
                candidates.append((str(rc_name), str(r["version"]), f"binary_rust_crate:{b.get('path')}"))
        for s in b.get("symbol_versions", []):
            if s.get("library") and s.get("version"):
                candidates.append((str(s["library"]), str(s["version"]), f"binary_symbol_version:{b.get('path')}"))
        for gb in b.get("generic_binary_banners", []):
            if gb.get("component") and gb.get("version"):
                candidates.append((str(gb["component"]), str(gb["version"]), f"binary_banner:{b.get('path')}"))
        pe_info = b.get("pe_version_info", {})
        if pe_info.get("ProductVersion"):
            pname = Path(str(b.get("path", ""))).stem
            candidates.append((pname, str(pe_info["ProductVersion"]), f"binary_pe:{b.get('path')}"))

    for imd in dpi.get("internal_manifest_discoveries", []):
        if imd.get("component") and imd.get("version") and imd.get("version") != "unversioned":
            candidates.append((str(imd["component"]), str(imd["version"]), f"internal_manifest:{imd.get('path')}"))

    # 3. BDIO components
    if bdio_components is not None:
        for bc in bdio_components:
            bname = bc.get("name")
            bver = bc.get("version")
            if bname and bver and bver != "unversioned":
                candidates.append((str(bname), str(bver), f"bdio:{bc.get('identifier', bname)}"))
    elif "detect_verification" in report:
        for bc in report["detect_verification"].get("components", []):
            bname = bc.get("name")
            bver = bc.get("version")
            if bname and bver and bver != "unversioned":
                candidates.append((str(bname), str(bver), f"bdio:{bc.get('identifier', bname)}"))

    kb_index = _get_vuln_kb_index(kb_vulns, custom_kb_path)
    hits_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    methods_by_key: dict[tuple[str, str, str, str], list[str]] = {}

    for cand_name, cand_ver, source in candidates:
        if not cand_ver or cand_ver == "unversioned":
            continue
        c_norm = _normalize_component_name(cand_name)
        c_without_lib = c_norm[3:] if c_norm.startswith("lib") and len(c_norm) > 3 else c_norm
        c_after_colon = c_norm.split(":")[-1]

        cand_eco = _infer_candidate_ecosystem(source)

        lookup_keys = {c_norm, c_without_lib}
        if len(c_after_colon) >= 6 and c_after_colon not in _GENERIC_BARE_ARTIFACT_BLOCKLIST:
            lookup_keys.add(c_after_colon)

        candidate_entries: list[dict[str, Any]] = []
        seen_entry_ids: set[int] = set()
        for lk in lookup_keys:
            for e in kb_index.get(lk, ()):
                eid = id(e)
                if eid not in seen_entry_ids:
                    seen_entry_ids.add(eid)
                    candidate_entries.append(e)

        for entry in candidate_entries:
            # Enforce ecosystem compatibility if candidate has an explicit ecosystem
            entry_eco = str(entry.get("ecosystem", "")).upper()
            if cand_eco and entry_eco and cand_eco not in entry_eco:
                continue

            aliases = list(entry.get("aliases") or entry.get("component_aliases") or [])
            target_comp = str(entry.get("component") or (aliases[0] if aliases else ""))
            all_names = [target_comp] + aliases

            matched_name = False
            for alias in all_names:
                a_norm = _normalize_component_name(str(alias))
                if ":" in c_norm and ":" in a_norm and c_norm != a_norm:
                    continue
                a_without_lib = a_norm[3:] if a_norm.startswith("lib") and len(a_norm) > 3 else a_norm
                a_after_colon = (
                    a_norm.split(":")[-1]
                    if (":" not in a_norm or (len(a_norm.split(":")[-1]) >= 6 and a_norm.split(":")[-1] not in _GENERIC_BARE_ARTIFACT_BLOCKLIST))
                    else a_norm
                )

                if (
                    c_norm in (a_norm, a_without_lib, a_after_colon)
                    or c_without_lib in (a_norm, a_without_lib, a_after_colon)
                    or (
                        c_after_colon not in _GENERIC_BARE_ARTIFACT_BLOCKLIST
                        and c_after_colon in (a_norm, a_without_lib, a_after_colon)
                    )
                ):
                    matched_name = True
                    break

            if not matched_name:
                continue

            vuln_re = entry.get("vulnerable_version_regex")
            vuln_ranges = entry.get("vulnerable_ranges")
            if not vuln_re and not vuln_ranges:
                continue

            ver_clean = cand_ver.strip().lstrip("v")
            ver_raw = cand_ver.strip()
            version_matched = bool(
                (vuln_re and (re.search(vuln_re, ver_raw) or re.search(vuln_re, ver_clean)))
                or (isinstance(vuln_ranges, list) and _version_in_ranges(ver_clean, vuln_ranges))
            )

            if version_matched:
                if ":" in source:
                    src_method, src_target = source.split(":", 1)
                else:
                    src_method, src_target = "match", source
                hit_key = (entry["cve_id"], target_comp, ver_clean, src_target)
                if hit_key not in hits_by_key:
                    fixed_ver = entry.get("fixed_in_version") or entry.get("fixed_version") or "latest"
                    pub_date = str(entry.get("published_date") or "")
                    pre_nvd = bool(entry.get("pre_nvd", False))
                    remedy = str(
                        entry.get(
                            "actionable_remedy",
                            entry.get("remediation") or f"Upgrade {target_comp} to {fixed_ver} or higher.",
                        )
                    )
                    osv_id = str(entry.get("osv_id") or "")
                    if pub_date.startswith(("2025-", "2026-")) and "[HOT " not in remedy and "[PRE-NVD " not in remedy:
                        badge = "PRE-NVD" if pre_nvd else "HOT"
                        cite = f" / {osv_id}" if (osv_id and osv_id != entry["cve_id"]) else (" / CISA-KEV" if entry.get("cisa_kev") else "")
                        remedy = f"{remedy} [{badge} {pub_date}{cite}]"
                    methods_by_key[hit_key] = [src_method]
                    hits_by_key[hit_key] = {
                        "cve_id": entry["cve_id"],
                        "component": target_comp,
                        "installed_version": cand_ver,
                        "purl": _build_purl(
                            target_comp,
                            cand_ver,
                            entry_eco,
                            aliases=list(entry.get("aliases") or []),
                        ),
                        "fixed_in_version": str(fixed_ver),
                        "cvss": entry.get("cvss", 0.0),
                        "cisa_kev": entry.get("cisa_kev", False),
                        "cwe": entry.get("cwe", "CWE-Unknown"),
                        "published_date": pub_date,
                        "pre_nvd": pre_nvd,
                        "evidence_source": source,
                        "actionable_remedy": remedy,
                        "confirmation_guidance": (
                            "Confirm vulnerability presence, CVSS score, and affected component "
                            "version using your licensed Black Duck SCA Server and KnowledgeBase."
                        ),
                    }
                else:
                    if src_method not in methods_by_key[hit_key]:
                        methods_by_key[hit_key].append(src_method)
                        merged_methods = "+".join(sorted(methods_by_key[hit_key]))
                        hits_by_key[hit_key]["evidence_source"] = f"{merged_methods}:{src_target}"

    # 4. Unpatched Code Snippet & Shaded-Bytecode Engine
    kb_cve_set = {str(e.get("cve_id", "")) for e in kb_vulns} if custom_kb_path is not None else None
    for snip in dpi.get("snippet_findings", []):
        snip_cve = str(snip.get("cve_id", ""))
        if not snip_cve:
            continue
        if kb_cve_set is not None and snip_cve not in kb_cve_set:
            continue
        snip_status = str(snip.get("status", ""))
        snip_loc = str(snip.get("location", ""))
        snip_arch = str(snip.get("archive_path", ""))
        snip_comp = str(snip.get("component", ""))
        snip_src_type = str(snip.get("source_type", "code_snippet"))

        cve_hits = [h for h in hits_by_key.values() if h.get("cve_id") == snip_cve]
        if snip_arch:
            matching_hits = [h for h in cve_hits if snip_arch in str(h.get("evidence_source", ""))]
        else:
            matching_hits = [
                h
                for h in cve_hits
                if not any(
                    t in str(h.get("evidence_source", ""))
                    for t in ("tarball:", "archive:", "archive_maven:", "binary_", "!/")
                )
            ]

        if snip_status == "UNPATCHED_SNIPPET":
            if matching_hits:
                for h in matching_hits:
                    h["snippet_verified"] = True
                    h["snippet_location"] = snip_loc
                    rem = str(h.get("actionable_remedy", ""))
                    if "[UNPATCHED-SNIPPET-VERIFIED:" not in rem:
                        h["actionable_remedy"] = f"{rem} [UNPATCHED-SNIPPET-VERIFIED: unpatched code in {snip_loc}]"
            else:
                if snip.get("has_archive_coordinates") is True:
                    continue
                inst_ver = (
                    "shaded (bytecode-pattern)"
                    if snip_src_type == "bytecode_pattern"
                    else "unversioned (code-snippet)"
                )
                hit_key = (snip_cve, snip_comp, inst_ver, snip_loc)
                if hit_key not in hits_by_key:
                    fixed_ver = str(snip.get("fixed_in_version") or "latest")
                    pub_date = str(snip.get("published_date") or "")
                    pre_nvd = bool(snip.get("pre_nvd", False))
                    remedy = str(
                        snip.get("actionable_remedy")
                        or f"Upgrade {snip_comp} to {fixed_ver} or higher."
                    )
                    osv_id = str(snip.get("osv_id") or "")
                    if pub_date.startswith(("2025-", "2026-")) and "[HOT " not in remedy and "[PRE-NVD " not in remedy:
                        badge = "PRE-NVD" if pre_nvd else "HOT"
                        cite = f" / {osv_id}" if (osv_id and osv_id != snip_cve) else (" / CISA-KEV" if snip.get("cisa_kev") else "")
                        remedy = f"{remedy} [{badge} {pub_date}{cite}]"
                    if "[UNPATCHED-SNIPPET-VERIFIED:" not in remedy:
                        remedy = f"{remedy} [UNPATCHED-SNIPPET-VERIFIED: unpatched code in {snip_loc}]"
                    methods_by_key[hit_key] = [snip_src_type]
                    hits_by_key[hit_key] = {
                        "cve_id": snip_cve,
                        "component": snip_comp,
                        "installed_version": inst_ver,
                        "purl": _build_purl(snip_comp, inst_ver, str(snip.get("ecosystem", ""))),
                        "fixed_in_version": fixed_ver,
                        "cvss": float(snip.get("cvss", 0.0)),
                        "cisa_kev": bool(snip.get("cisa_kev", False)),
                        "cwe": str(snip.get("cwe", "CWE-Unknown")),
                        "published_date": pub_date,
                        "pre_nvd": pre_nvd,
                        "evidence_source": f"{snip_src_type}:{snip_loc}",
                        "snippet_verified": True,
                        "snippet_location": snip_loc,
                        "actionable_remedy": remedy,
                        "confirmation_guidance": (
                            "Confirm vulnerability presence, CVSS score, and affected component "
                            "version using your licensed Black Duck SCA Server and KnowledgeBase."
                        ),
                    }
        elif snip_status == "PATCH_GUARD_PRESENT":
            for h in matching_hits:
                h["backport_guard_detected"] = True
                h["snippet_location"] = snip_loc
                rem = str(h.get("actionable_remedy", ""))
                if "[PATCH-GUARD-DETECTED:" not in rem:
                    h["actionable_remedy"] = (
                        f"{rem} [PATCH-GUARD-DETECTED: upstream security patch guard "
                        f"detected in {snip_loc}; verify if backported]"
                    )

    raw_hits = list(hits_by_key.values())
    raw_hits.sort(key=lambda x: (str(x.get("cve_id")), str(x.get("component")), str(x.get("evidence_source"))))

    # Consolidate identical (cve_id, component, installed_version) hits when > 3 locations match
    grouped_vulns: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for h in raw_hits:
        g_key = (str(h.get("cve_id")), str(h.get("component")), str(h.get("installed_version")))
        grouped_vulns.setdefault(g_key, []).append(h)

    hits: list[dict[str, Any]] = []
    for g_list in grouped_vulns.values():
        if len(g_list) <= 3:
            for item in g_list:
                item_copy = dict(item)
                item_copy["all_evidence_sources"] = [str(item["evidence_source"])]
                hits.append(item_copy)
        else:
            rep = dict(g_list[0])
            rep["all_evidence_sources"] = [str(x["evidence_source"]) for x in g_list]
            rep["evidence_source"] = f"{rep['evidence_source']} (+{len(g_list) - 1} locations)"
            hits.append(rep)

    hits.sort(key=lambda x: (str(x.get("cve_id")), str(x.get("component")), str(x.get("evidence_source"))))
    return hits


def match_pareto_license_risks(
    report: PrescanReport | dict[str, Any],
    bdio_components: list[dict[str, str]] | None = None,
    custom_kb_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Match workspace components and archive/source license texts against high-severity license & rugpull rules."""
    lic_rules = load_pareto_license_kb(custom_kb_path)
    candidates: list[tuple[str, str, str]] = []

    ws_root = Path(report.get("workspace_root", "."))
    if ws_root.is_dir():
        candidates.extend(
            extract_pinned_manifest_components(
                ws_root,
                report.get("lockfiles", []),
                report.get("unpinned_manifests", []),
            )
        )

    for p in report.get("pinned_manifest_components", []):
        if p.get("name") and p.get("version"):
            candidates.append((str(p["name"]), str(p["version"]), f"manifest:{p.get('source', '')}"))

    dpi = report.get("deep_packet_inspection", {})
    for a in dpi.get("filename_version_assertions", []):
        aname = a.get("artifact_name")
        aver = a.get("asserted_version")
        if aname and aver and aver != "unversioned":
            candidates.append((str(aname), str(aver), f"assertion:{a.get('relative_path')}"))

    for arch in dpi.get("archive_metadata", []):
        aid = arch.get("artifact_id") or arch.get("group_id")
        aver = arch.get("version")
        if aid and aver and aver != "unversioned":
            candidates.append((str(aid), str(aver), f"archive:{arch.get('path')}"))
        for mc in arch.get("maven_coordinates", []):
            m_aid = mc.get("artifactId") or mc.get("artifact_id")
            m_ver = mc.get("version")
            if m_aid and m_ver:
                candidates.append((str(m_aid), str(m_ver), f"archive_maven:{arch.get('path')}"))

    for tm in dpi.get("tarball_metadata", []):
        top = tm.get("top_level_prefix")
        if isinstance(top, dict):
            t_name = top.get("name")
            t_ver = top.get("version")
            if t_name and t_ver and t_ver != "unversioned":
                candidates.append((str(t_name), str(t_ver), f"tarball:{tm.get('path')}"))

    for b in dpi.get("binary_inspection", []):
        for c in b.get("catalog_version_matches", []):
            if c.get("component") and c.get("version"):
                candidates.append((str(c["component"]), str(c["version"]), f"binary_catalog:{b.get('path')}"))
        for g in b.get("go_dependencies", []):
            if g.get("module") and g.get("version"):
                candidates.append((str(g["module"]), str(g["version"]), f"binary_go_dep:{b.get('path')}"))
        for gb in b.get("generic_binary_banners", []):
            if gb.get("component") and gb.get("version"):
                candidates.append((str(gb["component"]), str(gb["version"]), f"binary_banner:{b.get('path')}"))

    for imd in dpi.get("internal_manifest_discoveries", []):
        if imd.get("component") and imd.get("version") and imd.get("version") != "unversioned":
            candidates.append((str(imd["component"]), str(imd["version"]), f"internal_manifest:{imd.get('path')}"))

    if bdio_components is not None:
        for bc in bdio_components:
            bname = bc.get("name")
            bver = bc.get("version")
            if bname and bver and bver != "unversioned":
                candidates.append((str(bname), str(bver), f"bdio:{bc.get('identifier', bname)}"))

    hits_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    methods_by_key: dict[tuple[str, str, str], list[str]] = {}

    for cand_name, cand_ver, source in candidates:
        if not cand_ver or cand_ver == "unversioned":
            continue
        c_norm = _normalize_component_name(cand_name)
        c_without_lib = c_norm[3:] if c_norm.startswith("lib") and len(c_norm) > 3 else c_norm
        c_after_colon = c_norm.split(":")[-1]
        cand_eco = _infer_candidate_ecosystem(source)

        for rule in lic_rules:
            rule_eco = str(rule.get("ecosystem", "")).upper()
            if cand_eco and rule_eco and cand_eco not in rule_eco:
                continue
            aliases = list(rule.get("aliases") or rule.get("component_aliases") or [])
            target_comp = str(rule.get("component") or (aliases[0] if aliases else ""))
            matched_name = False
            for alias in [target_comp] + aliases:
                a_norm = _normalize_component_name(str(alias))
                a_without_lib = a_norm[3:] if a_norm.startswith("lib") and len(a_norm) > 3 else a_norm
                a_after_colon = a_norm.split(":")[-1]
                if (
                    c_norm in (a_norm, a_without_lib, a_after_colon)
                    or c_without_lib in (a_norm, a_without_lib, a_after_colon)
                    or c_after_colon in (a_norm, a_without_lib, a_after_colon)
                ):
                    matched_name = True
                    break
            if not matched_name:
                continue

            ver_re = rule.get("affected_version_regex")
            if not ver_re:
                continue
            ver_clean = cand_ver.strip().lstrip("v")
            if re.search(str(ver_re), cand_ver.strip()) or re.search(str(ver_re), ver_clean):
                src_method, src_target = source.split(":", 1) if ":" in source else ("match", source)
                h_key = (str(rule["rule_id"]), ver_clean, src_target)
                if h_key not in hits_by_key:
                    methods_by_key[h_key] = [src_method]
                    hits_by_key[h_key] = {
                        "rule_id": str(rule["rule_id"]),
                        "component": target_comp,
                        "installed_version": cand_ver,
                        "license_id": str(rule.get("license_id") or rule.get("license_family") or "UNKNOWN"),
                        "previous_license": str(rule.get("previous_license", "")),
                        "severity": str(rule.get("severity", "HIGH")),
                        "safe_version_hint": str(rule.get("safe_version_hint") or rule.get("safe_version_note") or rule.get("remediation") or ""),
                        "summary": str(rule.get("summary") or rule.get("name") or ""),
                        "evidence_source": source,
                        "confirmation_guidance": (
                            "Confirm component license terms, commercial exceptions, and policy status "
                            "using your licensed Black Duck SCA Server and KnowledgeBase."
                        ),
                    }
                else:
                    if src_method not in methods_by_key[h_key]:
                        methods_by_key[h_key].append(src_method)
                        merged = "+".join(sorted(methods_by_key[h_key]))
                        hits_by_key[h_key]["evidence_source"] = f"{merged}:{src_target}"

    # Also include direct archive/source reciprocal license text discoveries (deduplicated per archive or rule_id for source trees)
    source_lic_groups: dict[str, dict[str, Any]] = {}
    for lic_disc in dpi.get("internal_license_discoveries", []):
        loc = str(lic_disc.get("location", ""))
        base_loc = loc.split("!/")[0]
        lic_id = str(lic_disc.get("license_id", ""))
        rule_id = f"LIC-DPI-{lic_id.upper().replace('.', '_')}"
        if "!/" in loc or base_loc.lower().endswith((".jar", ".war", ".ear", ".zip", ".tar.gz", ".tgz", ".whl")):
            h_key = (rule_id, "text_match", base_loc)
            if h_key not in hits_by_key:
                hits_by_key[h_key] = {
                    "rule_id": rule_id,
                    "component": Path(base_loc).name,
                    "installed_version": "detected_in_text",
                    "license_id": lic_id,
                    "previous_license": "",
                    "severity": str(lic_disc.get("severity", "HIGH")),
                    "safe_version_hint": "Review reciprocal license obligations with legal counsel or isolate/replace component.",
                    "summary": str(lic_disc.get("summary", "")),
                    "evidence_source": f"license_text:{loc}",
                    "confirmation_guidance": (
                        "Confirm license text match and obligation scope using your licensed Black Duck SCA Server."
                    ),
                }
        else:
            grp = source_lic_groups.setdefault(
                rule_id,
                {
                    "lic_disc": lic_disc,
                    "locations": [],
                },
            )
            if base_loc not in grp["locations"]:
                grp["locations"].append(base_loc)

    for rule_id, grp in source_lic_groups.items():
        locs: list[str] = grp["locations"]
        lic_disc = grp["lic_disc"]
        lic_id = str(lic_disc.get("license_id", ""))
        primary_loc = sorted(
            locs,
            key=lambda p: (
                0 if Path(p).name.upper().startswith(("LICENSE", "COPYING", "NOTICE")) and "/" not in p else (
                    1 if Path(p).name.upper().startswith(("LICENSE", "COPYING", "NOTICE")) else 2
                ),
                len(p),
                p,
            ),
        )[0]
        ev_src = (
            f"license_text:{primary_loc}"
            if len(locs) == 1
            else f"license_text:{primary_loc} (+{len(locs) - 1} files)"
        )
        h_key = (rule_id, "text_match", primary_loc)
        hits_by_key[h_key] = {
            "rule_id": rule_id,
            "component": Path(primary_loc).name,
            "installed_version": "detected_in_text",
            "license_id": lic_id,
            "previous_license": "",
            "severity": str(lic_disc.get("severity", "HIGH")),
            "safe_version_hint": "Review reciprocal license obligations with legal counsel or isolate/replace component.",
            "summary": str(lic_disc.get("summary", "")),
            "evidence_source": ev_src,
            "all_evidence_sources": [f"license_text:{loc}" for loc in locs],
            "confirmation_guidance": (
                "Confirm license text match and obligation scope using your licensed Black Duck SCA Server."
            ),
        }

    raw_results = list(hits_by_key.values())
    raw_results.sort(key=lambda x: (0 if x.get("severity") == "CRITICAL" else 1, str(x.get("rule_id")), str(x.get("evidence_source"))))

    grouped_lics: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in raw_results:
        g_key = (str(r.get("rule_id")), str(r.get("component")))
        grouped_lics.setdefault(g_key, []).append(r)

    results: list[dict[str, Any]] = []
    for g_list in grouped_lics.values():
        if len(g_list) <= 3:
            for item in g_list:
                item_copy = dict(item)
                if "all_evidence_sources" not in item_copy:
                    item_copy["all_evidence_sources"] = [str(item["evidence_source"])]
                results.append(item_copy)
        else:
            rep = dict(g_list[-1])
            all_ev: list[str] = []
            for x in g_list:
                all_ev.extend(x.get("all_evidence_sources") or [str(x["evidence_source"])])
            rep["all_evidence_sources"] = all_ev
            rep["evidence_source"] = f"{g_list[0]['evidence_source']} (+{len(g_list) - 1} locations)"
            results.append(rep)

    results.sort(key=lambda x: (0 if x.get("severity") == "CRITICAL" else 1, str(x.get("rule_id")), str(x.get("evidence_source"))))
    return results
