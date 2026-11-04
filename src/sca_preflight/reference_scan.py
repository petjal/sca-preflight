"""Armored Reference Scan ("SCA EICAR") & Deterministic Performance Scan Pile Generator.

Builds:
1. A compact, Base64-armored .tar.gz reference scan capsule (sca_preflight_reference_capsule.b64)
   containing Knowns, Unknowns, and Unversioned Snippets across 6 ecosystems (shaded uber-JARs,
   ELF .so binaries, tarballs, NuGet .nupkg, UTF-16LE requirements.txt, unversioned C/Java/Go
   code snippets, and AGPL/RSAL/SSPL/BSL/GPL license rugpulls) plus GROUND_TRUTH_MANIFEST.json.
2. A deterministic --scale-factor N polyglot source pile for scheduled Black Duck SCA
   performance benchmarking (tracking scan.cli duration, RSS memory, and bomengine trends).
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from sca_preflight.prescan import scan_workspace

CAPSULE_HEADER_BANNER = """# ==============================================================================
# SCA-PREFLIGHT: SCA PREFLIGHT REFERENCE SCAN CAPSULE
# Copyright (c) 2026 Emil Walter "Pete" Jalajas (pjalajas@gmail.com)
# Released under the MIT License (see LICENSE).
#
# NOTICE: This file contains a deterministic, synthetic polyglot SCA calibration
# workspace encoded as a Base64 .tar.gz stream so static repository scanners
# (GitHub Dependabot) do not flag the sample dependency manifests in git.
# It contains only synthetic metadata stubs and zero third-party GPL code blobs.
#
# POSIX 1-LINER TO UNPACK INTO /dev/shm/sca_preflight_reference_scan:
#   mkdir -p /dev/shm/sca_preflight_reference_scan && \\
#   grep -v '^#' benchmark/sca_preflight_reference_capsule.b64 | base64 -d | tar -xzf - -C /dev/shm/sca_preflight_reference_scan
# ==============================================================================
"""


def _make_jar_bytes(
    group_id: str,
    artifact_id: str,
    version: str,
    class_entries: list[str],
    license_text: str | None = None,
    extra_coords: list[tuple[str, str, str]] | None = None,
) -> bytes:
    """Create a deterministic, minimal valid JAR archive in memory (mtime=2026-11-03)."""
    buf = io.BytesIO()
    fixed_dt = (2026, 11, 3, 12, 0, 0)
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zi_mf = zipfile.ZipInfo("META-INF/MANIFEST.MF", date_time=fixed_dt)
        zf.writestr(
            zi_mf,
            f"Manifest-Version: 1.0\nImplementation-Title: {artifact_id}\nImplementation-Version: {version}\n",
        )
        all_coords = [(group_id, artifact_id, version)] + (extra_coords or [])
        for gid, aid, ver in all_coords:
            zi_p = zipfile.ZipInfo(f"META-INF/maven/{gid}/{aid}/pom.properties", date_time=fixed_dt)
            zf.writestr(zi_p, f"groupId={gid}\nartifactId={aid}\nversion={ver}\n")
        for cls_path in class_entries:
            zi_c = zipfile.ZipInfo(cls_path, date_time=fixed_dt)
            zf.writestr(zi_c, b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + cls_path.encode("utf-8"))
        if license_text:
            zi_l = zipfile.ZipInfo("META-INF/LICENSE.txt", date_time=fixed_dt)
            zf.writestr(zi_l, license_text.encode("utf-8"))
    return buf.getvalue()


def _make_tar_gz_bytes(prefix: str, files: dict[str, bytes]) -> bytes:
    """Create a deterministic, minimal valid .tar.gz archive in memory (mtime=1793707200 / 2026-11-03)."""
    raw_buf = io.BytesIO()
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=raw_buf, mtime=1793707200) as gz,
        tarfile.open(mode="w", fileobj=gz) as tf,
    ):
        for rel_name, content in sorted(files.items()):
            ti = tarfile.TarInfo(f"{prefix}/{rel_name}")
            ti.size = len(content)
            ti.mtime = 1793707200
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(content))
    return raw_buf.getvalue()


def build_reference_scan_tree(
    target_dir: str | Path,
    scale_factor: int = 1,
) -> dict[str, Any]:
    """Materialize the polyglot SCA EICAR reference scan tree (and optional scale_factor performance pile)."""
    root = Path(target_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)

    m1 = root / "mode_1_knowns"
    m2 = root / "mode_2_unknowns"
    (m1 / "lib").mkdir(parents=True, exist_ok=True)
    (m1 / "services" / "ingress_proxy").mkdir(parents=True, exist_ok=True)
    (m2 / "vendor" / "shaded").mkdir(parents=True, exist_ok=True)
    (m2 / "vendor" / "native").mkdir(parents=True, exist_ok=True)
    (m2 / "vendor" / "archives").mkdir(parents=True, exist_ok=True)
    (m2 / "vendor" / "npm_cache").mkdir(parents=True, exist_ok=True)
    (m2 / "vendor" / "nuget_feed").mkdir(parents=True, exist_ok=True)
    (m2 / "services" / "auth_worker").mkdir(parents=True, exist_ok=True)
    (m2 / "services" / "ingress_proxy").mkdir(parents=True, exist_ok=True)

    # 1. Mode 1 Knowns: JARs & Go manifest
    (m1 / "lib" / "log4j-core-2.14.1.jar").write_bytes(
        _make_jar_bytes(
            "org.apache.logging.log4j",
            "log4j-core",
            "2.14.1",
            ["org/apache/logging/log4j/core/lookup/JndiLookup.class"],
        )
    )
    (m1 / "lib" / "activemq-client-5.18.2.jar").write_bytes(
        _make_jar_bytes(
            "org.apache.activemq",
            "activemq-client",
            "5.18.2",
            ["org/apache/activemq/openwire/v11/BaseDataStreamMarshaller.class"],
        )
    )
    (m1 / "lib" / "spring-beans-5.3.17.jar").write_bytes(
        _make_jar_bytes(
            "org.springframework",
            "spring-beans",
            "5.3.17",
            ["org/springframework/beans/CachedIntrospectionResults.class"],
        )
    )
    (m1 / "lib" / "commons-text-1.9.jar").write_bytes(
        _make_jar_bytes(
            "org.apache.commons",
            "commons-text",
            "1.9",
            ["org/apache/commons/text/StringSubstitutor.class"],
        )
    )
    (m1 / "lib" / "snakeyaml-1.33.jar").write_bytes(
        _make_jar_bytes(
            "org.yaml",
            "snakeyaml",
            "1.33",
            ["org/yaml/snakeyaml/constructor/Constructor.class"],
        )
    )
    (m1 / "lib" / "bcprov-jdk15on-1.66.jar").write_bytes(
        _make_jar_bytes(
            "org.bouncycastle",
            "bcprov-jdk15on",
            "1.66",
            ["org/bouncycastle/crypto/generators/OpenBSDBCrypt.class"],
        )
    )
    (m1 / "lib" / "postgresql-42.2.18.jar").write_bytes(
        _make_jar_bytes(
            "org.postgresql",
            "postgresql",
            "42.2.18",
            ["org/postgresql/Driver.class"],
        )
    )
    (m1 / "lib" / "itextpdf-5.5.13.3.jar").write_bytes(
        _make_jar_bytes(
            "com.itextpdf",
            "itextpdf",
            "5.5.13.3",
            ["com/itextpdf/text/Document.class"],
            license_text="GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n",
        )
    )
    (m1 / "lib" / "mysql-connector-j-8.0.33.jar").write_bytes(
        _make_jar_bytes(
            "com.mysql",
            "mysql-connector-j",
            "8.0.33",
            ["com/mysql/cj/jdbc/Driver.class"],
        )
    )
    (m1 / "services" / "ingress_proxy" / "go.mod").write_text(
        "module calibration.example.com/s3-gateway\n\ngo 1.21\n\nrequire (\n"
        "\tgithub.com/minio/minio v0.0.0-20240310000000-111111111111\n"
        "\tgithub.com/hashicorp/vault v1.16.0\n)\n",
        encoding="utf-8",
    )

    # 2. Mode 2 Unknowns: Shaded uber-JAR, stripped ELF .so, tarballs, NuGet, UTF-16LE
    (m2 / "vendor" / "shaded" / "telemetry_agent_shaded.jar").write_bytes(
        _make_jar_bytes(
            "com.enterprise.telemetry",
            "telemetry-agent",
            "1.0.0",
            [
                "org/apache/logging/log4j/core/lookup/JndiLookup.class",
                "org/apache/commons/text/StringSubstitutor.class",
            ],
            extra_coords=[
                ("org.apache.logging.log4j", "log4j-core", "2.14.1"),
                ("org.apache.commons", "commons-text", "1.9"),
            ],
        )
    )
    (m2 / "vendor" / "native" / "libstorage_compress.so").write_bytes(
        b"\x7fELF\x02\x01\x01\x00"
        + b"\x00" * 32
        + b"deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly and Mark Adler\x00"
    )
    (m2 / "vendor" / "native" / "libdb_storage_kv.so").write_bytes(
        b"\x7fELF\x02\x01\x01\x00"
        + b"\x00" * 32
        + b"Redis/7.4.0\x00"
    )

    (m2 / "vendor" / "archives" / "openssl-3.0.4.tar.gz").write_bytes(
        _make_tar_gz_bytes("openssl-3.0.4", {"include/openssl/opensslv.h": b'#define OPENSSL_VERSION_STR "3.0.4"\n'})
    )
    (m2 / "vendor" / "archives" / "curl-8.3.0.tar.gz").write_bytes(
        _make_tar_gz_bytes("curl-8.3.0", {"include/curl/curlver.h": b'#define LIBCURL_VERSION "8.3.0"\n'})
    )
    (m2 / "vendor" / "archives" / "expat-2.6.2.tar.gz").write_bytes(
        _make_tar_gz_bytes("expat-2.6.2", {"lib/expat.h": b'#define EXPAT_VERSION "2.6.2"\n'})
    )
    (m2 / "vendor" / "archives" / "zlib-1.2.11.tar.gz").write_bytes(
        _make_tar_gz_bytes("zlib-1.2.11", {"zlib.h": b'#define ZLIB_VERSION "1.2.11"\n'})
    )
    (m2 / "vendor" / "archives" / "PyYAML-5.3.1.tar.gz").write_bytes(
        _make_tar_gz_bytes("PyYAML-5.3.1", {"PKG-INFO": b"Name: PyYAML\nVersion: 5.3.1\n"})
    )
    (m2 / "vendor" / "archives" / "readline-8.2.tar.gz").write_bytes(
        _make_tar_gz_bytes(
            "readline-8.2",
            {"COPYING": b"GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"},
        )
    )
    (m2 / "vendor" / "npm_cache" / "lodash-4.17.19.tgz").write_bytes(
        _make_tar_gz_bytes(
            "package",
            {"package.json": json.dumps({"name": "lodash", "version": "4.17.19"}).encode("utf-8")},
        )
    )
    (m2 / "vendor" / "npm_cache" / "cross-spawn-7.0.4.tgz").write_bytes(
        _make_tar_gz_bytes(
            "package",
            {"package.json": json.dumps({"name": "cross-spawn", "version": "7.0.4"}).encode("utf-8")},
        )
    )

    nupkg_buf = io.BytesIO()
    with zipfile.ZipFile(nupkg_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zi_nu = zipfile.ZipInfo("Newtonsoft.Json.nuspec", date_time=(2026, 11, 3, 12, 0, 0))
        zf.writestr(
            zi_nu,
            "<package><metadata><id>Newtonsoft.Json</id><version>12.0.3</version></metadata></package>",
        )
    (m2 / "vendor" / "nuget_feed" / "newtonsoft.json.12.0.3.nupkg").write_bytes(nupkg_buf.getvalue())

    req_utf16 = "PyYAML==5.3.1\nurllib3==1.26.4\ncryptography==41.0.5\n"
    (m2 / "services" / "auth_worker" / "requirements.txt").write_bytes(
        b"\xff\xfe" + req_utf16.encode("utf-16-le")
    )
    (m2 / "services" / "ingress_proxy" / "go.mod").write_text(
        "module calibration.example.com/ingress\n\ngo 1.21\n\nrequire (\n"
        "\tgolang.org/x/net v0.16.0\n"
        "\tgoogle.golang.org/grpc v1.55.0\n"
        "\tgoogle.golang.org/protobuf v1.31.0\n)\n",
        encoding="utf-8",
    )

    # 3. Mode 3 Unversioned Snippets & Stripped Shaded Bytecode (Zero Version Strings)
    m3 = root / "mode_3_unversioned_snippets"
    (m3 / "c_native").mkdir(parents=True, exist_ok=True)
    (m3 / "go_pre_nvd").mkdir(parents=True, exist_ok=True)
    (m3 / "java_unversioned").mkdir(parents=True, exist_ok=True)
    (m3 / "shaded_stripped").mkdir(parents=True, exist_ok=True)

    # 3a. Oct 26, 2026 CISA-KEV PHP allocator OOM UAF (CVE-2026-109618, no version header)
    (m3 / "c_native" / "zend_alloc.c").write_text(
        "static void zend_mm_safe_error(zend_mm_heap *heap, const char *format, size_t limit) {\n"
        "    heap->overflow = 0;\n"
        "    zend_bailout();\n"
        "}\n",
        encoding="utf-8",
    )

    # 3b. Oct 27, 2026 CISA-KEV Google Brotli decompression overflow (CVE-2026-111497, no version header)
    (m3 / "c_native" / "decode.c").write_text(
        "BrotliDecoderResult BrotliDecoderDecompressStream(BrotliDecoderState* s, size_t* available_in) {\n"
        "    int copy_len = s->ringbuffer_size - s->pos;\n"
        "    WriteRingBuffer(available_in, s);\n"
        "}\n",
        encoding="utf-8",
    )

    # 3c. Oct 30, 2026 Pre-NVD imgproxy SSRF (GHSA-hff9-5pqw-6w9f, no go.mod)
    (m3 / "go_pre_nvd" / "network.go").write_text(
        "package netutil\n"
        "func VerifyRequestURL(rawURL string) error {\n"
        "    return checkHost(rawURL)\n"
        "}\n",
        encoding="utf-8",
    )

    # 3d. 2025 CISA-KEV Apache Tomcat partial PUT RCE (CVE-2025-24813, no pom.xml)
    (m3 / "java_unversioned" / "DefaultServlet.java").write_text(
        "package org.apache.catalina.servlets;\n"
        "public class DefaultServlet {\n"
        "    protected File executePartialPut(HttpServletRequest req, Range range, String path) {\n"
        "        return new File(tempDir, path.replace('/', '.'));\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    # 3e. Shaded uber-JAR with META-INF/maven completely stripped and no version in filename (CVE-2021-44228)
    stripped_jar_buf = io.BytesIO()
    with zipfile.ZipFile(stripped_jar_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zi_mf = zipfile.ZipInfo("META-INF/MANIFEST.MF", date_time=(2026, 11, 3, 12, 0, 0))
        zf.writestr(zi_mf, "Manifest-Version: 1.0\nCreated-By: Maven Shade Plugin\n")
        zi_cls = zipfile.ZipInfo(
            "org/apache/logging/log4j/core/lookup/JndiLookup.class",
            date_time=(2026, 11, 3, 12, 0, 0),
        )
        zf.writestr(
            zi_cls,
            b"\xca\xfe\xba\xbe\x00\x00\x00\x34org/apache/logging/log4j/core/lookup/JndiLookup convert jndi:",
        )
    (m3 / "shaded_stripped" / "enterprise_gateway_shaded.jar").write_bytes(stripped_jar_buf.getvalue())

    # Optional scale-factor expansion for scheduled performance benchmarking
    if scale_factor > 1:
        perf_root = root / "perf_scale_modules"
        for idx in range(2, scale_factor + 1):
            mod_dir = perf_root / f"submodule_{idx:03d}"
            mod_dir.mkdir(parents=True, exist_ok=True)
            (mod_dir / "package.json").write_text(
                json.dumps(
                    {
                        "name": f"perf-submodule-{idx:03d}",
                        "version": "1.0.0",
                        "dependencies": {"lodash": "4.17.19", "cross-spawn": "7.0.4"},
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            (mod_dir / f"service_worker_{idx:03d}.c").write_text(
                f'/* Deterministic benchmark translation unit {idx:03d} */\n#include <zlib.h>\nint worker_{idx:03d}(void) {{ return 0; }}\n',
                encoding="utf-8",
            )

    report = scan_workspace(root, memory_limit_mb_override=6144)
    prov = report["scan_input_provenance"]
    traps = sorted({s["id"] for s in report["deep_packet_inspection"]["disaster_smells"]})
    ground_truth = {
        "schema": "sca-ops-reference-ground-truth/v1",
        "scale_factor": scale_factor,
        "multilayer_codebase_signature": prov["multilayer_codebase_signature"],
        "topology_skeleton_sha256": prov["topology_skeleton_sha256"],
        "workspace_tree_merkle_sha256": prov["workspace_tree_merkle_sha256"],
        "dependency_inputs_merkle_sha256": prov["dependency_inputs_merkle_sha256"],
        "effective_detect_config_sha256": prov["effective_detect_config_sha256"],
        "expected_vulnerability_matches_count": len(report["actionable_vulnerabilities"]),
        "expected_cves": sorted({v["cve_id"] for v in report["actionable_vulnerabilities"]}),
        "expected_license_rules": sorted({r["rule_id"] for r in report["actionable_license_risks"]}),
        "expected_blind_spot_traps": traps,
        "recommended_detect_arguments": report["recommended_detect_arguments"],
    }
    (root / "GROUND_TRUTH_MANIFEST.json").write_text(
        json.dumps(ground_truth, indent=2) + "\n", encoding="utf-8"
    )
    return ground_truth


def export_armored_capsule_b64(source_dir: str | Path, output_b64_path: str | Path) -> Path:
    """Package a reference scan directory into a deterministic Base64-armored .tar.gz capsule."""
    src = Path(source_dir).resolve()
    raw_tar_gz = io.BytesIO()
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=raw_tar_gz, mtime=1793707200) as gz,
        tarfile.open(mode="w", fileobj=gz) as tf,
    ):
        for fpath in sorted(src.rglob("*")):
            if fpath.is_file():
                rel = fpath.relative_to(src).as_posix()
                data = fpath.read_bytes()
                ti = tarfile.TarInfo(rel)
                ti.size = len(data)
                ti.mtime = 1793707200
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(data))

    b64_bytes = base64.b64encode(raw_tar_gz.getvalue()).decode("ascii")
    wrapped_lines = [b64_bytes[i : i + 76] for i in range(0, len(b64_bytes), 76)]
    out_file = Path(output_b64_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(CAPSULE_HEADER_BANNER + "\n".join(wrapped_lines) + "\n", encoding="utf-8")
    return out_file


def unpack_armored_capsule_b64(capsule_b64_path: str | Path, dest_dir: str | Path) -> Path:
    """Decode and extract a Base64-armored .tar.gz reference scan capsule into dest_dir."""
    cpath = Path(capsule_b64_path)
    b64_lines = [
        line.strip()
        for line in cpath.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    tar_gz_bytes = base64.b64decode("".join(b64_lines))
    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tar_gz_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.name.startswith("/") or ".." in member.name:
                raise ValueError(f"Unsafe path in capsule: {member.name}")
        tf.extractall(path=dest, filter="data")
    return dest
