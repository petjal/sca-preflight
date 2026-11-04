---
schema: sca-ops-ai-brief/v1
workspace_name: sca_preflight_reference_scan
dlp_sanitized: true
host_paths_stripped: true
multilayer_codebase_signature: sca-sig:v2:L0=35a527e1d2b5:L1=9c52bea95b81:L2=9c52bea95b81:CFG=2adcf6e44988@d3(100.0%)
topology_skeleton_sha256: 35a527e1d2b54db1e3a43418804fe3f054719595c872cf95ac5ddce52e26e9d1
workspace_tree_merkle_sha256: 9c52bea95b81847932784ff9acf167f17929077c9d47992f2ea0eb04f3788cc7
dependency_inputs_merkle_sha256: 9c52bea95b81847932784ff9acf167f17929077c9d47992f2ea0eb04f3788cc7
effective_detect_config_sha256: 2adcf6e44988ff2a5c42cefade661dd8c321d5c11369e759349879c0ad4647a0
coverage_pct: 100.0
early_stop_triggered: false
total_dirs_scanned: 15
total_files_scanned: 24
total_workspace_mb: 0.01
bucket_1_excluded_dirs_count: 0
bucket_2a_actionable_l1_files_count: 24
bucket_2b_provenance_only_l2_files_count: 0
bucket_3_early_stop_unhashed_files_count: 0
dependency_inputs_hashed_count: 24
lockfiles_count: 0
lockfile_paired_manifests_count: 0
unpinned_manifests_count: 3
expected_min_bom_components: 8
actionable_vulnerabilities_count: 27
actionable_license_risks_count: 8
blind_spot_traps_count: 6
operational_warnings_count: 10
---

# AI-First SCA Pre-Flight, Provenance & Risk Brief (`sca_preflight_reference_scan`)

> **LLM Ingestion Instructions**: Point your enterprise AI assistant (Copilot, Claude, ChatGPT Enterprise) at this single file. All host paths are stripped to relative workspace paths and all integer totals are pre-computed in the YAML header above.

## 1. Stratified Multilayer Codebase Signature & Config Provenance (BDIO Blind-Spot Anchor)

| Provenance Layer | SHA-256 Digest / Signature | Operational Meaning |
| :--- | :--- | :--- |
| **Compact Multilayer Signature** | `sca-sig:v2:L0=35a527e1d2b5:L1=9c52bea95b81:L2=9c52bea95b81:CFG=2adcf6e44988@d3(100.0%)` | Single-line composite fingerprint (`L0` Topology + `L1` Dependency Control Plane + `L2` Source Tree + `CFG` Detect Flags + depth/coverage watermark). |
| **Layer 0: Topology Skeleton (`L0`)** | `35a527e1d2b54db1e3a43418804fe3f054719595c872cf95ac5ddce52e26e9d1` | Zero-file-read breadth-first directory skeleton (relative folders, file counts, extension mix, byte totals). Instantaneous across monorepos. |
| **Layer 1: BOM Control Plane (`L1`)** | `9c52bea95b81847932784ff9acf167f17929077c9d47992f2ea0eb04f3788cc7` | Multithreaded hash of 100% of 24 dependency-bearing inputs (manifests, lockfiles, Dockerfiles, and sparse-fingerprinted archives/binaries). If unchanged across commits, BOM inputs are identical. |
| **Layer 2: Top-Down Source Tree (`L2`)** | `9c52bea95b81847932784ff9acf167f17929077c9d47992f2ea0eb04f3788cc7` | Breadth-first multithreaded source digest covering 24/24 files (100.0%, max depth 3). |
| **Effective Detect Config (`CFG`)** | `2adcf6e44988ff2a5c42cefade661dd8c321d5c11369e759349879c0ad4647a0` | Canonical digest of the sorted recommended Detect CLI properties. |
| **SCA Web UI Provenance Flag** | `--detect.project.version.notes=sca-ops-provenance:sca-sig:v2:L0=35a527e1d2b5:L1=9c52bea95b81:L2=9c52bea95b81:CFG=2adcf6e44988@d3(100.0%);tree_merkle=sha256:9c52bea95b818479;dep_merkle=sha256:9c52bea95b818479;cfg_sha256=2adcf6e44988ff2a;files=24/24;dep_inputs=24` | Pass this flag to Detect to stamp exact input/config provenance into the Project Version Notes UI. |

### What `sca-prescan` Actually Inspected (`15` dirs, `24` files, `0.01` MB)
- **Pass 1 (Directory, Manifest & Encoding Walk)**: Traversed `15` directories and `24` files (`0.01` MB), classified `0` lockfile(s), `3` unpinned manifest(s), and `0` native/container build script(s), verified manifest character encodings (`UTF-8` vs `UTF-16LE/BE`), and measured max directory depths for detectors, binaries, and exclusions.
- **Pass 2 (In-Memory Archive, Binary & Header Inspection)**: Inspected `19` archive(s) and `2` compiled binary file(s) in memory without disk extraction, parsed `29` internal version headers/manifests (`META-INF/maven`, `MANIFEST.MF`, `PKG-INFO`, C `zlib.h`/`opensslv.h`/`VERSION.dat`), and checked `0` legal/SPDX attribution file(s).
- **Pass 3 (3-Layer Cryptographic Provenance Hashing)**: Hashed `15` directory skeletons (`L0`, 0 file reads), 100% of `24` dependency-bearing inputs (`L1`), and `24/24` source files (`L2`, `100.0%` coverage).
- **Pass 4 (100% Offline Version-Range & Rugpull Matching)**: Evaluated all discovered `(component, version)` pairs offline against the built-in Pareto CVE (`pareto_vuln_kb.json`) and license-rugpull (`pareto_license_kb.json`) catalogs (`0` outbound network calls).

### File & Byte Disposition Accounting (`24 + 0 + 0 = 24` files)

| Bucket | Count / Size | What `sca-prescan` Did With These Objects | What Default Detect (`depth=0`) Does With Them |
| :--- | :---: | :--- | :--- |
| **Bucket 1: Excluded Non-Shipping Dirs** | `0` dir(s) | Saw 0 non-shipping folder(s) (none), skipped traversal, and added to --detect.excluded.directories. | Skips .git by default, but traverses .venv, venv, or unlocked node_modules unless explicitly excluded. |
| **Bucket 2a: Actionable BOM, Vuln & Calibration Files (`L1`)** | `24` file(s) (`0.01` MB) | Hashed 100% into Layer 1 (L1) and extracted BOM baselines, C/C++ header versions, archive/binary metadata, and 27 CVE / 8 license hit(s). | DETECTOR only processes root (depth=0) package manifests; SILENTLY IGNORES depth>=1 manifests, UTF-16 manifests, C/C++ version headers, CMake/Makefiles, and standalone binaries (--individualFileMatching=NONE). |
| **Bucket 2b: Source & Doc Provenance Only (`L2 - L1`)** | `0` file(s) (`0.0` MB) | Hashed 0 first-party source/doc files into Layer 2 (L2) and scanned for embedded private keys (0 third-party BOM declarations). | Ignored by DETECTOR; Signature Scanner hashes directory structure as a whole. |
| **Bucket 3: Unhashed Beyond Monorepo Early-Stop Cap** | `0` file(s) | 0 files skipped (100% hashed). | Signature Scanner hashes all files; >10,000 files or >1 GB in one scan risks server queue timeouts. |

### Actionable Files Processed in Bucket 2a (`24` file(s): `sca-prescan` vs. Default Detect)

| File Path (Depth) | Bucket Sub-Type | What `sca-prescan` Extracted & Did | What Default Detect (`depth=0`) Does |
| :--- | :--- | :--- | :--- |
| `mode_1_knowns/lib/activemq-client-5.18.2.jar` (`d=2`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2023-46604 (CVSS 10.0, CISA-KEV). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_1_knowns/lib/bcprov-jdk15on-1.66.jar` (`d=2`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2020-28052 (CVSS 9.8). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_1_knowns/lib/commons-text-1.9.jar` (`d=2`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2022-42889 (CVSS 9.8, CISA-KEV). Flagged blind-spot trap: CVE-2022-42889. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_1_knowns/lib/itextpdf-5.5.13.3.jar` (`d=2`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched license risk: LIC-DPI-AGPL-3_0 (AGPL-3.0), LIC-RUGPULL-ITEXT-AGPL (AGPL-3.0-only). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_1_knowns/lib/log4j-core-2.14.1.jar` (`d=2`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2021-44228 (CVSS 10.0, CISA-KEV). Flagged blind-spot trap: CVE-2021-44228. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_1_knowns/lib/mysql-connector-j-8.0.33.jar` (`d=2`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched license risk: LIC-COPYLEFT-MYSQL-CONNECTOR-GPL2 (GPL-2.0-only (Universal FOSS Exception)). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_1_knowns/lib/postgresql-42.2.18.jar` (`d=2`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2022-21724 (CVSS 9.8). Flagged blind-spot trap: CVE-2022-21724. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_1_knowns/lib/snakeyaml-1.33.jar` (`d=2`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2022-1471 (CVSS 9.8). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_1_knowns/lib/spring-beans-5.3.17.jar` (`d=2`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2022-22965 (CVSS 9.8, CISA-KEV). Flagged blind-spot trap: CVE-2022-22965. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_1_knowns/services/ingress_proxy/go.mod` (`d=3`) | `2a-i Unpinned Manifest` | Unpinned manifest (2 direct dep(s), encoding=utf-8, depth=3); hashed into L1. Matched license risk: LIC-RUGPULL-MINIO-AGPL (AGPL-3.0-only), LIC-RUGPULL-HASHICORP-BSL (BSL-1.1). | SILENTLY IGNORED by DETECTOR at default --detect.detector.search.depth=0 (located at depth 3); if depth>=3 is set without build tools installed, risks Exit Code 5/15 (FAILURE_ACCURACY_NOT_MET). |
| `mode_2_unknowns/services/auth_worker/requirements.txt` (`d=3`) | `2a-i Unpinned Manifest` | Unpinned manifest (3 direct dep(s), encoding=utf-16-le, depth=3); hashed into L1. Matched vulnerability: CVE-2020-14343 (CVSS 9.8), CVE-2023-45803 (CVSS 7.5), CVE-2023-49083 (CVSS 7.5). | SILENTLY CORRUPTED / 0% BOM MATCH (utf-16-le encoding breaks default UTF-8 parser). |
| `mode_2_unknowns/services/ingress_proxy/go.mod` (`d=3`) | `2a-i Unpinned Manifest` | Unpinned manifest (3 direct dep(s), encoding=utf-8, depth=3); hashed into L1. Matched vulnerability: CVE-2023-39325 (CVSS 7.5, CISA-KEV), CVE-2023-45288 (CVSS 7.5), CVE-2024-24786 (CVSS 7.5). | SILENTLY IGNORED by DETECTOR at default --detect.detector.search.depth=0 (located at depth 3); if depth>=3 is set without build tools installed, risks Exit Code 5/15 (FAILURE_ACCURACY_NOT_MET). |
| `mode_2_unknowns/vendor/archives/PyYAML-5.3.1.tar.gz` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2020-14343 (CVSS 9.8). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_2_unknowns/vendor/archives/curl-8.3.0.tar.gz` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2023-38545 (CVSS 9.8, CISA-KEV). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_2_unknowns/vendor/archives/expat-2.6.2.tar.gz` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2024-45490 (CVSS 9.8). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_2_unknowns/vendor/archives/openssl-3.0.4.tar.gz` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2022-2274 (CVSS 9.8), CVE-2022-3602 (CVSS 7.5). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_2_unknowns/vendor/archives/readline-8.2.tar.gz` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched license risk: LIC-COPYLEFT-GNU-READLINE-GPL3 (GPL-3.0-only), LIC-DPI-GPL-3_0 (GPL-3.0). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_2_unknowns/vendor/archives/zlib-1.2.11.tar.gz` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2022-37434 (CVSS 9.8, CISA-KEV), CVE-2023-45853 (CVSS 9.8). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_2_unknowns/vendor/native/libdb_storage_kv.so` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched license risk: LIC-RUGPULL-REDIS-RSAL-SSPL (RSALv2 / SSPL-1.0). | SILENTLY IGNORED by Signature Scanner default --individualFileMatching=NONE (omits single-file SHA-1 checksums). |
| `mode_2_unknowns/vendor/native/libstorage_compress.so` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2022-37434 (CVSS 9.8, CISA-KEV), CVE-2023-45853 (CVSS 9.8). | SILENTLY IGNORED by Signature Scanner default --individualFileMatching=NONE (omits single-file SHA-1 checksums). |
| `mode_2_unknowns/vendor/npm_cache/cross-spawn-7.0.4.tgz` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2024-21538 (CVSS 9.8). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_2_unknowns/vendor/npm_cache/lodash-4.17.19.tgz` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2021-23337 (CVSS 9.8). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_2_unknowns/vendor/nuget_feed/newtonsoft.json.12.0.3.nupkg` (`d=3`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Extracted `Newtonsoft.Json 12.0.3` (nuspec). Matched vulnerability: CVE-2024-21907 (CVSS 7.5). | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `mode_2_unknowns/vendor/shaded/telemetry_agent_shaded.jar` (`d=3`) | `2a-iii Shaded / Fat Archive` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. Matched vulnerability: CVE-2021-44228 (CVSS 10.0, CISA-KEV), CVE-2022-42889 (CVSS 9.8, CISA-KEV). Flagged blind-spot trap: CVE-2022-42889, CVE-2021-44228. | BLIND-SPOT TRAP: Ignored by DETECTOR; Signature Scanner hashes outer archive only and misses shaded/repackaged inner classes unless deep inspection or BDBA is enabled. |

## 2. Tuned Detect CLI Invocation & Configuration Calibration

### 2.1 Baseline Safe Invocation (Default Detect Policy + Safe Runner Hygiene)
> **Stated Vendor Policy**: Run Detect with default settings (`--detect.tools=ALL`, `--detect.detector.search.depth=0`) first for predictable scan speed, adding only safe runner memory sizing, `.git`/`.venv` directory exclusions, and the Project Version Notes provenance stamp below. Comma-separated properties (`--detect.excluded.directories`, `--detect.tools`) should always be **additively concatenated** to any existing pipeline values.

```bash
java -jar detect.jar \
  --detect.blackduck.signature.scanner.memory=4096 \
  --detect.blackduck.signature.scanner.parallel.processors=1 \
  '--detect.project.version.notes=sca-ops-provenance:sca-sig:v2:L0=35a527e1d2b5:L1=9c52bea95b81:L2=9c52bea95b81:CFG=2adcf6e44988@d3(100.0%);tree_merkle=sha256:9c52bea95b818479;dep_merkle=sha256:9c52bea95b818479;cfg_sha256=2adcf6e44988ff2a;files=24/24;dep_inputs=24'
```

### 2.2 Optional Fuller-BOM & Buildless Tweaks (Trade-Offs Explained)

| Optional Detect Flag | What Hidden Files / Failures It Unlocks in This Repo | Performance & BOM Trade-Off |
| :--- | :--- | :--- |
| `--detect.detector.search.depth=3` | Discovers nested manifests/lockfiles down to directory depth 3 (default is 0, which stops at root and skips standalone/non-reactor subdirectories or buildless nested modules). | Increases detector filesystem walk and subproject inspector invocations across nested folders. |
| `--detect.binary.scan.search.depth=3` | Discovers binary/archive artifacts down to directory depth 3 when BINARY_SCAN (BDBA) is enabled with --detect.binary.scan.file.name.patterns (default is 0; does not affect SIGNATURE_SCAN). | Applies only when BINARY_SCAN is enabled; uploads matching nested archives to the BDBA worker. |
| `--detect.blackduck.signature.scanner.individual.file.matching=BINARY` | Computes single-file SHA-1 checksums for standalone binaries (.so, .dll, .exe, .o) omitted by default NONE. | Adds per-file SHA-1 matching overhead during Signature Scanning. |

### Operational & Calibration Signals
- NON_UTF8_MANIFEST_WARNING: Manifest 'mode_2_unknowns/services/auth_worker/requirements.txt' is encoded in utf-16-le instead of UTF-8 (common with Windows PowerShell 'pip freeze > requirements.txt'). Default UTF-8 manifest parsers emit null-byte-corrupted BDIO identifiers ('\u0000') when reading UTF-16 files, causing 0% of dependencies in 'mode_2_unknowns/services/auth_worker/requirements.txt' to match in the BOM unless converted to UTF-8.
- Unpinned package manifests detected (mode_1_knowns/services/ingress_proxy/go.mod, mode_2_unknowns/services/auth_worker/requirements.txt, mode_2_unknowns/services/ingress_proxy/go.mod). Detect 10 defaults to --detect.accuracy.required=ALL (HIGH), which will exit with Code 5 (FAILURE_DETECTOR: Accuracy Not Met) or Exit Code 15 (FAILURE_ACCURACY_NOT_MET) if package manager executables (pip, npm, go, mvn, gradle, cargo, dotnet, bazel, conan, bundle) or installed environments are missing unless --detect.accuracy.required=NONE is passed for buildless/unbuilt runs.
- Binary/archive artifacts found at depth 3. Detect defaults --detect.binary.scan.search.depth=0; added --detect.binary.scan.search.depth=3 to recommended arguments for BINARY_SCAN.
- Standalone binary files (.so, .dll, .exe, .bin, .o) detected. Since 2020.2.0 (Scanning Best Practices), Signature Scanner defaults --individualFileMatching=NONE and omits single-file SHA-1 checksums in generated BDIO archives for standalone binaries. Added --detect.blackduck.signature.scanner.individual.file.matching=BINARY so standard SCA servers match unmodified binaries by file checksum.
- BLIND-SPOT TRAP [CRITICAL]: CVE-2022-42889 (Text4Shell) detected in mode_1_knowns/lib/commons-text-1.9.jar!/org/apache/commons/text/StringSubstitutor.class - Text4Shell vulnerable Commons Text StringSubstitutor class present in archive.
- BLIND-SPOT TRAP [CRITICAL]: CVE-2021-44228 (Log4Shell) detected in mode_1_knowns/lib/log4j-core-2.14.1.jar!/org/apache/logging/log4j/core/lookup/JndiLookup.class - Log4Shell vulnerable JndiLookup class present in archive.
- BLIND-SPOT TRAP [CRITICAL]: CVE-2022-21724 (PgJDBC SocketFactory RCE) detected in mode_1_knowns/lib/postgresql-42.2.18.jar!/org/postgresql/Driver.class - PgJDBC unauthenticated arbitrary class instantiation RCE via AuthenticationPluginClassName / SocketFactory
- BLIND-SPOT TRAP [CRITICAL]: CVE-2022-22965 (Spring4Shell) detected in mode_1_knowns/lib/spring-beans-5.3.17.jar!/org/springframework/beans/CachedIntrospectionResults.class - Spring4Shell vulnerable CachedIntrospectionResults class present in archive.
- BLIND-SPOT TRAP [CRITICAL]: CVE-2022-42889 (Text4Shell) detected in mode_2_unknowns/vendor/shaded/telemetry_agent_shaded.jar!/org/apache/commons/text/StringSubstitutor.class - Text4Shell vulnerable Commons Text StringSubstitutor class present in archive.
- BLIND-SPOT TRAP [CRITICAL]: CVE-2021-44228 (Log4Shell) detected in mode_2_unknowns/vendor/shaded/telemetry_agent_shaded.jar!/org/apache/logging/log4j/core/lookup/JndiLookup.class - Log4Shell vulnerable JndiLookup class present in archive.

## 3. Expected BOM Baseline & Post-Scan Completeness Gate

- **Expected Minimum BOM Components**: `>= 8` across `3` code location(s)
- **Baseline Summary**: You should expect a BOM of at least 8 component version(s) across 3 code location(s) (0 locked + 8 direct unpinned; per-subproject sum prior to cross-module BOM deduplication), and here is why:
  - `[GO] mode_1_knowns/services/ingress_proxy`: `>= 2` component(s) (mode_1_knowns/services/ingress_proxy/go.mod declares 2 direct dependency(s); no lockfile)
  - `[PYTHON] mode_2_unknowns/services/auth_worker`: `>= 3` component(s) (mode_2_unknowns/services/auth_worker/requirements.txt declares 3 direct dependency(s); no lockfile)
  - `[GO] mode_2_unknowns/services/ingress_proxy`: `>= 3` component(s) (mode_2_unknowns/services/ingress_proxy/go.mod declares 3 direct dependency(s); no lockfile)

## 4. Actionable High-Severity Vulnerabilities (27)

> **Honest Scope (Small Hit-List, Zero Promises)**: `sca-prescan`'s built-in check is **not** a full SCA vulnerability database and **promises nothing** when it comes to comprehensive CVE coverage. Its built-in catalog is intentionally tiny - just a curated hit-list of well-known CVSS 9.8-10.0 / CISA-KEV disasters (like Log4Shell, Spring4Shell, Text4Shell, OpenSSL, zlib, curl, pgjdbc) and notorious open-source license rugpulls (`AGPL-3.0`, `SSPL-1.0`, `RSALv2`, `BSL-1.1`). Its job is to flag obvious worst-of-the-worst blind spots in seconds *before* your main SCA scanner runs, while tuning your main scanner's CLI flags so your real vulnerability database does its job properly.

| CVE ID | CVSS | KEV | Component & Version | Evidence Source | Actionable Remedy |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `CVE-2020-14343` | 9.8 | NO | `pyyaml 5.3.1` | `assertion+tarball:mode_2_unknowns/vendor/archives/PyYAML-5.3.1.tar.gz` | Upgrade PyYAML to 5.4 or higher and use yaml.safe_load. |
| `CVE-2020-14343` | 9.8 | NO | `pyyaml 5.3.1` | `manifest:mode_2_unknowns/services/auth_worker/requirements.txt` | Upgrade PyYAML to 5.4 or higher and use yaml.safe_load. |
| `CVE-2020-28052` | 9.8 | NO | `bcprov-jdk15on 1.66` | `archive+archive_maven+assertion:mode_1_knowns/lib/bcprov-jdk15on-1.66.jar` | Upgrade BouncyCastle bcprov-jdk15on to 1.67 or bcprov-jdk18on 1.78+. |
| `CVE-2021-23337` | 9.8 | NO | `lodash 4.17.19` | `assertion:mode_2_unknowns/vendor/npm_cache/lodash-4.17.19.tgz` | Upgrade lodash to 4.17.21 or higher. |
| `CVE-2021-44228` | 10.0 | YES | `log4j-core 2.14.1` | `archive+archive_maven+assertion:mode_1_knowns/lib/log4j-core-2.14.1.jar` | Upgrade log4j-core to 2.17.1 or higher (or 2.12.4 for Java 7). |
| `CVE-2021-44228` | 10.0 | YES | `log4j-core 2.14.1` | `archive_maven:mode_2_unknowns/vendor/shaded/telemetry_agent_shaded.jar` | Upgrade log4j-core to 2.17.1 or higher (or 2.12.4 for Java 7). |
| `CVE-2022-1471` | 9.8 | NO | `snakeyaml 1.33` | `archive+archive_maven+assertion:mode_1_knowns/lib/snakeyaml-1.33.jar` | Upgrade SnakeYAML to 2.0 or higher. |
| `CVE-2022-21724` | 9.8 | NO | `postgresql 42.2.18` | `archive+archive_maven+assertion:mode_1_knowns/lib/postgresql-42.2.18.jar` | Upgrade postgresql to 42.2.25 or higher. |
| `CVE-2022-2274` | 9.8 | NO | `openssl 3.0.4` | `assertion+tarball:mode_2_unknowns/vendor/archives/openssl-3.0.4.tar.gz` | Upgrade OpenSSL to 3.0.5 or higher. |
| `CVE-2022-22965` | 9.8 | YES | `spring-beans 5.3.17` | `archive+archive_maven+assertion:mode_1_knowns/lib/spring-beans-5.3.17.jar` | Upgrade spring-beans/spring-webmvc to 5.3.18 or 5.2.20 or higher. |
| `CVE-2022-3602` | 7.5 | NO | `openssl 3.0.4` | `assertion+tarball:mode_2_unknowns/vendor/archives/openssl-3.0.4.tar.gz` | Upgrade OpenSSL to 3.0.7 or higher. |
| `CVE-2022-37434` | 9.8 | YES | `zlib 1.2.11` | `assertion+tarball:mode_2_unknowns/vendor/archives/zlib-1.2.11.tar.gz` | Upgrade zlib to 1.2.12.1, 1.2.13, or higher. |
| `CVE-2022-37434` | 9.8 | YES | `zlib 1.2.11` | `binary_catalog:mode_2_unknowns/vendor/native/libstorage_compress.so` | Upgrade zlib to 1.2.12.1, 1.2.13, or higher. |
| `CVE-2022-42889` | 9.8 | YES | `commons-text 1.9` | `archive+archive_maven+assertion:mode_1_knowns/lib/commons-text-1.9.jar` | Upgrade commons-text to 1.10.0 or higher. |
| `CVE-2022-42889` | 9.8 | YES | `commons-text 1.9` | `archive_maven:mode_2_unknowns/vendor/shaded/telemetry_agent_shaded.jar` | Upgrade commons-text to 1.10.0 or higher. |
| `CVE-2023-38545` | 9.8 | YES | `curl 8.3.0` | `assertion+tarball:mode_2_unknowns/vendor/archives/curl-8.3.0.tar.gz` | Upgrade curl / libcurl to 8.4.0 or higher. |
| `CVE-2023-39325` | 7.5 | YES | `golang.org/x/net v0.16.0` | `manifest:mode_2_unknowns/services/ingress_proxy/go.mod` | Upgrade golang.org/x/net to v0.17.0 or higher. |
| `CVE-2023-45288` | 7.5 | NO | `golang.org/x/net v0.16.0` | `manifest:mode_2_unknowns/services/ingress_proxy/go.mod` | Upgrade golang.org/x/net to v0.23.0 or higher. |
| `CVE-2023-45803` | 7.5 | NO | `urllib3 1.26.4` | `manifest:mode_2_unknowns/services/auth_worker/requirements.txt` | Upgrade urllib3 to 1.26.18, 2.0.7, or higher. |
| `CVE-2023-45853` | 9.8 | NO | `zlib 1.2.11` | `assertion+tarball:mode_2_unknowns/vendor/archives/zlib-1.2.11.tar.gz` | Upgrade zlib / MiniZip to 1.3.1 or higher. |
| `CVE-2023-45853` | 9.8 | NO | `zlib 1.2.11` | `binary_catalog:mode_2_unknowns/vendor/native/libstorage_compress.so` | Upgrade zlib / MiniZip to 1.3.1 or higher. |
| `CVE-2023-46604` | 10.0 | YES | `activemq-client 5.18.2` | `archive+archive_maven+assertion:mode_1_knowns/lib/activemq-client-5.18.2.jar` | Upgrade ActiveMQ client and broker to 5.18.3, 5.17.6, or 5.16.7 or higher. |
| `CVE-2023-49083` | 7.5 | NO | `cryptography 41.0.5` | `manifest:mode_2_unknowns/services/auth_worker/requirements.txt` | Upgrade cryptography to 41.0.6 or higher. |
| `CVE-2024-21538` | 9.8 | NO | `cross-spawn 7.0.4` | `assertion:mode_2_unknowns/vendor/npm_cache/cross-spawn-7.0.4.tgz` | Upgrade cross-spawn to 7.0.5 or higher. |
| `CVE-2024-21907` | 7.5 | NO | `newtonsoft.json 12.0.3` | `internal_manifest:mode_2_unknowns/vendor/nuget_feed/newtonsoft.json.12.0.3.nupkg!/Newtonsoft.Json.nuspec` | Upgrade Newtonsoft.Json to 13.0.1 or higher. |
| `CVE-2024-24786` | 7.5 | NO | `google.golang.org/protobuf v1.31.0` | `manifest:mode_2_unknowns/services/ingress_proxy/go.mod` | Upgrade google.golang.org/protobuf to v1.33.0 or higher. |
| `CVE-2024-45490` | 9.8 | NO | `expat 2.6.2` | `assertion+tarball:mode_2_unknowns/vendor/archives/expat-2.6.2.tar.gz` | Upgrade libexpat to 2.6.3 or higher. |

## 5. High-Severity License & Rugpull Risks (8)

| Rule ID | Severity | Component & Version | License / Transition | Evidence Source | Safe Version / Remedy |
| :--- | :---: | :--- | :--- | :--- | :--- |
| `LIC-DPI-AGPL-3_0` | `CRITICAL` | `itextpdf-5.5.13.3.jar detected_in_text` | `AGPL-3.0` | `license_text:mode_1_knowns/lib/itextpdf-5.5.13.3.jar!/META-INF/LICENSE.txt` | Review reciprocal license obligations with legal counsel or isolate/replace component. |
| `LIC-RUGPULL-ITEXT-AGPL` | `CRITICAL` | `itextpdf 5.5.13.3` | `AGPL-3.0-only` (from MPL-1.1 / LGPL-2.0 (iText 2.1.7)) | `archive+archive_maven+assertion:mode_1_knowns/lib/itextpdf-5.5.13.3.jar` | OpenPDF (LGPL/MPL fork of iText 2.1.7) or Apache PDFBox (Apache-2.0) |
| `LIC-RUGPULL-MINIO-AGPL` | `CRITICAL` | `minio v0.0.0-20240310000000-111111111111` | `AGPL-3.0-only` (from Apache-2.0) | `manifest:mode_1_knowns/services/ingress_proxy/go.mod` | Verify commercial license agreement or isolate via strict out-of-process network boundary per legal review |
| `LIC-RUGPULL-REDIS-RSAL-SSPL` | `CRITICAL` | `redis 7.4.0` | `RSALv2 / SSPL-1.0` (from BSD-3-Clause) | `binary_banner:mode_2_unknowns/vendor/native/libdb_storage_kv.so` | Redis <= 7.2.x (BSD-3-Clause) or Valkey (BSD-3-Clause) |
| `LIC-COPYLEFT-GNU-READLINE-GPL3` | `HIGH` | `readline 8.2` | `GPL-3.0-only` (from GPL-3.0-only (not LGPL)) | `assertion+tarball:mode_2_unknowns/vendor/archives/readline-8.2.tar.gz` | Replace libreadline with BSD-licensed libedit (editline) or linenoise |
| `LIC-COPYLEFT-MYSQL-CONNECTOR-GPL2` | `HIGH` | `mysql-connector-java 8.0.33` | `GPL-2.0-only (Universal FOSS Exception)` (from GPL-2.0-only) | `archive+archive_maven+assertion:mode_1_knowns/lib/mysql-connector-j-8.0.33.jar` | Replace with MariaDB Connector/J (LGPL-2.1) or verify Oracle commercial/FOSS exception eligibility |
| `LIC-DPI-GPL-3_0` | `HIGH` | `readline-8.2.tar.gz detected_in_text` | `GPL-3.0` | `license_text:mode_2_unknowns/vendor/archives/readline-8.2.tar.gz!/readline-8.2/COPYING` | Review reciprocal license obligations with legal counsel or isolate/replace component. |
| `LIC-RUGPULL-HASHICORP-BSL` | `HIGH` | `vault v1.16.0` | `BSL-1.1` (from MPL-2.0) | `manifest:mode_1_knowns/services/ingress_proxy/go.mod` | OpenBao (MPL-2.0 fork of Vault) or pre-BSL MPL-2.0 releases |

## 6. Ready-to-Copy Prompts for Your Enterprise LLM

### 6.1 Prompts to Point at This AI-Intended Report (`LLM_INGESTION_REPORT.md`)
> [!NOTE]
> **Run Right Now (No Extra Code Needed)**: Paste this `LLM_INGESTION_REPORT.md` file into your company's internal AI (Copilot, Claude, ChatGPT Enterprise) with any of Prompts A1-A4 below.

- **Prompt A1 (CI Pipeline Calibration PR)**: *"Using Section 1 and Section 2 of this brief, write a pull-request description for our DevSecOps pipeline explaining which Detect CLI flags we are adding, which uncalibrated coverage gaps they close, and how the multilayer codebase signature (`L0/L1/L2/CFG`) works."*
- **Prompt A2 (Legal & License Rugpull Triage)**: *"Using Section 5 of this brief, group all AGPL-3.0, SSPL-1.0, RSALv2, BSL-1.1, and GPL findings by distribution risk for a shipped commercial appliance vs. internal tool, and list the exact non-copyleft drop-in replacements."*
- **Prompt A3 (Security Remediation Plan)**: *"Using Section 4 of this brief, prioritize all CISA-KEV and CVSS 9.8-10.0 vulnerabilities by artifact location (distinguishing standard manifests vs. shaded uber-JARs, nested vendor archives, and native binaries) and output a step-by-step upgrade plan."*
- **Prompt A4 (BOM Delta Cross-Examination)**: *"Compare Section 3 (Expected BOM Baseline) and Sections 4-5 (Deep Packet Inspection findings) in this brief against our current Project Version BOM export, and list every component that default detector settings omitted."*

### 6.2 InfoSec Self-Audit Prompts (For the Private `sca-ops-toolkit` Workbench & Sample Outputs)
> [!IMPORTANT]
> **Where is the Python source code? It lives in a separate, private repo (`sca-ops-toolkit`)**: This public `sca-preflight` repo only has the free test project (`benchmark/`) and sample output files (`examples/`).
>
> When Pete runs these scripts as his diagnostic workbench during a scan-tuning or server-troubleshooting engagement (or if you email **Pete (`pjalajas+sca-preflight@gmail.com`)** to review the scripts), your InfoSec reviewer can drop the plain, readable Python source folder (no compiled binaries or extra pip packages) into your internal AI with Prompts B1-B3 below to verify its safety boundaries. (You can also run the second half of **Prompt B3** on this `LLM_INGESTION_REPORT.md` file right now.)

- **Prompt B1 (Zero-Exfiltration & Network Boundary Audit)**: *"Audit all Python modules in the toolkit (`src/`). Enumerate every import or call involving network sockets, HTTP clients (`urllib`, `http`, `socket`), or subprocess execution. Verify that `sca-prescan`, `sca-tealeaves`, and `sca-log-sanitize` make zero outbound network connections during workspace analysis unless `--bd-url` is explicitly passed by the operator."*
- **Prompt B2 (Read-Only Workspace & Dry-Run Mutation Safety Audit)**: *"Audit `prescan.py`, `completeness.py`, and `bom_ifttt.py`. Verify that workspace scanning is strictly read-only on the target source tree, never executes untrusted build scripts (`mvn`, `gradle`, `npm`, `pip`), and that `BomIftttEngine` defaults to `dry_run=True` unless `--apply` is explicitly supplied."*
- **Prompt B3 (DLP & Output Sanitization Audit)**: *"Audit `log_sanitize.py` and this generated `LLM_INGESTION_REPORT.md` file. Verify that workstation paths, internal hostnames, private IPv4 addresses, and credentials (`--blackduck.api.token`, Bearer tokens, URI passwords) are stripped or tokenized before external sharing."*
