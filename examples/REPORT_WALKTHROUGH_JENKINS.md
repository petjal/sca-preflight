---
schema: sca-ops-ai-brief/v1
workspace_name: jenkins
dlp_sanitized: true
host_paths_stripped: true
multilayer_codebase_signature: sca-sig:v2:L0=f8f133bf81ec:L1=4b1193082a77:L2=8185de89c633:CFG=30a0c11701f3@d8(41.9%)
topology_skeleton_sha256: f8f133bf81ecfcefb8bbf89efbe0a2ce83787bd13eb96bb4104035826bec20aa
workspace_tree_merkle_sha256: 8185de89c6336bed1d79f2112f017b166f14a8ea026d87c05de0dd2b4973937c
dependency_inputs_merkle_sha256: 4b1193082a77f9cef76631e54f1678096aab50ea8db3498dd577e6572c7238b2
effective_detect_config_sha256: 30a0c11701f37da8ebc20bb852a8edea005ef079b37109d129c1046006365910
coverage_pct: 41.9
early_stop_triggered: true
total_dirs_scanned: 1251
total_files_scanned: 12046
total_workspace_mb: 31.03
bucket_1_excluded_dirs_count: 1
bucket_2a_actionable_l1_files_count: 49
bucket_2b_provenance_only_l2_files_count: 5000
bucket_3_early_stop_unhashed_files_count: 6997
dependency_inputs_hashed_count: 49
lockfiles_count: 1
lockfile_paired_manifests_count: 1
unpinned_manifests_count: 9
expected_min_bom_components: 839
actionable_vulnerabilities_count: 6
actionable_license_risks_count: 0
blind_spot_traps_count: 0
operational_warnings_count: 6
---

# AI-First SCA Pre-Flight, Provenance & Risk Brief (`jenkins`)

> **LLM Ingestion Instructions**: Point your enterprise AI assistant (Copilot, Claude, ChatGPT Enterprise) at this single file. All host paths are stripped to relative workspace paths and all integer totals are pre-computed in the YAML header above.

## 1. Workspace Input & Config Hashes (L0 / L1 / L2 / CFG)

| Provenance Layer | SHA-256 Digest / Signature | Operational Meaning |
| :--- | :--- | :--- |
| **Compact Workspace Signature** | `sca-sig:v2:L0=f8f133bf81ec:L1=4b1193082a77:L2=8185de89c633:CFG=30a0c11701f3@d8(41.9%)` | Single-line composite fingerprint (`L0` Folder Tree + `L1` Dependency Inputs + `L2` Source Tree + `CFG` Detect Flags + depth/coverage watermark). |
| **Layer 0: Folder Tree Hash (`L0`)** | `f8f133bf81ecfcefb8bbf89efbe0a2ce83787bd13eb96bb4104035826bec20aa` | Zero-file-read breadth-first directory skeleton (relative folders, file counts, extension mix, byte totals). Instantaneous across monorepos. |
| **Layer 1: Dependency Input Hash (`L1`)** | `4b1193082a77f9cef76631e54f1678096aab50ea8db3498dd577e6572c7238b2` | Multithreaded hash of 100% of 49 dependency-bearing inputs (manifests, lockfiles, Dockerfiles, and sparse-fingerprinted archives/binaries). If unchanged across commits, BOM inputs are identical. |
| **Layer 2: Source File Hash (`L2`)** | `8185de89c6336bed1d79f2112f017b166f14a8ea026d87c05de0dd2b4973937c` | Breadth-first multithreaded source digest covering 5049/12046 files (41.9%, max depth 8). |
| **Effective Detect Config (`CFG`)** | `30a0c11701f37da8ebc20bb852a8edea005ef079b37109d129c1046006365910` | Canonical digest of the sorted recommended Detect CLI properties. |
| **SCA Web UI Provenance Flag** | `--detect.project.version.notes=sca-ops-provenance:sca-sig:v2:L0=f8f133bf81ec:L1=4b1193082a77:L2=8185de89c633:CFG=30a0c11701f3@d8(41.9%);tree_merkle=sha256:8185de89c6336bed;dep_merkle=sha256:4b1193082a77f9ce;cfg_sha256=30a0c11701f37da8;files=5049/12046;dep_inputs=49` | Pass this flag to Detect to stamp exact input/config provenance into the Project Version Notes UI. |

### What `sca-prescan` Actually Inspected (`1251` dirs, `12046` files, `31.03` MB)
- **Pass 1 (Directory, Manifest & Encoding Walk)**: Traversed `1251` directories and `12046` files (`31.03` MB), classified `1` lockfile(s), `1` lockfile-paired manifest(s), `9` unpinned manifest(s), and `1` native/container build script(s), verified manifest character encodings (`UTF-8` vs `UTF-16LE/BE`), and measured max directory depths for detectors, binaries, and exclusions.
- **Pass 2 (In-Memory Archive, Binary & Header Inspection)**: Inspected `35` archive(s) and `0` compiled binary file(s) in memory without disk extraction, parsed `5` internal version headers/manifests (`META-INF/maven`, `MANIFEST.MF`, `PKG-INFO`, C `zlib.h`/`opensslv.h`/`VERSION.dat`), and checked `2` legal/SPDX attribution file(s).
- **Pass 3 (3-Layer Cryptographic Provenance Hashing)**: Hashed `1251` directory skeletons (`L0`, 0 file reads), 100% of `49` dependency-bearing inputs (`L1`), and `5049/12046` source files (`L2`, `41.9%` coverage).
- **Pass 4 (100% Offline Version-Range & Rugpull Matching)**: Evaluated all discovered `(component, version)` pairs offline against the built-in Pareto CVE (`pareto_vuln_kb.json`) and license-rugpull (`pareto_license_kb.json`) catalogs (`0` outbound network calls).

### File & Byte Disposition Accounting (`49 + 5000 + 6997 = 12046` files)

| Bucket | Count / Size | What `sca-prescan` Did With These Objects | What Default Detect (`depth=0`) Does With Them |
| :--- | :---: | :--- | :--- |
| **Bucket 1: Excluded Non-Shipping Dirs** | `1` dir(s) | Saw 1 non-shipping folder(s) (.git), skipped traversal, and added to --detect.excluded.directories. | Skips .git by default, but traverses .venv, venv, or unlocked node_modules unless explicitly excluded. |
| **Bucket 2a: Actionable BOM, Vuln & Calibration Files (`L1`)** | `49` file(s) (`1.08` MB) | Hashed 100% into Layer 1 (L1) and extracted BOM baselines, C/C++ header versions, archive/binary metadata, and 6 CVE / 0 license hit(s). | DETECTOR only processes root (depth=0) package manifests; SILENTLY IGNORES depth>=1 manifests, UTF-16 manifests, C/C++ version headers, CMake/Makefiles, and standalone binaries (--individualFileMatching=NONE). |
| **Bucket 2b: Source & Doc Provenance Only (`L2 - L1`)** | `5000` file(s) (`29.95` MB) | Hashed 5000 first-party source/doc files into Layer 2 (L2), scanned for unpatched code snippets (1 source-snippet verification(s)) and embedded private keys (0 third-party BOM declarations). | Ignored by DETECTOR; Signature Scanner hashes directory structure as a whole. |
| **Bucket 3: Unhashed Beyond Monorepo Early-Stop Cap** | `6997` file(s) | Skipped L2 content hashing on 6997 deep source files beyond 5,000-file cap (L0 and L1 still 100% complete). | Signature Scanner hashes all files; >10,000 files or >1 GB in one scan risks server queue timeouts. |

### Actionable Files Processed in Bucket 2a (`49` file(s): `sca-prescan` vs. Default Detect)

| File Path (Depth) | Bucket Sub-Type | What `sca-prescan` Extracted & Did | What Default Detect (`depth=0`) Does |
| :--- | :--- | :--- | :--- |
| `core/pom.xml` (`d=1`) | `2a-i Maven Reactor Module` | Maven child module POM (72 direct dep(s), declared in parent <modules>, depth=1); hashed into L1. Matched vulnerability: CVE-2024-23897 (CVSS 9.8, CISA-KEV). | Traversed at depth=0 ONLY if parent Maven CLI reactor succeeds (mvn dependency:tree); SILENTLY IGNORED at default depth=0 in buildless mode (requires --detect.detector.search.depth>=1 and --detect.detector.search.continue=true). |
| `coverage/pom.xml` (`d=1`) | `2a-i Maven Reactor Module` | Maven child module POM (3 direct dep(s), declared in parent <modules>, depth=1); hashed into L1. Matched vulnerability: CVE-2024-23897 (CVSS 9.8, CISA-KEV). | Traversed at depth=0 ONLY if parent Maven CLI reactor succeeds (mvn dependency:tree); SILENTLY IGNORED at default depth=0 in buildless mode (requires --detect.detector.search.depth>=1 and --detect.detector.search.continue=true). |
| `pom.xml` (`d=0`) | `2a-i Root Aggregator POM` | Root Maven aggregator POM (1 direct dep(s), declares child <modules>, encoding=utf-8); hashed into L1. Matched vulnerability: CVE-2024-23897 (CVSS 9.8, CISA-KEV). | Processed by DETECTOR at root depth=0 (Maven CLI traverses declared <modules>, but skips standalone non-reactor POMs and Gradle subprojects unless depth and continue=true are set). |
| `test/pom.xml` (`d=1`) | `2a-i Maven Reactor Module` | Maven child module POM (20 direct dep(s), declared in parent <modules>, depth=1); hashed into L1. Matched vulnerability: CVE-2024-23897 (CVSS 9.8, CISA-KEV). | Traversed at depth=0 ONLY if parent Maven CLI reactor succeeds (mvn dependency:tree); SILENTLY IGNORED at default depth=0 in buildless mode (requires --detect.detector.search.depth>=1 and --detect.detector.search.continue=true). |
| `war/pom.xml` (`d=1`) | `2a-i Maven Reactor Module` | Maven child module POM (7 direct dep(s), declared in parent <modules>, depth=1); hashed into L1. Matched vulnerability: CVE-2024-23897 (CVSS 9.8, CISA-KEV). | Traversed at depth=0 ONLY if parent Maven CLI reactor succeeds (mvn dependency:tree); SILENTLY IGNORED at default depth=0 in buildless mode (requires --detect.detector.search.depth>=1 and --detect.detector.search.continue=true). |
| `war/yarn.lock` (`d=1`) | `2a-i Lockfile` | Pinned lockfile (719 locked component(s), encoding=utf-8); hashed into L1. Matched vulnerability: CVE-2024-21538 (CVSS 9.8), CVE-2026-106445 (CVSS 9.8), CVE-2026-106446 (CVSS 9.8), CVE-2026-29063 (CVSS 9.8), CVE-2026-33937 (CVSS 9.8). | SILENTLY IGNORED by DETECTOR at default --detect.detector.search.depth=0 (located at depth 1). |
| `.gitpod/Dockerfile` (`d=1`) | `2a-ii Containerfile` | Extracted base image declaration(s): gitpod/workspace-full; hashed into L1. | SILENTLY IGNORED by standard source DETECTOR scan (requires CONTAINER_SCAN on built image tar). |
| `cli/pom.xml` (`d=1`) | `2a-i Maven Reactor Module` | Maven child module POM (12 direct dep(s), declared in parent <modules>, depth=1); hashed into L1. | Traversed at depth=0 ONLY if parent Maven CLI reactor succeeds (mvn dependency:tree); SILENTLY IGNORED at default depth=0 in buildless mode (requires --detect.detector.search.depth>=1 and --detect.detector.search.continue=true). |
| `war/package.json` (`d=1`) | `2a-i Manifest (Lockfile-Paired)` | Package manifest (32 direct dep(s), paired with sibling lockfile, encoding=utf-8, depth=1); hashed into L1. Extracted `jenkins-ui 1.0.0` (package_json). | SILENTLY IGNORED by DETECTOR at default --detect.detector.search.depth=0 (located at depth 1). |
| `websocket/jetty10/pom.xml` (`d=2`) | `2a-i Maven Reactor Module` | Maven child module POM (4 direct dep(s), declared in parent <modules>, depth=2); hashed into L1. | Traversed at depth=0 ONLY if parent Maven CLI reactor succeeds (mvn dependency:tree); SILENTLY IGNORED at default depth=0 in buildless mode (requires --detect.detector.search.depth>=2 and --detect.detector.search.continue=true). |
| `websocket/spi/pom.xml` (`d=2`) | `2a-i Maven Reactor Module` | Maven child module POM (1 direct dep(s), declared in parent <modules>, depth=2); hashed into L1. | Traversed at depth=0 ONLY if parent Maven CLI reactor succeeds (mvn dependency:tree); SILENTLY IGNORED at default depth=0 in buildless mode (requires --detect.detector.search.depth>=2 and --detect.detector.search.continue=true). |
| `LICENSE.txt` (`d=0`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `bom/pom.xml` (`d=1`) | `2a-i Maven Reactor Module` | Maven child module POM (0 direct dep(s), declared in parent <modules>, depth=1); hashed into L1. | Traversed at depth=0 ONLY if parent Maven CLI reactor succeeds (mvn dependency:tree); SILENTLY IGNORED at default depth=0 in buildless mode (requires --detect.detector.search.depth>=1 and --detect.detector.search.continue=true). |
| `test/src/test/resources/hudson/ClassicPluginStrategyTest/testDependencyClassLoader.zip` (`d=6`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/ClassicPluginStrategyTest/testDisabledDependencyClassLoader.zip` (`d=6`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/ClassicPluginStrategyTest/testMaskResourceClassLoader.zip` (`d=6`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/FilePathTest/ZipSlipSamePathPrefix/evil-win.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/FilePathTest/ZipSlipSamePathPrefix/evil.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/FilePathTest/zip_with_relative/zip-rel-one-up.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/FilePathTest/zip_with_relative/zip-slip-win.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/FilePathTest/zip_with_relative/zip-slip.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/FilePathTest/zip_with_relative/zip-with-folder.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/diagnosis/OldDataMonitorTest/robustness.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/init/impl/GroovyInitScriptTest/errorsHandled.zip` (`d=8`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/DependencyGraphTest/testItemReadPermission.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/ItemGroupMixInTest/xmlFileReadCannotResolveClassException.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/ItemGroupMixInTest/xmlFileReadExceptionOnLoad.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/JobTest/configDotXmlPermission.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/JobTest/getArtifactsUpTo.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/ParametersAction2Test/backwardCompatibility.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/QueueTest/recover_from_legacy_list.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/ViewTest/testAllViewCreatedIfNoPrimary.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/ViewTest/testAllViewNotCreatedIfPrimary.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/model/update-center.json.zip` (`d=6`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/tasks/ArtifactArchiverTest/fingerprintMigration.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/tasks/ArtifactArchiverTest/followSymlinksEnabledForOldConfig.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/tasks/ArtifactArchiverTest/latestOnlyMigration.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/tasks/BatchFileTest/canLoadUnstableReturnFromDisk.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/tasks/FingerprinterTest/actionSerialization.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/tasks/ShellTest/canLoadUnstableReturnFromDisk.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/tasks/maven-empty.zip` (`d=6`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/util/ProcessTreeKiller-test-project.jar` (`d=6`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/hudson/util/RobustReflectionConverterTest/randomExceptionsReported.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/jenkins/install/LoadDetachedPluginsTest/installDetachedDependencies/example.zip` (`d=8`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/jenkins/model/BuildDiscarderPropertyTest/buildDiscarderField.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/jenkins/security/ApiTokenPropertyTest/migrationFromLegacyToken.zip` (`d=7`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/plugins/annotations-test-sources.jar` (`d=5`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `test/src/test/resources/simple-projects.zip` (`d=4`) | `2a-iii Archive / Binary` | Inspected in memory for internal POM/manifest metadata, shaded classes, and binary version strings; hashed into L1. | Ignored by DETECTOR; Signature Scanner hashes archive structure, but shaded classes with stripped POMs require deep inspection or BDBA. |
| `war/src/main/resources/images/symbols/LICENCE` (`d=6`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |

## 2. Tuned Detect CLI Invocation & Configuration Calibration

### 2.1 Baseline Safe Invocation (Default Detect Policy + Safe Runner Hygiene)
> **Stated Vendor Policy**: Run Detect with default settings (`--detect.tools=ALL`, `--detect.detector.search.depth=0`) first for predictable scan speed, adding only safe runner memory sizing, `.git`/`.venv` directory exclusions, and the Project Version Notes provenance stamp below. Comma-separated properties (`--detect.excluded.directories`, `--detect.tools`) should always be **additively concatenated** to any existing pipeline values.

```bash
java -jar detect.jar \
  --detect.blackduck.signature.scanner.memory=4096 \
  --detect.blackduck.signature.scanner.parallel.processors=1 \
  --detect.excluded.directories=.git \
  '--detect.project.version.notes=sca-ops-provenance:sca-sig:v2:L0=f8f133bf81ec:L1=4b1193082a77:L2=8185de89c633:CFG=30a0c11701f3@d8(41.9%);tree_merkle=sha256:8185de89c6336bed;dep_merkle=sha256:4b1193082a77f9ce;cfg_sha256=30a0c11701f37da8;files=5049/12046;dep_inputs=49'
```

### 2.2 Optional Fuller-BOM & Buildless Tweaks (Trade-Offs Explained)

| Optional Detect Flag | What Hidden Files / Failures It Unlocks in This Repo | Performance & BOM Trade-Off |
| :--- | :--- | :--- |
| `--detect.detector.search.depth=2` | Discovers nested manifests/lockfiles down to directory depth 2 (default is 0, which stops at root and skips standalone/non-reactor subdirectories or buildless nested modules). | Increases detector filesystem walk and subproject inspector invocations across nested folders. |
| `--detect.detector.search.continue=true` | Continues running child directory detectors even after a parent manifest is found (default is false; needed for non-reactor subprojects, mixed Maven/Gradle trees, or buildless mode). | Runs package manager inspectors on every nested subproject; can slow down large multi-module monorepos. |
| `--detect.binary.scan.search.depth=8` | Discovers binary/archive artifacts down to directory depth 8 when BINARY_SCAN (BDBA) is enabled with --detect.binary.scan.file.name.patterns (default is 0; does not affect SIGNATURE_SCAN). | Applies only when BINARY_SCAN is enabled; uploads matching nested archives to the BDBA worker. |

### Operational & Calibration Signals
- Unpinned package manifests detected (pom.xml, bom/pom.xml, cli/pom.xml, +6 more). Detect 10 defaults to --detect.accuracy.required=ALL (HIGH), which will exit with Code 5 (FAILURE_DETECTOR: Accuracy Not Met) or Exit Code 15 (FAILURE_ACCURACY_NOT_MET) if package manager executables (pip, npm, go, mvn, gradle, cargo, dotnet, bazel, conan, bundle) or installed environments are missing unless --detect.accuracy.required=NONE is passed for buildless/unbuilt runs.
- Nested package manifests detected across parent/child directories. Detect defaults to --detect.detector.search.continue=false, which skips child detectors (missing standalone non-reactor subprojects, mixed ecosystems, and buildless nested modules). Added --detect.detector.search.continue=true to recommended arguments to ensure all nested subprojects are resolved.
- Binary/archive artifacts found at depth 8. Detect defaults --detect.binary.scan.search.depth=0; added --detect.binary.scan.search.depth=8 to recommended arguments for BINARY_SCAN.
- MONOREPO_SCAN_SPLIT_RECOMMENDATION: Workspace contains 12046 files (0.03 GB), exceeding the Scanning Best Practices threshold (>10,000 files or >1 GB) for a single Signature Scan. Split Signature Scans across top-level subfolders mapped to the same Project Version via --detect.code.location.name.
- DOCKER_INSPECTOR_EOL_WARNING: Dockerfile/Containerfile detected (1 base image declaration(s)). Docker Inspector (--detect.tools=DOCKER / detect-docker-inspector.jar) reached End-of-Life in July 2026 and fails with exit code 255 on modern container layers. Use --detect.tools=CONTAINER_SCAN with --detect.container.scan.file.path=<image.tar> instead of --detect.tools=DOCKER.
- SCASS_ASYNC_TIMEOUT_WARNING: High-volume workspace (12046 files, >= 839 expected BOM components across 9 code locations). In SCA Server 2025.x-2026.x (SCASS / Matching-as-a-Service), Detect exits 0 immediately after upload while server-side BOM computation can queue or time out with ERR021002. Pass --detect.wait.for.results=true (and --detect.report.timeout=1800) if CI gates require confirmed BOM completion.

## 3. Expected BOM Baseline & Post-Scan Completeness Gate

- **Expected Minimum BOM Components**: `>= 839` across `9` code location(s)
- **Baseline Summary**: You should expect a BOM of at least 839 component version(s) across 9 code location(s) (719 locked + 120 direct unpinned; per-subproject sum prior to cross-module BOM deduplication), and here is why:
  - `[MAVEN] cli`: `>= 12` component(s) (cli/pom.xml declares 12 direct dependency(s); no lockfile)
  - `[MAVEN] core`: `>= 72` component(s) (core/pom.xml declares 72 direct dependency(s); no lockfile)
  - `[MAVEN] coverage`: `>= 3` component(s) (coverage/pom.xml declares 3 direct dependency(s); no lockfile)
  - `[MAVEN] test`: `>= 20` component(s) (test/pom.xml declares 20 direct dependency(s); no lockfile)
  - `[MAVEN] war`: `>= 7` component(s) (war/pom.xml declares 7 direct dependency(s); no lockfile)
  - `[NPM] war`: `>= 719` component(s) (war/yarn.lock declares 719 locked package(s))
  - `[MAVEN] websocket/jetty10`: `>= 4` component(s) (websocket/jetty10/pom.xml declares 4 direct dependency(s); no lockfile)
  - `[MAVEN] websocket/spi`: `>= 1` component(s) (websocket/spi/pom.xml declares 1 direct dependency; no lockfile)
  - `[MAVEN] .`: `>= 1` component(s) (pom.xml declares 1 direct dependency; no lockfile)

## 4. Actionable High-Severity Vulnerabilities (6)

> **Scope Note (Free 5-Second Worst-of-the-Worst Check, Not a Full SCA Database)**: `sca-prescan`'s main job is tuning your Detect CLI flags and catching BOM blind spots before your scan starts. As a free 5-second side dish while walking the tree, it also checks an offline hit-list (`3,910` version/range rules + `32` unpatched code-snippet and shaded-bytecode patterns) focused strictly on **must-catch disasters**: actively exploited **CISA-KEV** flaws, **recent 2025-2026 critical advisories** (including pre-NVD `GHSA`/`GO`/`RUSTSEC` advisories), `CVSS 9.8-10.0` RCEs, and major open-source license rugpulls (`AGPL-3.0`, `SSPL-1.0`, `RSALv2`, `BSL-1.1`). When version strings are missing or stripped from shaded uber-JARs, it checks source files and in-memory `.class` constant pools directly (`[UNPATCHED-SNIPPET-VERIFIED]` / `[PATCH-GUARD-DETECTED]`). Always rely on your full SCA server and AST/SAST tools for comprehensive vulnerability coverage.

| CVE ID | CVSS | KEV | Component & Version | Evidence Source | Actionable Remedy |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `CVE-2024-21538` | 9.8 | NO | `cross-spawn 7.0.3` | `lockfile:war/yarn.lock` | Upgrade cross-spawn to 7.0.5 or higher. |
| `CVE-2024-23897` | 9.8 | YES | `jenkins-core 2.440` | `manifest:core/pom.xml (+4 locations)` | Upgrade jenkins-core to 2.441 (weekly) or 2.426.3 (LTS) or higher. [UNPATCHED-SNIPPET-VERIFIED: unpatched code in core/src/main/java/hudson/cli/CLICommand.java] |
| `CVE-2026-106445` | 9.8 | NO | `handlebars 4.7.8` | `lockfile:war/yarn.lock` | Upgrade handlebars to 4.7.10 or higher. [HOT 2026-10-08 / GHSA-p8wg-vrv2-v86f] |
| `CVE-2026-106446` | 9.8 | NO | `handlebars 4.7.8` | `lockfile:war/yarn.lock` | Upgrade handlebars to 4.7.10 or higher. [HOT 2026-10-08 / GHSA-8r5x-fm3f-whwj] |
| `CVE-2026-29063` | 9.8 | NO | `immutable 4.3.0` | `lockfile:war/yarn.lock` | Upgrade immutable to 4.3.8 or higher. [HOT 2026-03-04 / GHSA-wf6x-7x77-mvgw] |
| `CVE-2026-33937` | 9.8 | NO | `handlebars 4.7.8` | `lockfile:war/yarn.lock` | Upgrade handlebars to 4.7.9 or higher. [HOT 2026-03-27 / GHSA-2w6w-674q-4c4q] |

## 5. High-Severity License & Rugpull Risks (0)

_No high-severity license or rugpull risks matched._

