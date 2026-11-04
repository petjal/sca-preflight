---
schema: sca-ops-ai-brief/v1
workspace_name: opencontainers_runc
dlp_sanitized: true
host_paths_stripped: true
multilayer_codebase_signature: sca-sig:v2:L0=3931b6c806ae:L1=dd8b83315b2a:L2=7989f337ae21:CFG=2df5fcb38981@d6(100.0%)
topology_skeleton_sha256: 3931b6c806ae4579a46192a59bfa1a50cfd48575588ec0b76818d13dced64ce8
workspace_tree_merkle_sha256: 7989f337ae2137e1fff85ed498ff8909e779c96452828699d5234c18f3ee190c
dependency_inputs_merkle_sha256: dd8b83315b2a8fb97f71a55beeb2515fa21c02e68fb542a7654fe51f25e5ad8a
effective_detect_config_sha256: 2df5fcb389812bfe503c7eee67c23bcc87daf1340ca66debccf34b5c8459f27b
coverage_pct: 100.0
early_stop_triggered: false
total_dirs_scanned: 153
total_files_scanned: 1205
total_workspace_mb: 12.07
bucket_1_excluded_dirs_count: 1
bucket_2a_actionable_l1_files_count: 34
bucket_2b_provenance_only_l2_files_count: 1171
bucket_3_early_stop_unhashed_files_count: 0
dependency_inputs_hashed_count: 34
lockfiles_count: 1
lockfile_paired_manifests_count: 1
unpinned_manifests_count: 0
expected_min_bom_components: 43
actionable_vulnerabilities_count: 4
actionable_license_risks_count: 0
blind_spot_traps_count: 0
operational_warnings_count: 1
---

# AI-First SCA Pre-Flight, Provenance & Risk Brief (`opencontainers_runc`)

> **LLM Ingestion Instructions**: Point your enterprise AI assistant (Copilot, Claude, ChatGPT Enterprise) at this single file. All host paths are stripped to relative workspace paths and all integer totals are pre-computed in the YAML header above.

## 1. Workspace Input & Config Hashes (L0 / L1 / L2 / CFG)

| Provenance Layer | SHA-256 Digest / Signature | Operational Meaning |
| :--- | :--- | :--- |
| **Compact Workspace Signature** | `sca-sig:v2:L0=3931b6c806ae:L1=dd8b83315b2a:L2=7989f337ae21:CFG=2df5fcb38981@d6(100.0%)` | Single-line composite fingerprint (`L0` Folder Tree + `L1` Dependency Inputs + `L2` Source Tree + `CFG` Detect Flags + depth/coverage watermark). |
| **Layer 0: Folder Tree Hash (`L0`)** | `3931b6c806ae4579a46192a59bfa1a50cfd48575588ec0b76818d13dced64ce8` | Zero-file-read breadth-first directory skeleton (relative folders, file counts, extension mix, byte totals). Instantaneous across monorepos. |
| **Layer 1: Dependency Input Hash (`L1`)** | `dd8b83315b2a8fb97f71a55beeb2515fa21c02e68fb542a7654fe51f25e5ad8a` | Multithreaded hash of 100% of 34 dependency-bearing inputs (manifests, lockfiles, Dockerfiles, and sparse-fingerprinted archives/binaries). If unchanged across commits, BOM inputs are identical. |
| **Layer 2: Source File Hash (`L2`)** | `7989f337ae2137e1fff85ed498ff8909e779c96452828699d5234c18f3ee190c` | Breadth-first multithreaded source digest covering 1205/1205 files (100.0%, max depth 6). |
| **Effective Detect Config (`CFG`)** | `2df5fcb389812bfe503c7eee67c23bcc87daf1340ca66debccf34b5c8459f27b` | Canonical digest of the sorted recommended Detect CLI properties. |
| **SCA Web UI Provenance Flag** | `--detect.project.version.notes=sca-ops-provenance:sca-sig:v2:L0=3931b6c806ae:L1=dd8b83315b2a:L2=7989f337ae21:CFG=2df5fcb38981@d6(100.0%);tree_merkle=sha256:7989f337ae2137e1;dep_merkle=sha256:dd8b83315b2a8fb9;cfg_sha256=2df5fcb389812bfe;files=1205/1205;dep_inputs=34` | Pass this flag to Detect to stamp exact input/config provenance into the Project Version Notes UI. |

### What `sca-prescan` Actually Inspected (`153` dirs, `1205` files, `12.07` MB)
- **Pass 1 (Directory, Manifest & Encoding Walk)**: Traversed `153` directories and `1205` files (`12.07` MB), classified `1` lockfile(s), `1` lockfile-paired manifest(s), `0` unpinned manifest(s), and `6` native/container build script(s), verified manifest character encodings (`UTF-8` vs `UTF-16LE/BE`), and measured max directory depths for detectors, binaries, and exclusions.
- **Pass 2 (In-Memory Archive, Binary & Header Inspection)**: Inspected `0` archive(s) and `0` compiled binary file(s) in memory without disk extraction, parsed `0` internal version headers/manifests (`META-INF/maven`, `MANIFEST.MF`, `PKG-INFO`, C `zlib.h`/`opensslv.h`/`VERSION.dat`), and checked `26` legal/SPDX attribution file(s).
- **Pass 3 (3-Layer Cryptographic Provenance Hashing)**: Hashed `153` directory skeletons (`L0`, 0 file reads), 100% of `34` dependency-bearing inputs (`L1`), and `1205/1205` source files (`L2`, `100.0%` coverage).
- **Pass 4 (100% Offline Version-Range & Rugpull Matching)**: Evaluated all discovered `(component, version)` pairs offline against the built-in Pareto CVE (`pareto_vuln_kb.json`) and license-rugpull (`pareto_license_kb.json`) catalogs (`0` outbound network calls).

### File & Byte Disposition Accounting (`34 + 1171 + 0 = 1205` files)

| Bucket | Count / Size | What `sca-prescan` Did With These Objects | What Default Detect (`depth=0`) Does With Them |
| :--- | :---: | :--- | :--- |
| **Bucket 1: Excluded Non-Shipping Dirs** | `1` dir(s) | Saw 1 non-shipping folder(s) (.git), skipped traversal, and added to --detect.excluded.directories. | Skips .git by default, but traverses .venv, venv, or unlocked node_modules unless explicitly excluded. |
| **Bucket 2a: Actionable BOM, Vuln & Calibration Files (`L1`)** | `34` file(s) (`0.16` MB) | Hashed 100% into Layer 1 (L1) and extracted BOM baselines, C/C++ header versions, archive/binary metadata, and 4 CVE / 0 license hit(s). | DETECTOR only processes root (depth=0) package manifests; SILENTLY IGNORES depth>=1 manifests, UTF-16 manifests, C/C++ version headers, CMake/Makefiles, and standalone binaries (--individualFileMatching=NONE). |
| **Bucket 2b: Source & Doc Provenance Only (`L2 - L1`)** | `1171` file(s) (`11.91` MB) | Hashed 1171 first-party source/doc files into Layer 2 (L2) and scanned for embedded private keys (0 third-party BOM declarations). | Ignored by DETECTOR; Signature Scanner hashes directory structure as a whole. |
| **Bucket 3: Unhashed Beyond Monorepo Early-Stop Cap** | `0` file(s) | 0 files skipped (100% hashed). | Signature Scanner hashes all files; >10,000 files or >1 GB in one scan risks server queue timeouts. |

### Actionable Files Processed in Bucket 2a (`34` file(s): `sca-prescan` vs. Default Detect)

| File Path (Depth) | Bucket Sub-Type | What `sca-prescan` Extracted & Did | What Default Detect (`depth=0`) Does |
| :--- | :--- | :--- | :--- |
| `go.mod` (`d=0`) | `2a-i Manifest (Lockfile-Paired)` | Package manifest (23 direct dep(s), paired with sibling lockfile, encoding=utf-8, depth=0); hashed into L1. Matched vulnerability: CVE-2023-39325 (CVSS 7.5, CISA-KEV), CVE-2023-45288 (CVSS 7.5), CVE-2024-21626 (CVSS 8.6, CISA-KEV), CVE-2024-24786 (CVSS 7.5). | Processed by DETECTOR at root depth=0 alongside sibling lockfile. |
| `Dockerfile` (`d=0`) | `2a-ii Containerfile` | Extracted base image declaration(s): golang:${GO_VERSION}-bullseye; hashed into L1. | SILENTLY IGNORED by standard source DETECTOR scan (requires CONTAINER_SCAN on built image tar). |
| `go.sum` (`d=0`) | `2a-i Lockfile` | Pinned lockfile (43 locked component(s), encoding=utf-8); hashed into L1. | Processed by DETECTOR at root depth=0. |
| `LICENSE` (`d=0`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `Makefile` (`d=0`) | `2a-ii Native Build Script` | Inspected for native find_package/pkg_check_modules hints and build-execution hooks; hashed into L1. | SILENTLY IGNORED by DETECTOR (no C/C++ package lockfile). |
| `NOTICE` (`d=0`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/checkpoint-restore/go-criu/v5/LICENSE` (`d=5`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/checkpoint-restore/go-criu/v5/Makefile` (`d=5`) | `2a-ii Native Build Script` | Inspected for native find_package/pkg_check_modules hints and build-execution hooks; hashed into L1. | SILENTLY IGNORED by DETECTOR (no C/C++ package lockfile). |
| `vendor/github.com/cilium/ebpf/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/cilium/ebpf/Makefile` (`d=4`) | `2a-ii Native Build Script` | Inspected for native find_package/pkg_check_modules hints and build-execution hooks; hashed into L1. | SILENTLY IGNORED by DETECTOR (no C/C++ package lockfile). |
| `vendor/github.com/containerd/console/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/coreos/go-systemd/v22/LICENSE` (`d=5`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/coreos/go-systemd/v22/NOTICE` (`d=5`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/cpuguy83/go-md2man/v2/LICENSE.md` (`d=5`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/cyphar/filepath-securejoin/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/docker/go-units/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/godbus/dbus/v5/LICENSE` (`d=5`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/moby/sys/mountinfo/LICENSE` (`d=5`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/mrunalp/fileutils/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/opencontainers/runtime-spec/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/opencontainers/selinux/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/russross/blackfriday/v2/LICENSE.txt` (`d=5`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/seccomp/libseccomp-golang/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/seccomp/libseccomp-golang/Makefile` (`d=4`) | `2a-ii Native Build Script` | Inspected for native find_package/pkg_check_modules hints and build-execution hooks; hashed into L1. | SILENTLY IGNORED by DETECTOR (no C/C++ package lockfile). |
| `vendor/github.com/shurcooL/sanitized_anchor_name/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/sirupsen/logrus/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/syndtr/gocapability/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/urfave/cli/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/vishvananda/netlink/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/github.com/vishvananda/netlink/Makefile` (`d=4`) | `2a-ii Native Build Script` | Inspected for native find_package/pkg_check_modules hints and build-execution hooks; hashed into L1. | SILENTLY IGNORED by DETECTOR (no C/C++ package lockfile). |
| `vendor/github.com/vishvananda/netns/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/golang.org/x/net/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/golang.org/x/sys/LICENSE` (`d=4`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |
| `vendor/google.golang.org/protobuf/LICENSE` (`d=3`) | `2a-iv Legal / Attribution` | Inspected license/attribution text (no SPDX tag); hashed into L1. | SILENTLY IGNORED by default unless --detect.blackduck.signature.scanner.license.search=true is enabled. |

## 2. Tuned Detect CLI Invocation & Configuration Calibration

### 2.1 Baseline Safe Invocation (Default Detect Policy + Safe Runner Hygiene)
> **Stated Vendor Policy**: Run Detect with default settings (`--detect.tools=ALL`, `--detect.detector.search.depth=0`) first for predictable scan speed, adding only safe runner memory sizing, `.git`/`.venv` directory exclusions, and the Project Version Notes provenance stamp below. Comma-separated properties (`--detect.excluded.directories`, `--detect.tools`) should always be **additively concatenated** to any existing pipeline values.

```bash
java -jar detect.jar \
  --detect.blackduck.signature.scanner.memory=4096 \
  --detect.blackduck.signature.scanner.parallel.processors=1 \
  --detect.excluded.directories=.git \
  '--detect.project.version.notes=sca-ops-provenance:sca-sig:v2:L0=3931b6c806ae:L1=dd8b83315b2a:L2=7989f337ae21:CFG=2df5fcb38981@d6(100.0%);tree_merkle=sha256:7989f337ae2137e1;dep_merkle=sha256:dd8b83315b2a8fb9;cfg_sha256=2df5fcb389812bfe;files=1205/1205;dep_inputs=34'
```

### 2.2 Optional Fuller-BOM & Buildless Tweaks (Trade-Offs Explained)

| Optional Detect Flag | What Hidden Files / Failures It Unlocks in This Repo | Performance & BOM Trade-Off |
| :--- | :--- | :--- |
| `--detect.blackduck.signature.scanner.license.search=true` | Scans 24 vendored legal/attribution notice(s) under vendor/ (default is false, which skips embedded license text inside vendored source trees). | Increases Signature Scanner text-search time across vendored source files. |

### Operational & Calibration Signals
- DOCKER_INSPECTOR_EOL_WARNING: Dockerfile/Containerfile detected (1 base image declaration(s)). Docker Inspector (--detect.tools=DOCKER / detect-docker-inspector.jar) reached End-of-Life in July 2026 and fails with exit code 255 on modern container layers. Use --detect.tools=CONTAINER_SCAN with --detect.container.scan.file.path=<image.tar> instead of --detect.tools=DOCKER.

## 3. Expected BOM Baseline & Post-Scan Completeness Gate

- **Expected Minimum BOM Components**: `>= 43` across `1` code location(s)
- **Baseline Summary**: You should expect a BOM of at least 43 component version(s) across 1 code location(s) (43 locked + 0 direct unpinned), and here is why:
  - `[GO] .`: `>= 43` component(s) (go.sum declares 43 locked module(s))

## 4. Actionable High-Severity Vulnerabilities (4)

> **Scope Note (Free 5-Second Worst-of-the-Worst Check, Not a Full SCA Database)**: `sca-prescan`'s main job is tuning your Detect CLI flags and catching BOM blind spots before your scan starts. As a free 5-second side dish while walking the tree, it also checks an offline hit-list (`3,910` version/range rules + `32` unpatched code-snippet and shaded-bytecode patterns) focused strictly on **must-catch disasters**: actively exploited **CISA-KEV** flaws, **recent 2025-2026 critical advisories** (including pre-NVD `GHSA`/`GO`/`RUSTSEC` advisories), `CVSS 9.8-10.0` RCEs, and major open-source license rugpulls (`AGPL-3.0`, `SSPL-1.0`, `RSALv2`, `BSL-1.1`). When version strings are missing or stripped from shaded uber-JARs, it checks source files and in-memory `.class` constant pools directly (`[UNPATCHED-SNIPPET-VERIFIED]` / `[PATCH-GUARD-DETECTED]`). Always rely on your full SCA server and AST/SAST tools for comprehensive vulnerability coverage.

| CVE ID | CVSS | KEV | Component & Version | Evidence Source | Actionable Remedy |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `CVE-2023-39325` | 7.5 | YES | `golang.org/x/net v0.8.0` | `manifest:go.mod` | Upgrade golang.org/x/net to v0.17.0 or higher. |
| `CVE-2023-45288` | 7.5 | NO | `golang.org/x/net v0.8.0` | `manifest:go.mod` | Upgrade golang.org/x/net to v0.23.0 or higher. |
| `CVE-2024-21626` | 8.6 | YES | `runc 1.1.11` | `manifest:go.mod` | Upgrade runc to 1.1.12 or higher. |
| `CVE-2024-24786` | 7.5 | NO | `google.golang.org/protobuf v1.27.1` | `manifest:go.mod` | Upgrade google.golang.org/protobuf to v1.33.0 or higher. |

## 5. High-Severity License & Rugpull Risks (0)

_No high-severity license or rugpull risks matched._

