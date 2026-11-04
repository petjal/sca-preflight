---
schema: sca-ops-ai-brief/v1
workspace_name: benchmark
dlp_sanitized: true
host_paths_stripped: true
multilayer_codebase_signature: sca-sig:v2:L0=3a617a0faa6a:L1=e3b0c44298fc:L2=a225b7d53641:CFG=73c849ec2dde@d0(100.0%)
topology_skeleton_sha256: 3a617a0faa6a651c1efe4327d7966c8521ddab9678c39a900e95d0723cececf3
workspace_tree_merkle_sha256: a225b7d536416f038b0efc527be578fb36565714bbf0d6e034a330c140db2e79
dependency_inputs_merkle_sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
effective_detect_config_sha256: 73c849ec2ddeb9ec6eafe280f95f5f57a91712b362b93259cd74536ec836e338
coverage_pct: 100.0
early_stop_triggered: false
total_dirs_scanned: 1
total_files_scanned: 2
total_workspace_mb: 0.02
bucket_1_excluded_dirs_count: 0
bucket_2a_actionable_l1_files_count: 0
bucket_2b_provenance_only_l2_files_count: 2
bucket_3_early_stop_unhashed_files_count: 0
dependency_inputs_hashed_count: 0
lockfiles_count: 0
lockfile_paired_manifests_count: 0
unpinned_manifests_count: 0
expected_min_bom_components: 0
actionable_vulnerabilities_count: 0
actionable_license_risks_count: 0
blind_spot_traps_count: 0
operational_warnings_count: 1
---

# AI-First SCA Pre-Flight, Provenance & Risk Brief (`benchmark`)

> **LLM Ingestion Instructions**: Point your enterprise AI assistant (Copilot, Claude, ChatGPT Enterprise) at this single file. All host paths are stripped to relative workspace paths and all integer totals are pre-computed in the YAML header above.

## 1. Stratified Multilayer Codebase Signature & Config Provenance (BDIO Blind-Spot Anchor)

| Provenance Layer | SHA-256 Digest / Signature | Operational Meaning |
| :--- | :--- | :--- |
| **Compact Multilayer Signature** | `sca-sig:v2:L0=3a617a0faa6a:L1=e3b0c44298fc:L2=a225b7d53641:CFG=73c849ec2dde@d0(100.0%)` | Single-line composite fingerprint (`L0` Topology + `L1` Dependency Control Plane + `L2` Source Tree + `CFG` Detect Flags + depth/coverage watermark). |
| **Layer 0: Topology Skeleton (`L0`)** | `3a617a0faa6a651c1efe4327d7966c8521ddab9678c39a900e95d0723cececf3` | Zero-file-read breadth-first directory skeleton (relative folders, file counts, extension mix, byte totals). Instantaneous across monorepos. |
| **Layer 1: BOM Control Plane (`L1`)** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Multithreaded hash of 100% of 0 dependency-bearing inputs (manifests, lockfiles, Dockerfiles, and sparse-fingerprinted archives/binaries). If unchanged across commits, BOM inputs are identical. |
| **Layer 2: Top-Down Source Tree (`L2`)** | `a225b7d536416f038b0efc527be578fb36565714bbf0d6e034a330c140db2e79` | Breadth-first multithreaded source digest covering 2/2 files (100.0%, max depth 0). |
| **Effective Detect Config (`CFG`)** | `73c849ec2ddeb9ec6eafe280f95f5f57a91712b362b93259cd74536ec836e338` | Canonical digest of the sorted recommended Detect CLI properties. |
| **SCA Web UI Provenance Flag** | `--detect.project.version.notes=sca-ops-provenance:sca-sig:v2:L0=3a617a0faa6a:L1=e3b0c44298fc:L2=a225b7d53641:CFG=73c849ec2dde@d0(100.0%);tree_merkle=sha256:a225b7d536416f03;dep_merkle=sha256:e3b0c44298fc1c14;cfg_sha256=73c849ec2ddeb9ec;files=2/2;dep_inputs=0` | Pass this flag to Detect to stamp exact input/config provenance into the Project Version Notes UI. |

### What `sca-prescan` Actually Inspected (`1` dirs, `2` files, `0.02` MB)
- **Pass 1 (Directory, Manifest & Encoding Walk)**: Traversed `1` directories and `2` files (`0.02` MB), classified `0` lockfile(s), `0` unpinned manifest(s), and `0` native/container build script(s), verified manifest character encodings (`UTF-8` vs `UTF-16LE/BE`), and measured max directory depths for detectors, binaries, and exclusions.
- **Pass 2 (In-Memory Archive, Binary & Header Inspection)**: Inspected `0` archive(s) and `0` compiled binary file(s) in memory without disk extraction, parsed `0` internal version headers/manifests (`META-INF/maven`, `MANIFEST.MF`, `PKG-INFO`, C `zlib.h`/`opensslv.h`/`VERSION.dat`), and checked `0` legal/SPDX attribution file(s).
- **Pass 3 (3-Layer Cryptographic Provenance Hashing)**: Hashed `1` directory skeletons (`L0`, 0 file reads), 100% of `0` dependency-bearing inputs (`L1`), and `2/2` source files (`L2`, `100.0%` coverage).
- **Pass 4 (100% Offline Version-Range & Rugpull Matching)**: Evaluated all discovered `(component, version)` pairs offline against the built-in Pareto CVE (`pareto_vuln_kb.json`) and license-rugpull (`pareto_license_kb.json`) catalogs (`0` outbound network calls).

### File & Byte Disposition Accounting (`0 + 2 + 0 = 2` files)

| Bucket | Count / Size | What `sca-prescan` Did With These Objects | What Default Detect (`depth=0`) Does With Them |
| :--- | :---: | :--- | :--- |
| **Bucket 1: Excluded Non-Shipping Dirs** | `0` dir(s) | Saw 0 non-shipping folder(s) (none), skipped traversal, and added to --detect.excluded.directories. | Skips .git by default, but traverses .venv, venv, or unlocked node_modules unless explicitly excluded. |
| **Bucket 2a: Actionable BOM, Vuln & Calibration Files (`L1`)** | `0` file(s) (`0.0` MB) | Hashed 100% into Layer 1 (L1) and extracted BOM baselines, C/C++ header versions, archive/binary metadata, and 0 CVE / 0 license hit(s). | DETECTOR only processes root (depth=0) package manifests; SILENTLY IGNORES depth>=1 manifests, UTF-16 manifests, C/C++ version headers, CMake/Makefiles, and standalone binaries (--individualFileMatching=NONE). |
| **Bucket 2b: Source & Doc Provenance Only (`L2 - L1`)** | `2` file(s) (`0.02` MB) | Hashed 2 first-party source/doc files into Layer 2 (L2) and scanned for embedded private keys (0 third-party BOM declarations). | Ignored by DETECTOR; Signature Scanner hashes directory structure as a whole. |
| **Bucket 3: Unhashed Beyond Monorepo Early-Stop Cap** | `0` file(s) | 0 files skipped (100% hashed). | Signature Scanner hashes all files; >10,000 files or >1 GB in one scan risks server queue timeouts. |

## 2. Tuned Detect CLI Invocation & Configuration Calibration

### 2.1 Baseline Safe Invocation (Default Detect Policy + Safe Runner Hygiene)
> **Stated Vendor Policy**: Run Detect with default settings (`--detect.tools=ALL`, `--detect.detector.search.depth=0`) first for predictable scan speed, adding only safe runner memory sizing, `.git`/`.venv` directory exclusions, and the Project Version Notes provenance stamp below. Comma-separated properties (`--detect.excluded.directories`, `--detect.tools`) should always be **additively concatenated** to any existing pipeline values.

```bash
java -jar detect.jar \
  --detect.blackduck.signature.scanner.memory=6039 \
  --detect.blackduck.signature.scanner.parallel.processors=1 \
  '--detect.project.version.notes=sca-ops-provenance:sca-sig:v2:L0=3a617a0faa6a:L1=e3b0c44298fc:L2=a225b7d53641:CFG=73c849ec2dde@d0(100.0%);tree_merkle=sha256:a225b7d536416f03;dep_merkle=sha256:e3b0c44298fc1c14;cfg_sha256=73c849ec2ddeb9ec;files=2/2;dep_inputs=0'
```

### Operational & Calibration Signals
- No local Java runtime found (checked DETECT_JAVA_PATH, JAVA_HOME, and PATH). Note: While the downloaded Signature Scanner (scan.cli.zip) bundles its own embedded JRE, the Detect bootstrapper (detect.sh / detect.jar) does not and requires a host Java 11, 17, or 21 runtime to execute.

## 3. Expected BOM Baseline & Post-Scan Completeness Gate

- **Expected Minimum BOM Components**: `>= 0` across `0` code location(s)
- **Baseline Summary**: You should expect a BOM of at least 0 component version(s) across 0 code location(s) (0 locked + 0 direct unpinned) from package manager detectors (no third-party package lockfiles or external dependencies declared; BOM relies on Signature Scanning or BDBA).

## 4. Actionable High-Severity Vulnerabilities (0)

> **Honest Scope (Small Hit-List, Zero Promises)**: `sca-prescan`'s built-in check is **not** a full SCA vulnerability database and **promises nothing** when it comes to comprehensive CVE coverage. Its built-in catalog is intentionally tiny - just a curated hit-list of well-known CVSS 9.8-10.0 / CISA-KEV disasters (like Log4Shell, Spring4Shell, Text4Shell, OpenSSL, zlib, curl, pgjdbc) and notorious open-source license rugpulls (`AGPL-3.0`, `SSPL-1.0`, `RSALv2`, `BSL-1.1`). Its job is to flag obvious worst-of-the-worst blind spots in seconds *before* your main SCA scanner runs, while tuning your main scanner's CLI flags so your real vulnerability database does its job properly.

_No high-severity Pareto vulnerabilities matched._

## 5. High-Severity License & Rugpull Risks (0)

_No high-severity license or rugpull risks matched._

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
