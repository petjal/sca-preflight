# Companion Contractor Toolkit Walkthrough (`sca-bom-ifttt`, `sca-log-sanitize`, `sca-diag`)

Whereas `sca-prescan` (open-sourced in [`src/sca_preflight/`](../src/sca_preflight/) under the MIT License) runs **before** your scan to calibrate CLI flags and catch blind spots, the three companion tools documented on this page run **after** your scan to clean up noisy BOMs, scrub sensitive data from support logs, and troubleshoot server, container, or PostgreSQL bottlenecks.

> **Current Status & Customer Staging Partner Invitation**:
> I built and maintain these three utilities (`sca-bom-ifttt`, `sca-log-sanitize`, and `sca-diag` + `pj_collect.sh` + `pj_schema_gate.sql`) in a private toolkit repository (`94` passing unit tests) for use during W2 and 1099 customer engagements.
>
> Because I work as an independent engineer and do not run a licensed commercial SCA server in my home lab:
> - **100% Tested & Ready Today (Offline & Dry-Run Modes)**: Offline BOM JSON rule evaluation (`--offline-bom-file`), offline code-location unmapping previews (`--offline-codelocations-file`), `.bdio` vs. BOM dropped-component checks (`--verify-bdio`), streaming `.zip` / `.bdio` / `.sql` log sanitization (`sca-log-sanitize`), and offline server/PostgreSQL/Detect diagnostics (`sca-diag`) are 100% built and verified against offline fixtures and real Detect 10 diagnostic bundles.
> - **Ready for Live Customer Staging Validation**: The live REST API mutation phase (`--apply` sending `PUT` and `DELETE` calls against a live server) is built with token-bucket rate limiting and pre-mutation JSONL audit logging, and is ready to be validated against a customer's non-production or staging server.
>
> **Want to test-drive or co-develop these against your staging environment?** If your team has a non-production server, an exported BOM JSON file, or a tricky diagnostic `.zip` bundle and wants to collaborate on tuning these rules for your environment, email **`pjalajas+sca-preflight@gmail.com`**.

---

## 1. `sca-bom-ifttt` (Declarative Post-Scan BOM Cleanup & `.bdio` Zero-Day Verifier)

**Codebase Size & Test Status**: `1,469` lines of Python (`bom_ifttt.py`), `12/12` unit tests passing.

In large enterprise deployments, teams spend hours every release cycle manually repeating the same BOM edits in the web UI: ignoring noisy sub-components, overriding stale fuzzy signature matches, resolving dual-license GPL warnings on commercial dual-licensed libraries, and unmapping old CI branch scans.

`sca-bom-ifttt` replaces manual clicking with a declarative `.toml`, `.jsonc`, or `.yaml` rulebook that runs in **safe `--dry-run` preview mode by default** and requires a mandatory audit comment on every rule.

### 1.1 CLI Interface

```text
usage: sca-bom-ifttt [-h] --rules RULES [--apply]
                     [--offline-bom-file OFFLINE_BOM_FILE]
                     [--offline-codelocations-file OFFLINE_CODELOCATIONS_FILE]
                     [--bd-url BD_URL] [--bd-token BD_TOKEN]
                     [--project-version-bom-url PROJECT_VERSION_BOM_URL]
                     [--audit-log AUDIT_LOG] [--max-rps MAX_RPS]
                     [--allow-two-phase-wait]
                     [--prescan-report PRESCAN_REPORT]
                     [--verify-bdio VERIFY_BDIO] [--json]
```

### 1.2 Built-In Engineering Safeguards

1. **Two-Phase Execution Guard (Prevents `HTTP 409 Conflict` & `bomengine` Queue Storms)**:
   - Unmapping or deleting a code location (`phase = "codelocation"`) triggers asynchronous `bomengine` recalculation on the server. If a script immediately sends `PUT` edits to BOM components (`phase = "bom_component"`) while `bomengine` is still recalculating, the server rejects the edits (`HTTP 409 Conflict`) or leaves component state inconsistent.
   - `sca-bom-ifttt` enforces strict phase separation: it blocks rulefiles that mix `codelocation` and `bom_component` rules unless `--allow-two-phase-wait` is explicitly passed.
2. **Pre-Mutation JSONL Rollback & Audit Trail (`ifttt_audit.jsonl`)**:
   - Before any `PUT` or `DELETE` request is sent in `--apply` mode, the engine records the exact `before_state` (`componentName`, `componentVersionName`, `reviewStatus`, `ignored`, `usages`, `mappedProjectVersion`) and `after_payload` to a local `.jsonl` audit file alongside the mandatory rule comment written to the server UI.
3. **Production REST Pacing**:
   - Uses a client-side token-bucket rate limiter (`--max-rps 5.0` default), proactive Bearer token renewal at 80% of TTL, snapshot-first pagination deduplicated by `_meta.href`, and exponential backoff on `HTTP 429 / 502 / 503 / 504`.

### 1.3 What It Catches That Standard Scripts Miss (`sample_bom_ifttt_rules.toml`)

See [`examples/sample_bom_ifttt_rules.toml`](sample_bom_ifttt_rules.toml) for the complete sample TOML file covering four high-value post-scan accuracy tasks:

- **Problem A (`require_parent_component_regex` - Framework Sub-Component Rollup)**:
  - Automatically ignores noisy sub-components (such as `jackson-core` and `jackson-annotations`) when the parent umbrella package (`jackson-databind`) is already present and unignored in the same BOM.
- **Problem B (`--verify-bdio` - Silently Dropped Zero-Day / Unindexed KB Component Check)**:
  - Diffs every `#Component` node inside the uploaded `.bdio` archive against the server's `/components` JSON response. If a newly published package version was discovered by Detect on disk and uploaded in `.bdio`, but silently dropped from the server BOM because the central KnowledgeBase has not indexed yesterday's release yet, `sca-bom-ifttt` flags it (`ZERO_DAY_COMPONENTS_DROPPED`).
- **Problem C (`require_newer_exact_dependency_present` & `require_prescan_version_mismatch` - Linking Pre-Scan Disk Truth to Post-Scan BOM Cleanup)**:
  - When the signature scanner guesses an older `N-1` version via fuzzy file matching (`FILE_SOME_FILES_MODIFIED` or `FILE_FILES_ADDED_DELETED_AND_MODIFIED`), `sca-bom-ifttt` cross-references your exact package-manager lockfile matches (`FILE_DEPENDENCY*`) and your `sca-prescan` JSON report (archive POM properties, binary symbols, tarball prefixes, filename version assertions) to prove the true version on disk and automatically suppress or annotate the false positive.
- **Problem D (`license_name_regex` - Dual-License / Commercial Exception Review)**:
  - Marks known dual-licensed components (such as `MySQL-Connector-Java`, `OpenSSL`, or `cURL`) as `REVIEWED` with your compliance team's standard policy comment so engineers do not have to re-review them on every release branch.

### 1.4 Sample Dry-Run Execution Output (`--dry-run`)

Running `sca-bom-ifttt` offline against exported server JSON files and a `sca-prescan` JSON report:

```text
$ sca-bom-ifttt \
    --rules examples/sample_bom_ifttt_rules.toml \
    --offline-codelocations-file codelocations.json \
    --offline-bom-file bom_components.json \
    --prescan-report prescan_report.json \
    --verify-bdio scan_output.bdio

=== SCA BOM IFTTT Engine [DRY-RUN PREVIEW (no mutations applied)] ===
Evaluated Rules: 5
Actions Matched: 5
[SIMULATED_UNMAP] Rule 'codeloc-hygiene-ephemeral-ci-unmap' -> codelocation 'storage-platform-ci-runner-build-98412-scan': unmap
   Comment: Codelocation Hygiene: Unmapping stale ephemeral CI build scan older than 30 days.
[SIMULATED_IGNORE] Rule 'enterprise-prob-a-jackson-rollup' -> bom_component 'jackson-core@2.13.3': ignore
   Comment: Problem A: Subcomponent rolled up into parent jackson-databind framework entry.
[SIMULATED_IGNORE] Rule 'enterprise-prob-c-n-minus-1-aliasing' -> bom_component 'Apache Log4j@2.13.3': ignore
   Comment: Problem C: Prioritizing exact package manager dependency version over signature match.
[SIMULATED_COMMENT] Rule 'enterprise-prob-c-filename-version-truth' -> bom_component 'activemq-client@5.18.1': comment
   Comment: Problem C: Prescan filename inspection detected version difference against signature match; confirm in SCA Server.
[SIMULATED_REVIEW] Rule 'enterprise-prob-d-dual-license-cpe-errata' -> bom_component 'MySQL-Connector-Java@8.0.33': mark_reviewed
   Comment: Problem D: Resolved dual-license ambiguity under enterprise commercial exception per compliance policy.

BDIO vs. Server BOM Verification [ZERO_DAY_COMPONENTS_DROPPED]:
  BDIO Total: 1, BOM Total: 6, Matched: 0, Dropped: 1
  ! [PROBLEM B ADVISORY] Newly released component versions awaiting KnowledgeBase matching on SCA Server:
    - postgresql @ 42.7.99-ZERODAY (org.postgresql:postgresql:42.7.99-ZERODAY)
```

### 1.5 Sample Pre-Mutation Audit Log Record (`ifttt_audit.jsonl`)

Every simulated or applied action writes a structured JSONL line so compliance auditors can see the exact before and after state:

```json
{
  "timestamp_utc": "2026-11-04T17:30:00+00:00",
  "rule_id": "enterprise-prob-c-n-minus-1-aliasing",
  "phase": "bom_component",
  "target_href": "https://sca.example.internal/api/projects/p1/versions/v1/components/c1/versions/cv1",
  "action": "ignore",
  "before_state": {
    "componentName": "cURL",
    "componentVersionName": "8.6.0",
    "reviewStatus": "NOT_REVIEWED",
    "ignored": false,
    "usages": ["DYNAMICALLY_LINKED"]
  },
  "after_payload": {
    "action": "ignore",
    "comment": "Problem C: Prioritizing exact package manager dependency version over signature match.",
    "ignored": true
  },
  "status": "SIMULATED_IGNORE",
  "note": "Declarative BOM action recorded."
}
```

### 1.6 Open Item for Customer Staging Validation

- **What works right now**: You can export your project version's `/components` JSON (`GET /api/projects/{id}/versions/{ver}/components?limit=1000`) and run `sca-bom-ifttt --offline-bom-file components.json` completely offline today with zero connection to your server.
- **What needs a staging server**: Validating endpoint-specific vendor `Accept` / `Content-Type` headers (`application/vnd.blackducksoftware.bill-of-materials-6+json` vs. generic `application/json`) during live `PUT` updates across 2024.x, 2025.x, and 2026.x server releases.

---

## 2. `sca-log-sanitize` (In-Memory `.zip`, `.gz`, `.bdio` & SQL DLP Scrubber)

**Codebase Size & Test Status**: `485` lines of Python (`log_sanitize.py`), `8/8` unit tests passing (including multi-megabyte Detect 10 diagnostic `.zip` bundles with nested `.bdio` and `.gz` archives).

When a scan fails or a server slows down, engineers often cannot share Detect diagnostic `.zip` bundles or container logs with outside consultants or internal AI assistants because the logs contain API tokens, JDBC passwords, internal hostnames (`.corp`, `.internal`), employee usernames (`/home/jsmith/...`), and proprietary project names.

Unlike naive `sed` scripts that only scrub flat `.log` files (or accidentally corrupt IP-like product versions such as `2024.7.0.1` and binary tarballs), `sca-log-sanitize` reaches **inside nested `.zip` support bundles, nested `.gz` container logs, and nested `.bdio` ZIP containers (`.jsonld` dependency graphs)** in a single streaming pass while **preserving 100% of the technical signal needed to debug the problem**.

### 2.1 CLI Interface

```text
usage: sca-log-sanitize [-h] --input INPUT --output OUTPUT
                        [--terms-file TERMS_FILE]
                        [--projects-export PROJECTS_EXPORT]
                        [--mapping-output MAPPING_OUTPUT]
```

### 2.2 What Gets Redacted vs. What Gets Preserved

| Data Category in Diagnostic Bundle | `sca-log-sanitize` Action | Example Output |
| :--- | :--- | :--- |
| **API Tokens & Auth Headers** (`Bearer ...`, `Basic ...`, `--blackduck.api.token=...`) | Redacted in place | `--blackduck.api.token=[REDACTED_TOKEN]` |
| **JDBC & URI Passwords** (`postgresql://user:pass@host:5432/bds_hub`) | Password stripped, scheme/user/port kept | `postgresql://blackduck_user:[REDACTED_SECRET]@[REDACTED_HOST]:5432/bds_hub` |
| **Internal FQDNs & Private IPv4s** (`hub-prod.acme-corp.internal`, `10.42.88.19`) | Replaced with `[REDACTED_HOST]` / `[REDACTED_IP]` | `https://[REDACTED_HOST]:8443` / `[REDACTED_IP]` |
| **Workstation User Paths** (`/home/ajones/workspace/...`, `C:\Users\ajones\...`) | Username scrubbed | `/REDACTED_HOME/[REDACTED_USER]/workspace/...` |
| **Proprietary Project & Version Names** (auto-extracted from `status/status.json` or `--projects-export`) | Deterministically tokenized (`Project_001`, `Version_001`) across all logs and `.bdio` JSON-LD graphs | `"projectName": "Project_001"`, `"projectVersion": "Version_001"` |
| **Binary Archives Inside `.zip`** (`.tar.gz`, `.tgz`, binary `.gz` streams) | **Preserved byte-for-byte** (checks first 512 bytes for null bytes before decompressing) | Unmodified binary checksum |
| **4-Part Product & DB Versions, Loopback, OIDs** (`2024.7.0.1`, `PostgreSQL 14.11.0.1`, `127.0.0.1`) | **Preserved untouched** (never mistaken for IPv4 addresses) | `Detect version: 10.1.0`, `Server 2024.7.0.1`, `127.0.0.1` |
| **API & Linux Kernel Cgroup Paths** (`/api/codelocations`, `/sys/fs/cgroup/memory.max`, `/proc/meminfo`) | **Preserved untouched** (never mistaken for `/home/` paths) | `/api/tokens/authenticate`, `/sys/fs/cgroup/memory.current` |

### 2.3 Before vs. After Example on a Detect Diagnostic Log Line

**Before (`detect-run-2026-11-04.zip -> logs/detect.log`)**:

```text
2026-11-04 09:14:22 INFO [main] -- Running Detect 10.1.0 against https://bdhub.acme-corp.internal:8443 (Server 2024.7.0.1)
2026-11-04 09:14:22 INFO [main] -- CLI args: --blackduck.api.token=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo= --detect.source.path=/home/ajones/builds/storage-ha-controller --detect.project.name=Storage-HA-Controller --detect.project.version.name=9.15.1-RC2-internal
2026-11-04 09:14:25 ERROR [main] -- Connection to 10.184.22.91:8443 timed out; contact ajones@acme-corp.com
```

**After running `sca-log-sanitize -i detect-run-2026-11-04.zip -o sanitized-run.zip --mapping-output token_map.json`**:

```text
2026-11-04 09:14:22 INFO [main] -- Running Detect 10.1.0 against https://[REDACTED_HOST]:8443 (Server 2024.7.0.1)
2026-11-04 09:14:22 INFO [main] -- CLI args: --blackduck.api.token=[REDACTED_TOKEN] --detect.source.path=/REDACTED_HOME/[REDACTED_USER]/builds/storage-ha-controller --detect.project.name=Project_001 --detect.project.version.name=Version_001
2026-11-04 09:14:25 ERROR [main] -- Connection to [REDACTED_IP]:8443 timed out; contact user@redacted.domain
```

And the local lookup table (`token_map.json`, saved on your workstation with `0600` permissions so you never lose track of which token maps to which internal project):

```json
{
  "term_to_token": {
    "Storage-HA-Controller": "Project_001",
    "9.15.1-RC2-internal": "Version_001"
  },
  "token_to_term": {
    "Project_001": "Storage-HA-Controller",
    "Version_001": "9.15.1-RC2-internal"
  }
}
```

---

## 3. `sca-diag` + `pj_collect.sh` + `pj_schema_gate.sql` (Offline Server, PostgreSQL & Container Diagnostic Suite)

**Codebase Size & Test Status**: `2,215` lines total across 3 components (`1,138` lines of Python in `diag.py`, `536` lines of Bash in `collectors/pj_collect.sh`, and `541` lines of SQL in `sql/pj_schema_gate.sql`), `8/8` unit/integration tests passing (including against real Detect 10 diagnostic bundles).

### 3.1 Origin: The 1.1 TB "One-Hoss Shay" Bottleneck Testbed

Before wrapping up my 12-year W2 run in June 2026, I built a **1.1 TB full-stack stress testbed ("One-Hoss Shay")** in my spare time to empirically isolate where massive enterprise deployments actually bottleneck across Linux kernel cgroups, JVM containers, internal message queues, and external PostgreSQL. That lab uncovered concrete, repeatable wins:

- **19.5 GB of Redundant PostgreSQL Indexes**: Identified `idx_scan = 0` non-unique secondary indexes consuming shared buffer RAM and adding write IOPS overhead on every scan insert.
- **11% Lower Database Insert Latency on Single-Replica Containers**: Achieved by tuning per-table `autovacuum` scale factors, `bgwriter_lru_maxpages`, and `shared_buffers` (paired with matching container `/dev/shm` sizing).
- **11 Minutes -> 41 Seconds Queue Bottleneck Reduction**: Isolated a single-channel internal queue consumer starving multi-core pods and widened it from 1 to 4 channels.

I turned those findings into a **3-part, 100% read-only diagnostic suite** that your DBA or platform engineer can run locally with zero risk to production and zero customer PII leakage:

### 3.2 Part A: Out-of-Pod OOM "Black Box" Flight Recorder (`collectors/pj_collect.sh`)

When a `webapp`, `scanmatch`, or `jobrunner` container gets killed by the Linux OOM-killer (`SIGKILL` / `exit 137`), any diagnostic script running *inside* the container dies with it and loses the capture.

`pj_collect.sh` solves this by streaming cgroup v1/v2 memory counters (`anon` JVM memory vs. `file` OS page cache), `/dev/shm` capacity, JVM Native Memory Tracking (`jcmd VM.native_memory`), Spring Boot `/metrics` Actuator gauges (`hikaricp_*`, `jvm_gc_pause_seconds_max`), and read-only PostgreSQL telemetry **from outside the pod over `kubectl/oc exec` (`--watch 2 300`)** so every sample up to **2 seconds before crash** is safely saved on your jump host:

- **100% Read-Only SQL (`BEGIN TRANSACTION READ ONLY` + `2s` lock timeout)**: Captures `pg_stat_bgwriter`, `pg_stat_database` temp spills, `pg_stat_user_indexes` 0-scan index overhead, and `pg_stat_user_tables` dead tuples, then executes `ROLLBACK`.
- **Portable In-SQL Query Fingerprinting (Solves the Cross-Customer `queryid` Trap)**: PostgreSQL's `pg_stat_statements.queryid` hashes internal table OIDs, which differ on every customer database. `pj_collect.sh` strips all single-quoted strings (`'...'`), dollar-quoted strings (`$tag$...$tag$`), UUIDs, integers, and `IN (...)` lists *inside SQL* before emitting an MD5 structural query fingerprint (`sql_md5`), allowing slow queries to be matched across any RDS/CloudSQL instance with zero customer strings.
- **Built-In Customer InfoSec Self-Audit (`./pj_collect.sh --verify-dlp`)**: Before sending `/tmp/pj_diag.jsonl` outside your network, your InfoSec team can run `--verify-dlp` to verify zero PII:

```text
$ ./collectors/pj_collect.sh --verify-dlp /tmp/pj_diag.jsonl
=== PJ_COLLECT DLP SELF-AUDIT: /tmp/pj_diag.jsonl (14 JSONL records) ===
[PASS] Zero email addresses detected.
[PASS] Zero filesystem paths detected.
[PASS] Zero unmasked SQL string literals detected.
[PASS] Zero dollar-quoted literals detected.
[PASS] Zero private IPv4 addresses detected.
[PASS] Zero authorization tokens or passwords detected.
=== DLP VERDICT: PASS (100% numeric/UUID/structural schema metadata) ===
```

### 3.3 Part B: 6-Gate Pre-Upgrade External PostgreSQL Readiness Audit (`sql/pj_schema_gate.sql`)

Wrapped in `BEGIN TRANSACTION READ ONLY; SET LOCAL lock_timeout = '2s'; ... ROLLBACK;`, `pj_schema_gate.sql` runs in under 5 seconds via `psql` and catches the exact external PostgreSQL drift that causes Friday-night upgrade failures and Monday-morning P1 outages:

| Gate | What `pj_schema_gate.sql` Audits | Classic Production Failure Caught |
| :--- | :--- | :--- |
| **Gate 1 & 1B** | Required extensions (`uuid-ossp`, `hstore`, `pg_stat_statements`), `xid_age` wraparound (`>1.5B`), 27 `pg_settings` parameters, `pg_stat_bgwriter` backend write ratio, and `pg_stat_database` daily temp-spill rate (`temp_bytes_per_day`) | Query threads stalled flushing dirty pages synchronously to disk (`buffers_backend > buffers_clean`) or spilling `>50 GB/day` of BOM sorts to disk because `work_mem` is left at `4 MB` |
| **Gate 2** | Flyway migration history (`st.schema_version`) integrity | Leftover `success = false` migration row from a prior interrupted upgrade that will cause the new upgrade installer to abort immediately |
| **Gate 3** | Comprehensive object ownership inventory across tables, partitioned tables, sequences, views, matviews, functions/procedures (`pg_proc`), custom types (`pg_type`), and schemas (`st`, `public`, `usermgmt`, `reporting`, `lds`) | Tables or functions accidentally owned by `postgres` or `rdsadmin` instead of `blackduck`, causing `ERROR: must be owner of table/relation` mid-upgrade |
| **Gate 4** | Default privileges role-scope check (`pg_default_acl`) | **The `defaclrole` Trap**: A DBA ran `ALTER DEFAULT PRIVILEGES IN SCHEMA st GRANT ... TO blackduck_user` while logged in as `postgres` instead of adding `FOR ROLE blackduck`. PostgreSQL silently scopes that ACL only to tables created by `postgres`, so when `blackduck` creates new tables during an upgrade, `blackduck_user` gets `permission denied` |
| **Gate 5A & 5B** | Unvalidated constraints (`convalidated = false`), invalid/unready indexes (`indisvalid = false`), disabled user triggers (`tgenabled = 'D'`), and per-schema structural MD5 catalog fingerprints | Interrupted `CREATE INDEX CONCURRENTLY` or `pg_restore` leaving broken indexes (`indisvalid = false`) that the query planner cannot use during scans |
| **Gate 6 & 6B** | Top 20 tables by dead-tuple bloat + custom `reloptions`, `pg_largeobject_metadata` count (`vacuumlo` check), and unused non-unique indexes (`idx_scan = 0`, `>= 10 MB`, with `< 7 days` `stats_reset` guard) | Multi-gigabyte 0-scan indexes and unvacuumed dead tuples starving shared buffers and slowing down scan ingestion |

### 3.4 Part C: Offline Root-Cause Analyzer (`sca-diag`)

`sca-diag` ingests the output of `pj_collect.sh`, `pj_schema_gate.sql`, container logs (`webapp`, `scanmatch`, `jobrunner`), and Detect `-d` diagnostic `.zip` bundles (`status/status.json` + `executables/EXE-*-ERR.xout`), ranking every finding by severity with exact symptoms, root cause, and remediation.

In addition to container cgroup OOMs, `/dev/shm` starvation (`64 MB` Docker default vs. `shared_buffers`), `HikariPool` timeouts, and PostgreSQL schema gates, `sca-diag` automatically catches tricky Detect and Signature Scanner failure modes inside `-d` diagnostic `.zip` bundles:

- **`DIAGNOSTIC_BUNDLE_OUTPUT_PATH_TRAP`** (from Pete's published Community article): Warns when `detect.output.path`, `detect.bdio.output.path`, or `detect.scan.output.path` are overridden in `status.json`, which causes Detect's `-d` zip generator to silently omit `.bdio` and scan outputs redirected outside `~/blackduck/runs/`.
- **`SIGNATURE_SCANNER_MISSING_JRE`**: Catches `Could not find the 'jre' directory` (Exit Code 6 `FAILURE_SCAN` on ARM64, Alpine musl, or airgapped runners) and prescribes `BDS_JAVA_HOME` or `--detect.blackduck.signature.scanner.local.path`.
- **`DETECT.EXECUTABLE_FAILED` (with Automatic `EXE-*-ERR.xout` Stderr Extraction)**: Automatically maps failed detectors in `status.json` through `executables/EXE-MAP.txt` to pull the exact package-manager stderr capture (for example, diagnosing Go `inconsistent vendoring` and prescribing `GOFLAGS=-mod=readonly` or `go mod vendor`).
- **`DETECT.ACCURACY_NOT_MET` & `DETECT.SETUPTOOLS_NO_DEPENDENCIES`**: Catches Detect 10's stricter `--detect.accuracy.required=ALL` failures and zero-dependency Python `pyproject.toml` projects failing the `SETUPTOOLS` detector (`--detect.excluded.detector.types=SETUPTOOLS`).

### 3.5 Sample `sca-diag` Execution Output

```text
$ sca-diag \
    --pj-collect /tmp/pj_diag.jsonl \
    --schema-gate /tmp/schema_gate.out \
    --logs webapp.log detect-run-2026-11-04.zip

=== Offline Server & PostgreSQL Diagnostic Report [CRITICAL] ===
Total Findings: 6

[CRITICAL] #1: Container OOM Kills Detected (3 kill events) (Container Memory & Cgroup)
  Symptoms:    cgroup memory.events records 3 processes terminated by the Linux OOM-killer.
  Root Cause:  Container memory limit (memory.max / memory.limit_in_bytes) was exceeded. JVM heap and off-heap allocations squeezed OS file page cache to zero.
  Remediation: Increase container memory limit in deployment/helm values, or adjust -XX:MaxRAMPercentage down to leave >= 2GB headroom for native process memory.

[CRITICAL] #2: Critically Constrained /dev/shm (64 MB < 256 MB) (Database /dev/shm)
  Symptoms:    /dev/shm mount size is only 64 MB (standard default is 64 MB).
  Root Cause:  Container runtime defaulted /dev/shm to 64MB. PostgreSQL parallel query workers and large hash joins require POSIX shared memory segments. Exceeding this triggers 'could not resize shared memory segment' errors.
  Remediation: Mount an emptyDir with medium: Memory to /dev/shm sized to match or exceed PostgreSQL shared_buffers (e.g. sizeLimit: 8Gi).

[CRITICAL] #3: Missing Default Privileges for Admin Role in Schema 'st' (PostgreSQL Default Privileges (Gate 4))
  Symptoms:    FAIL: Missing ALTER DEFAULT PRIVILEGES FOR ROLE blackduck IN SCHEMA st GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO blackduck_user
  Root Cause:  ALTER DEFAULT PRIVILEGES was either omitted or executed for role 'postgres' instead of 'FOR ROLE blackduck', so new tables created during upgrades will lack grants for blackduck_user.
  Remediation: Run ALTER DEFAULT PRIVILEGES FOR ROLE blackduck IN SCHEMA st GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO blackduck_user;

[HIGH] #4: Excessive Backend Dirty Page Eviction (90.9% backend writes) (PostgreSQL I/O & Bgwriter)
  Symptoms:    90.9% of buffer pool writes are performed directly by query backend threads (buffers_backend=5000 vs buffers_clean=500).
  Root Cause:  The background writer is not keeping pace with dirty page generation. Query worker threads are stalled waiting to flush dirty pages synchronously to disk.
  Remediation: Tune PostgreSQL settings: increase bgwriter_lru_maxpages (e.g. 1000-2000), lower bgwriter_delay (e.g. 50ms), and ensure shared_buffers is adequately sized.

[HIGH] #5: HikariCP Connection Pool Starvation (4 timeouts in webapp.log) (Database Connection Pool)
  Symptoms:    4 connection acquisition timeouts detected in log.
  Root Cause:  Database connection pool (maximumPoolSize) is saturated or backend queries are holding connections open longer than connectionTimeout during scan bursts.
  Remediation: Check PostgreSQL active connections and long-running queries in pg_stat_activity. Tune pool sizes in blackduck-config or investigate slow BOM queries.

[WARNING] #6: Output Path Overrides Cause Diagnostic Bundle Omissions (Detect Configuration & Diagnostic Bundling)
  Symptoms:    Properties detect.output.path, detect.bdio.output.path are overridden in status.json. Detect's diagnostic zip generator will exclude outputs redirected outside ~/blackduck/runs/.
  Root Cause:  When output paths (such as detect.output.path or detect.bdio.output.path) are redirected, Detect's diagnostic zip generator (-d / --detect.diagnostic=true) only archives the standard ~/blackduck/runs/ directory, omitting generated .bdio files and scan outputs.
  Remediation: Remove detect.output.path, detect.bdio.output.path, and detect.scan.output.path overrides during diagnostic runs, or manually collect external directories when submitting diagnostic bundles to Black Duck Support.
```
