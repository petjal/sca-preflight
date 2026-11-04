# Companion Contractor Toolkit Walkthrough (`sca-bom-ifttt`, `sca-log-sanitize`, `sca-tealeaves`)

Whereas `sca-prescan` (open-sourced in [`src/sca_preflight/`](../src/sca_preflight/) under the MIT License) runs **before** your scan to calibrate CLI flags and catch blind spots, the three companion tools documented on this page run **after** your scan to clean up noisy BOMs, scrub sensitive data from support logs, and troubleshoot server or PostgreSQL bottlenecks.

> **Current Status & Customer Staging Partner Invitation**:
> I built and maintain these three utilities (`sca-bom-ifttt`, `sca-log-sanitize`, and `sca-tealeaves`) in a private toolkit repository (`94` passing unit tests) for use during W2 and 1099 customer engagements.
>
> Because I work as an independent engineer and do not run a licensed commercial SCA server in my home lab:
> - **100% Tested & Ready Today (Offline & Dry-Run Modes)**: Offline BOM JSON rule evaluation (`--offline-bom-file`), offline code-location unmapping previews (`--offline-codelocations-file`), `.bdio` vs. BOM dropped-component checks (`--verify-bdio`), and streaming `.zip` / `.bdio` / `.sql` log sanitization (`sca-log-sanitize`) are 100% built and verified against offline fixtures and real Detect diagnostic bundles.
> - **Ready for Live Customer Staging Validation**: The live REST API mutation phase (`--apply` sending `PUT` and `DELETE` calls against a live server) is built with token-bucket rate limiting and pre-mutation JSONL audit logging, and is ready to be validated against a customer's non-production or staging server.
>
> **Want to test-drive or co-develop these against your staging environment?** If your team has a non-production server, an exported BOM JSON file, or a tricky diagnostic `.zip` bundle and wants to collaborate on tuning these rules for your environment, email **`pjalajas+sca-preflight@gmail.com`**.

---

## 1. `sca-bom-ifttt` (Declarative Post-Scan BOM Cleanup & Code Location Unmapper)

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

1. **Two-Phase Execution Guard (Prevents `HTTP 409 Conflict` Races)**:
   - Unmapping or deleting a code location (`phase = "codelocation"`) triggers asynchronous `bomengine` recalculation on the server. If a script immediately sends `PUT` edits to BOM components (`phase = "bom_component"`) while `bomengine` is still recalculating, the server rejects the edits or corrupts component state.
   - `sca-bom-ifttt` enforces strict phase separation: it blocks rulefiles that mix `codelocation` and `bom_component` rules unless `--allow-two-phase-wait` is explicitly passed.
2. **Pre-Mutation JSONL Rollback & Audit Trail (`ifttt_audit.jsonl`)**:
   - Before any `PUT` or `DELETE` request is sent in `--apply` mode, the engine records the exact `before_state` (`componentName`, `componentVersionName`, `reviewStatus`, `ignored`, `usages`, `mappedProjectVersion`) and `after_payload` to a local `.jsonl` audit file alongside the mandatory rule comment written to the server UI.
3. **Production REST Pacing**:
   - Uses a client-side token-bucket rate limiter (`--max-rps 5.0` default), proactive Bearer token renewal at 80% of TTL, snapshot-first pagination deduplicated by `_meta.href`, and exponential backoff on `HTTP 429 / 502 / 503 / 504`.

### 1.3 The 4 Enterprise BOM Accuracy Rules (`sample_bom_ifttt_rules.toml`)

See [`examples/sample_bom_ifttt_rules.toml`](sample_bom_ifttt_rules.toml) for the complete sample TOML file covering four common post-scan cleanup tasks:

- **Problem A (`require_parent_component_regex` - Framework Sub-Component Rollup)**:
  - Automatically ignores noisy sub-components (such as `jackson-core` and `jackson-annotations`) when the parent umbrella package (`jackson-databind`) is already present and unignored in the same BOM.
- **Problem B (`--verify-bdio` - Dropped Zero-Day / Unindexed KB Component Check)**:
  - Compares every `#Component` node inside the uploaded `.bdio` archive against the server's `/components` JSON response. If a newly published package version was discovered by Detect and uploaded in `.bdio`, but silently dropped from the server BOM because the central KnowledgeBase has not indexed that version yet, `sca-bom-ifttt` flags it (`ZERO_DAY_COMPONENTS_DROPPED`).
- **Problem C (`require_newer_exact_dependency_present` & `require_prescan_version_mismatch` - Signature Scan `N-1` Aliasing Override)**:
  - When the signature scanner guesses an older `N-1` version via fuzzy file matching (`FILE_SOME_FILES_MODIFIED` or `FILE_FILES_ADDED_DELETED_AND_MODIFIED`), `sca-bom-ifttt` checks whether an exact package-manager lockfile match (`FILE_DEPENDENCY*`) or a ground-truth `sca-prescan` archive/filename version assertion already proves the true version on disk.
- **Problem D (`license_name_regex` - Dual-License / Commercial Exception Review)**:
  - Marks known dual-licensed components (such as `MySQL-Connector-Java`, `OpenSSL`, or `cURL`) as `REVIEWED` with your compliance team's standard policy comment.

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

## 2. `sca-log-sanitize` (Streaming Diagnostic `.zip`, `.bdio` & SQL DLP Scrubber)

**Codebase Size & Test Status**: `485` lines of Python (`log_sanitize.py`), `8/8` unit tests passing (including multi-megabyte Detect 10 diagnostic `.zip` bundles with nested `.bdio` and `.gz` archives).

When a scan fails or a server slows down, engineers often cannot share Detect diagnostic `.zip` bundles or container logs with outside consultants or internal AI assistants because the logs contain API tokens, JDBC passwords, internal hostnames (`.corp`, `.internal`), employee usernames (`/home/jsmith/...`), and proprietary project names.

`sca-log-sanitize` scrubs plain-text logs, `.jsonl` telemetry, `.sql` dumps, and nested `.zip` / `.gz` / `.bdio` diagnostic bundles in a single streaming pass while **preserving the technical signal needed to debug the problem**.

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
| **Workstation User Paths** (`/home/pgupta/workspace/...`, `C:\Users\pgupta\...`) | Username scrubbed | `/REDACTED_HOME/[REDACTED_USER]/workspace/...` |
| **Proprietary Project & Version Names** (auto-extracted from `status/status.json` or `--projects-export`) | Deterministically tokenized (`Project_001`, `Version_001`) across all logs and `.bdio` JSON-LD graphs | `"projectName": "Project_001"`, `"projectVersion": "Version_001"` |
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

## 3. `sca-tealeaves` (Offline Server, PostgreSQL & Container Cgroup Diagnostic Analyzer)

**Codebase Size & Test Status**: `1,066` lines of Python (`tealeaves.py`), tested against offline container logs and PostgreSQL diagnostic captures.

Once a support bundle or database telemetry dump has been sanitized by `sca-log-sanitize`, `sca-tealeaves` inspects the logs, container cgroup counters (`pj_collect.sh`), and read-only PostgreSQL catalog snapshots (`pj_schema_gate.sql`) to rank the root causes of slow scans and UI timeouts:

- **Container Cgroup Memory vs. OS Page Cache**: Distinguishes genuine container OOM-kills (`memory.oom.group` / `OutOfMemoryError`) from benign Linux file page cache usage.
- **PostgreSQL `/dev/shm` Starvation**: Flags containers where `/dev/shm` is left at the 64 MB Docker default while PostgreSQL `shared_buffers` or parallel workers attempt to allocate shared memory segments (`No space left on device` during large BOM recalculations).
- **HikariCP Connection Pool Exhaustion**: Detects `HikariPool` acquisition timeouts (`Connection is not available, request timed out after 30000ms`), connection leaks, and VM clock-leap stalls across `webapp`, `scanmatch`, and `jobrunner`.
- **Database Index & Dead-Tuple Bloat**: Evaluates `pg_stat_user_tables` and `pg_stat_user_indexes` to pinpoint multi-gigabyte unused indexes, high dead-tuple ratios starving autovacuum, and unindexed foreign-key deletes during scan unmapping.
