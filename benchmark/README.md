# What Is Inside `sca_preflight_reference_capsule.b64`?

[`sca_preflight_reference_capsule.b64`](sca_preflight_reference_capsule.b64) is a tiny `.tar.gz` folder (about **11 KB total** across **25 files**) encoded as Base64 text so GitHub Dependabot does not spam automated security alerts on this test repository.

When you unpack it into `/dev/shm/sca_preflight_reference_scan`:

```bash
mkdir -p /dev/shm/sca_preflight_reference_scan && \
  grep -v '^#' benchmark/sca_preflight_reference_capsule.b64 | base64 -d | tar -xzf - -C /dev/shm/sca_preflight_reference_scan
```

it creates two top-level test directories:
- **`mode_1_knowns/`**: Standard dependencies that an SCA scanner will find *if* its folder-depth and standalone-JAR settings are turned on.
- **`mode_2_unknowns/`**: Hidden or tricky dependencies (shaded uber-JARs, stripped C/C++ `.so` files, UTF-16 manifests, cached tarballs) that default scanner settings usually miss.

> **How does this connect to your real builds?** This free test folder shows what default scanner settings miss when you already have an answer key (`GROUND_TRUTH_MANIFEST.json`). For your **real** production repos (where you don't have an answer key), Pete's private **`sca-ops-toolkit`** is designed to run right *before* your regular SCA scanner to spot early hints of these critical issues while automatically generating the tuned CLI flags your scanner needs to catch them cleanly. See [Section 3 below](#3-how-to-catch-these-issues-in-your-real-builds) for how to use it with your team.

---

## 1. One Example of Each of the 8 Types of Test Files Inside

### 1. Standard Java JAR (`mode_1_knowns/lib/log4j-core-2.14.1.jar` - 743 bytes)
- **What is inside**: Not the real 1.8 MB Apache Log4j library. It is a tiny 743-byte valid `.zip`/`.jar` containing:
  - `META-INF/MANIFEST.MF`
  - `META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties` (`groupId=org.apache.logging.log4j`, `artifactId=log4j-core`, `version=2.14.1`)
  - A 42-byte dummy Java class header (`0xCAFEBABE`) at `org/apache/logging/log4j/core/lookup/JndiLookup.class`.
- **What it tests**: Whether your scanner checks standalone `.jar` files in a `lib/` folder when there is no `pom.xml` or `build.gradle` next to them, and whether it flags **Log4Shell (`CVE-2021-44228`)**.

### 2. Shaded "Uber-JAR" (`mode_2_unknowns/vendor/shaded/telemetry_agent_shaded.jar` - 1,523 bytes)
- **What is inside**: A single `.jar` file named after a fake internal tool (`telemetry_agent_shaded.jar`), but inside `META-INF/maven/` it has **three** embedded `pom.properties` files (`telemetry-agent 1.0.0`, `log4j-core 2.14.1`, and `commons-text 1.9`) plus the `JndiLookup.class` and `StringSubstitutor.class` paths.
- **What it tests**: Many Java teams bundle third-party libraries inside one big "fat" or "shaded" JAR. If a scanner only looks at the outer filename (`telemetry_agent_shaded.jar`), it misses both **Log4Shell (`CVE-2021-44228`)** and **Text4Shell (`CVE-2022-42889`)** hiding inside.

### 3. Stripped C/C++ Shared Library (`mode_2_unknowns/vendor/native/libdb_storage_kv.so` - 52 bytes)
- **What is inside**: A 52-byte file starting with the Linux ELF binary magic bytes (`\x7fELF...`) followed by the ASCII version string `Redis server v=7.4.0 sha=00000000:0 malloc=libc`.
- **What it tests**: In C/C++ or storage appliance builds, teams often check in pre-compiled `.so` libraries with generic filenames (`libdb_storage_kv.so`). Default Detect settings don't run binary/string inspection, so they miss that this file embeds **Redis 7.4.0** (which switched from permissive `BSD-3-Clause` to the restrictive **`RSALv2 / SSPL-1.0`** license).

### 4. UTF-16LE Python Manifest (`mode_2_unknowns/services/auth_worker/requirements.txt` - 104 bytes)
- **What is inside**: A 3-line Python `requirements.txt` (`PyYAML==5.3.1`, `urllib3==1.26.4`, `cryptography==41.0.5`), but saved with a Windows PowerShell **UTF-16 Little-Endian BOM (`0xFF 0xFE`)** where every ASCII character is separated by a null byte (`\x00`).
- **What it tests**: When a developer on Windows runs `pip freeze > requirements.txt` in PowerShell, it saves as UTF-16LE. Many Linux-based scanners try to read `requirements.txt` as UTF-8, fail silently on the null bytes, and report `0` Python dependencies (missing `CVE-2020-14343` in `PyYAML 5.3.1`, `CVE-2023-45803` in `urllib3 1.26.4`, and `CVE-2023-49083` in `cryptography 41.0.5`).

### 5. Plain-Text Go Module File (`mode_1_knowns/services/ingress_proxy/go.mod` - 159 bytes)
- **What is inside**: A normal `go.mod` file nested 3 folders deep (`mode_1_knowns/services/ingress_proxy/go.mod`) declaring `github.com/hashicorp/vault v1.16.0` and `github.com/minio/minio`.
- **What it tests**:
  - **Depth trap**: Because it sits 3 folders down from the root, `--detect.detector.search.depth=0` completely ignores it.
  - **License rugpulls**: Flags that HashiCorp Vault `v1.16.0` switched from `MPL-2.0` to **`BSL-1.1`**, and MinIO switched from `Apache-2.0` to **`AGPL-3.0-only`**.

### 6. Vendored C/C++ Source Tarball (`mode_2_unknowns/vendor/archives/openssl-3.0.4.tar.gz` - 165 bytes)
- **What is inside**: A tiny `.tar.gz` archive containing a 1-line `README` (`OpenSSL 3.0.4`). (A sibling tarball, `readline-8.2.tar.gz`, also includes a `COPYING` file with the `GNU GENERAL PUBLIC LICENSE Version 3` header).
- **What it tests**: Whether your scanner inspects vendored `.tar.gz` source archives in a `vendor/archives/` directory and flags **OpenSSL `3.0.4` (`CVE-2022-2274`, CVSS 9.8, and `CVE-2022-3602`)** and **GNU Readline `8.2` (`GPL-3.0-only`)**.

### 7. Cached npm Package Tarball (`mode_2_unknowns/vendor/npm_cache/lodash-4.17.19.tgz` - 147 bytes)
- **What is inside**: A `.tgz` archive containing `package/package.json` (`{"name": "lodash", "version": "4.17.19"}`).
- **What it tests**: Offline or air-gapped enterprise builds often keep cached `.tgz` packages in a vendor folder without running `npm install`. Tests whether the scanner inspects `.tgz` archives and catches **`CVE-2021-23337`**.

### 8. Cached .NET NuGet Package (`mode_2_unknowns/vendor/nuget_feed/newtonsoft.json.12.0.3.nupkg` - 231 bytes)
- **What is inside**: A `.nupkg` (zip) file containing `Newtonsoft.Json.nuspec` (`<id>Newtonsoft.Json</id><version>12.0.3</version>`).
- **What it tests**: Whether the scanner inspects offline NuGet `.nupkg` feeds and catches **`CVE-2024-21907`**.

---

## 2. Full List of All 25 Files Inside the Unpacked Capsule

| Unpacked Relative File Path | Size (Bytes) | What It Tests |
| :--- | :---: | :--- |
| `GROUND_TRUTH_MANIFEST.json` | 1,823 | Answer key (expected CVEs, license rules, traps, and `sca-sig:v2` digests) |
| `mode_1_knowns/lib/activemq-client-5.18.2.jar` | 778 | `CVE-2023-46604` (CVSS 10.0, CISA-KEV) |
| `mode_1_knowns/lib/bcprov-jdk15on-1.66.jar` | 734 | `CVE-2020-28052` (BouncyCastle auth bypass) |
| `mode_1_knowns/lib/commons-text-1.9.jar` | 709 | `CVE-2022-42889` (Text4Shell, CVSS 9.8) |
| `mode_1_knowns/lib/itextpdf-5.5.13.3.jar` | 818 | `LIC-RUGPULL-ITEXT-AGPL` & `LIC-DPI-AGPL-3_0` (`AGPL-3.0-only`) |
| `mode_1_knowns/lib/log4j-core-2.14.1.jar` | 743 | `CVE-2021-44228` (Log4Shell, CVSS 10.0, CISA-KEV) |
| `mode_1_knowns/lib/mysql-connector-j-8.0.33.jar` | 657 | `LIC-COPYLEFT-MYSQL-CONNECTOR-GPL2` (`GPL-2.0-only`) |
| `mode_1_knowns/lib/postgresql-42.2.18.jar` | 637 | `CVE-2022-21724` (pgjdbc RCE, CVSS 9.8) |
| `mode_1_knowns/lib/snakeyaml-1.33.jar` | 672 | `CVE-2022-1471` (SnakeYAML deserialization, CVSS 9.8) |
| `mode_1_knowns/lib/spring-beans-5.3.17.jar` | 751 | `CVE-2022-22965` (Spring4Shell, CVSS 9.8, CISA-KEV) |
| `mode_1_knowns/services/ingress_proxy/go.mod` | 159 | `LIC-RUGPULL-HASHICORP-BSL` (`BSL-1.1`) & `LIC-RUGPULL-MINIO-AGPL` (`AGPL-3.0-only`) |
| `mode_2_unknowns/services/auth_worker/requirements.txt` | 104 | `UTF-16LE` manifest encoding trap + `CVE-2020-14343`, `CVE-2023-45803`, `CVE-2023-49083` |
| `mode_2_unknowns/services/ingress_proxy/go.mod` | 155 | Nested Go module + `CVE-2023-39325` (CISA-KEV), `CVE-2023-45288`, `CVE-2024-24786` |
| `mode_2_unknowns/vendor/archives/curl-8.3.0.tar.gz` | 161 | `CVE-2023-38545` (curl SOCKS5 heap overflow, CVSS 9.8) |
| `mode_2_unknowns/vendor/archives/expat-2.6.2.tar.gz` | 153 | `CVE-2024-45490` (libexpat XML parser, CVSS 9.8) |
| `mode_2_unknowns/vendor/archives/openssl-3.0.4.tar.gz` | 165 | `CVE-2022-2274` (CVSS 9.8) & `CVE-2022-3602` |
| `mode_2_unknowns/vendor/archives/PyYAML-5.3.1.tar.gz` | 150 | `CVE-2020-14343` (PyYAML arbitrary code execution, CVSS 9.8) |
| `mode_2_unknowns/vendor/archives/readline-8.2.tar.gz` | 168 | `LIC-COPYLEFT-GNU-READLINE-GPL3` & `LIC-DPI-GPL-3_0` (`GPL-3.0-only`, not LGPL) |
| `mode_2_unknowns/vendor/archives/zlib-1.2.11.tar.gz` | 151 | `CVE-2022-37434` (zlib heap overflow, CVSS 9.8) |
| `mode_2_unknowns/vendor/native/libdb_storage_kv.so` | 52 | Stripped ELF `.so` embedding Redis `7.4.0` (`LIC-RUGPULL-REDIS-RSAL-SSPL`) |
| `mode_2_unknowns/vendor/native/libstorage_compress.so` | 107 | Stripped ELF `.so` embedding zlib `1.2.11` (`CVE-2022-37434`) |
| `mode_2_unknowns/vendor/npm_cache/cross-spawn-7.0.4.tgz` | 151 | Cached npm tarball (`CVE-2024-21538`, CVSS 9.8) |
| `mode_2_unknowns/vendor/npm_cache/lodash-4.17.19.tgz` | 147 | Cached npm tarball (`CVE-2021-23337`) |
| `mode_2_unknowns/vendor/nuget_feed/newtonsoft.json.12.0.3.nupkg` | 231 | Cached NuGet `.nupkg` (`CVE-2024-21907`) |
| `mode_2_unknowns/vendor/shaded/telemetry_agent_shaded.jar` | 1,523 | Multi-`pom.properties` shaded uber-JAR (`CVE-2021-44228` + `CVE-2022-42889`) |

---

## 3. How to Catch These Issues in Your Real Builds

In this test project, you have [`GROUND_TRUTH_MANIFEST.json`](GROUND_TRUTH_MANIFEST.json) to tell you what your scanner missed. In your own production repositories, you don't have an answer key when a scan finishes with `0` errors but quietly skips a shaded JAR, a stripped `.so` library, or a `UTF-16` manifest.

That is what the separate, private **`sca-ops-toolkit`** repository is built for (see sample outputs from it in [`../examples/`](../examples/)):

- **Run `sca-prescan` *before* your standard SCA scanner**:
  - It scans your workspace in a few seconds (read-only, without running your build) to find early hints of these high-risk issues (shaded uber-JARs, stripped `.so` version strings, `UTF-16` manifests, `AGPL`/`SSPL`/`BSL` license changes, and CISA-KEV / CVSS 9.8-10.0 dependencies).
  - At the same time, it calculates the **tuned CLI flags** for your actual SCA scanner (`search.depth`, memory limits, safe folder exclusions, and the `sca-sig:v2` workspace fingerprint) and sets an expected minimum component count so your pipeline fails fast if a detector silently drops a subproject.
  - **Honest Scope (Small Hit-List, Zero Promises)**: `sca-prescan` is **not** a replacement for a full SCA vulnerability database and **promises nothing** when it comes to catching every CVE out there. Its built-in catalog is intentionally tiny - just a curated hit-list of well-known CVSS 9.8-10.0 / CISA-KEV disasters (Log4Shell, Spring4Shell, Text4Shell, OpenSSL, zlib, curl, pgjdbc) and major license rugpulls (`AGPL-3.0`, `SSPL-1.0`, `RSALv2`, `BSL-1.1`). Its job is to give you a fast, 5-second heads-up on the worst-of-the-worst blind spots and tune your main scanner so your real vulnerability database does its job properly.
- **Run `sca-bom-ifttt` *after* your scan**:
  - Uses simple rule files ([`../examples/sample_bom_ifttt_rules.toml`](../examples/sample_bom_ifttt_rules.toml)) to unmap stale CI build scans, roll up noisy subcomponents, suppress duplicate `N-1` signature-scan noise, and flag brand-new component versions that were uploaded in `.bdio` but dropped from the server BOM.

### Licensing & Advisory Contact

If your team wants to license **`sca-ops-toolkit`** for your internal CI/CD pipelines, or bring Pete in for a focused consulting engagement to tune your SCA scans, automate BOM cleanup, or troubleshoot server/database bottlenecks:

- **Emil Walter "Pete" Jalajas**
- Email: `pjalajas@gmail.com`
- Phone: `978-225-0525`
- LinkedIn: https://linkedin.com/in/ewpj
- GitHub: https://github.com/petjal
