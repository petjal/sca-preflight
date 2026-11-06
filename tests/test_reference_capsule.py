"""End-to-end integration test suite for sca-prescan and the reference benchmark capsule.

Uses only the Python standard library (unittest) so CI and enterprise security
teams can execute tests with zero external pip dependencies:
    PYTHONPATH=src python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sca_preflight.prescan import (
    generate_ai_brief_html,
    generate_ai_brief_markdown,
    scan_workspace,
)
from sca_preflight.reference_scan import unpack_armored_capsule_b64

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPSULE_B64 = REPO_ROOT / "benchmark" / "sca_preflight_reference_capsule.b64"
GROUND_TRUTH_PATH = REPO_ROOT / "benchmark" / "GROUND_TRUTH_MANIFEST.json"


class TestReferenceCapsuleAndPrescan(unittest.TestCase):
    """Verify sca-prescan against the 3-mode reference benchmark capsule."""

    def test_capsule_parity_and_full_prescan(self) -> None:
        self.assertTrue(CAPSULE_B64.is_file(), f"Missing capsule: {CAPSULE_B64}")
        self.assertTrue(GROUND_TRUTH_PATH.is_file(), f"Missing manifest: {GROUND_TRUTH_PATH}")

        expected = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as td:
            ws_dir = Path(td) / "sca_preflight_reference_scan"
            ws_dir.mkdir(parents=True, exist_ok=True)
            unpack_armored_capsule_b64(CAPSULE_B64, ws_dir)

            # Remove GROUND_TRUTH_MANIFEST.json before scanning target files, or verify embedded manifest matches
            embedded_manifest = ws_dir / "GROUND_TRUTH_MANIFEST.json"
            self.assertTrue(embedded_manifest.is_file())
            self.assertEqual(
                json.loads(embedded_manifest.read_text(encoding="utf-8")),
                expected,
            )
            embedded_manifest.unlink()

            report = scan_workspace(ws_dir, repo_only=True)

            # 1. 4-Bucket File & Byte Disposition Accounting conservation of mass
            acct = report["file_accounting"]
            b2a = acct["bucket_2a_actionable_l1_files"]["count"]
            b2b = acct["bucket_2b_provenance_only_l2_files"]["count"]
            b3 = acct["bucket_3_early_stop_unhashed_files"]["count"]
            total_files = report["total_files_scanned"]
            self.assertEqual(total_files, 29)
            self.assertEqual((b2a, b2b, b3), (25, 4, 0))
            self.assertEqual(b2a + b2b + b3, total_files)

            # 2. L0 / L1 / L2 / CFG workspace provenance hashes
            prov = report["scan_input_provenance"]
            self.assertEqual(
                prov["multilayer_codebase_signature"],
                expected["multilayer_codebase_signature"],
            )
            self.assertEqual(
                prov["topology_skeleton_sha256"],
                expected["topology_skeleton_sha256"],
            )
            self.assertEqual(
                prov["dependency_inputs_merkle_sha256"],
                expected["dependency_inputs_merkle_sha256"],
            )
            self.assertEqual(
                prov["workspace_tree_merkle_sha256"],
                expected["workspace_tree_merkle_sha256"],
            )

            # 3. Vulnerability matches (37 total matches across 30 unique CVEs/GHSAs)
            vulns = report["actionable_vulnerabilities"]
            self.assertEqual(len(vulns), expected["expected_vulnerability_matches_count"])
            found_cves = sorted({v["cve_id"] for v in vulns})
            self.assertEqual(found_cves, sorted(expected["expected_cves"]))

            # Verify unpatched code-snippet and shaded-bytecode detections in mode_3
            by_cve_and_src = {(v["cve_id"], v["evidence_source"]): v for v in vulns}
            self.assertIn(
                (
                    "CVE-2021-44228",
                    "bytecode_pattern:mode_3_unversioned_snippets/shaded_stripped/enterprise_gateway_shaded.jar!/org/apache/logging/log4j/core/lookup/JndiLookup.class",
                ),
                by_cve_and_src,
            )
            self.assertIn(
                ("CVE-2025-24813", "code_snippet:mode_3_unversioned_snippets/java_unversioned/DefaultServlet.java"),
                by_cve_and_src,
            )
            self.assertIn(
                ("CVE-2026-109618", "code_snippet:mode_3_unversioned_snippets/c_native/zend_alloc.c"),
                by_cve_and_src,
            )
            self.assertIn(
                ("CVE-2026-111497", "code_snippet:mode_3_unversioned_snippets/c_native/decode.c"),
                by_cve_and_src,
            )
            self.assertIn(
                ("GHSA-hff9-5pqw-6w9f", "code_snippet:mode_3_unversioned_snippets/go_pre_nvd/network.go"),
                by_cve_and_src,
            )

            # 4. License & rugpull rules (8 expected rules)
            lic_risks = report["actionable_license_risks"]
            found_lic_rules = sorted({r["rule_id"] for r in lic_risks})
            self.assertEqual(found_lic_rules, sorted(expected["expected_license_rules"]))

            # 5. Markdown & HTML report generation and DLP/path hygiene
            md_brief = generate_ai_brief_markdown(report)
            html_brief = generate_ai_brief_html(report)
            self.assertIn("## 1. Workspace Input & Config Hashes (L0 / L1 / L2 / CFG)", md_brief)
            self.assertIn("actionable_vulnerabilities_count: 37", md_brief)
            self.assertIn("actionable_license_risks_count: 8", md_brief)
            self.assertNotIn("/home/", md_brief)
            self.assertNotIn("\u2014", md_brief)
            self.assertNotIn("\u2013", md_brief)
            self.assertIn('id="sca-ops-ai-brief-json"', html_brief)

    def test_sshhole_cve_2026_123158_snippet_and_patch_guard(self) -> None:
        """Verify CVE-2026-123158 (OpenSSH < 10.6p2 musl password auth bypass) snippet and MIN_PASSWORD_HASH_LEN guard."""
        with tempfile.TemporaryDirectory() as td:
            unpatched_ws = Path(td) / "openssh_unpatched"
            unpatched_ws.mkdir(parents=True, exist_ok=True)
            (unpatched_ws / "auth-passwd.c").write_text(
                "int sys_auth_passwd(struct ssh *ssh, const char *password) {\n"
                "    struct passwd *pw = ssh->authctxt->pw;\n"
                "    char *encrypted_password, *salt = NULL;\n"
                "    char *pw_password = ssh->authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;\n"
                "    encrypted_password = xcrypt(password, salt);\n"
                "    return encrypted_password != NULL &&\n"
                "        strcmp(encrypted_password, pw_password) == 0;\n"
                "}\n",
                encoding="utf-8",
            )
            rep_unpatched = scan_workspace(unpatched_ws, repo_only=True)
            cves_unpatched = {v["cve_id"]: v for v in rep_unpatched["actionable_vulnerabilities"]}
            self.assertIn("CVE-2026-123158", cves_unpatched)
            self.assertEqual(cves_unpatched["CVE-2026-123158"]["evidence_source"], "code_snippet:auth-passwd.c")

            patched_ws = Path(td) / "openssh_patched"
            patched_ws.mkdir(parents=True, exist_ok=True)
            (patched_ws / "auth-passwd.c").write_text(
                "#define MIN_PASSWORD_HASH_LEN 4\n"
                "int sys_auth_passwd(struct ssh *ssh, const char *password) {\n"
                "    int ret = encrypted_password != NULL &&\n"
                "        strlen(pw_password) >= MIN_PASSWORD_HASH_LEN &&\n"
                "        strcmp(encrypted_password, pw_password) == 0;\n"
                "    return ret;\n"
                "}\n",
                encoding="utf-8",
            )
            rep_patched = scan_workspace(patched_ws, repo_only=True)
            cves_patched = {v["cve_id"]: v for v in rep_patched["actionable_vulnerabilities"]}
            self.assertNotIn("CVE-2026-123158", cves_patched)


if __name__ == "__main__":
    unittest.main()
