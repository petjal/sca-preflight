"""Unit tests for zero-secret Black Duck Detect API token shape and source hygiene checks."""

from __future__ import annotations

import json
import unittest

from sca_preflight.prescan import inspect_detect_token_hygiene


class TestDetectTokenHygiene(unittest.TestCase):
    """Verify length, shape, CI corruption classes, precedence conflicts, and zero-secret output."""

    def test_valid_100_char_token_and_zero_secret_leak(self) -> None:
        secret = "SECRET_CANARY_TOKEN_" + ("A1b2C3d4" * 10)  # 100 chars
        self.assertEqual(len(secret), 100)
        res = inspect_detect_token_hygiene(env={"BLACKDUCK_API_TOKEN": secret})
        self.assertEqual(res["status"], "ok")
        self.assertTrue(res["token_present"])
        self.assertEqual(res["effective_source"], "env:BLACKDUCK_API_TOKEN")
        self.assertEqual(res["effective_raw_length"], 100)
        self.assertEqual(res["effective_trimmed_length"], 100)
        self.assertEqual(res["effective_shape"], "plausible_token_shape")
        self.assertEqual(res["issues"], [])
        # Strict zero-secret invariant: no token characters or substrings may appear in serialized output
        serialized = json.dumps(res)
        self.assertNotIn("SECRET_CANARY", serialized)
        self.assertNotIn("A1b2C3d4", serialized)

    def test_empty_whitespace_and_literal_null_injections(self) -> None:
        r_empty = inspect_detect_token_hygiene(bd_token="", include_env=False)
        self.assertEqual(r_empty["status"], "invalid")
        self.assertEqual(r_empty["effective_raw_length"], 0)
        self.assertEqual(r_empty["effective_shape"], "empty")

        r_ws = inspect_detect_token_hygiene(bd_token="  \n\r\t ", include_env=False)
        self.assertEqual(r_ws["status"], "invalid")
        self.assertEqual(r_ws["effective_raw_length"], 6)
        self.assertEqual(r_ws["effective_trimmed_length"], 0)
        self.assertEqual(r_ws["effective_shape"], "whitespace_only")

        for junk in ("null", "NULL", "undefined", "None", "*****"):
            r_null = inspect_detect_token_hygiene(bd_token=junk, include_env=False)
            self.assertEqual(r_null["status"], "invalid")
            self.assertEqual(r_null["effective_shape"], "literal_placeholder")

    def test_html_xml_json_and_unexpanded_ci_variables(self) -> None:
        html_err = "<html><body><h1>502 Bad Gateway</h1></body></html>"
        r_html = inspect_detect_token_hygiene(env={"BLACKDUCK_API_TOKEN": html_err})
        self.assertEqual(r_html["status"], "invalid")
        self.assertEqual(r_html["effective_shape"], "html_or_xml_junk")
        self.assertNotIn("502 Bad Gateway", json.dumps(r_html))

        xml_err = '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>'
        r_xml = inspect_detect_token_hygiene(env={"BLACKDUCK_API_TOKEN": xml_err})
        self.assertEqual(r_xml["effective_shape"], "html_or_xml_junk")

        json_err = '{"errors":["permission denied fetching secret"]}'
        r_json = inspect_detect_token_hygiene(env={"BLACKDUCK_API_TOKEN": json_err})
        self.assertEqual(r_json["effective_shape"], "json_payload_junk")
        self.assertNotIn("permission denied", json.dumps(r_json))

        for unexp in ("${BLACKDUCK_API_TOKEN}", "$BD_TOKEN", "%BLACKDUCK_API_TOKEN%", "{{ secrets.BD_TOKEN }}"):
            r_var = inspect_detect_token_hygiene(env={"BLACKDUCK_API_TOKEN": unexp})
            self.assertEqual(r_var["effective_shape"], "unexpanded_ci_variable")

    def test_quotes_newlines_prefixes_and_truncation(self) -> None:
        tok_100 = "X" * 100
        r_quotes = inspect_detect_token_hygiene(bd_token=f'"{tok_100}"', include_env=False)
        self.assertEqual(r_quotes["effective_shape"], "wrapped_in_quotes")
        self.assertEqual(r_quotes["effective_raw_length"], 102)

        r_nl = inspect_detect_token_hygiene(bd_token=f"{tok_100}\n", include_env=False)
        self.assertEqual(r_nl["status"], "invalid")
        self.assertEqual(r_nl["effective_raw_length"], 101)
        self.assertEqual(r_nl["effective_trimmed_length"], 100)
        self.assertEqual(r_nl["effective_shape"], "surrounding_whitespace")

        r_bearer = inspect_detect_token_hygiene(bd_token=f"Bearer {tok_100}", include_env=False)
        self.assertEqual(r_bearer["effective_shape"], "auth_scheme_prefix")

        r_trunc = inspect_detect_token_hygiene(bd_token="abcd1234efgh5678", include_env=False)
        self.assertEqual(r_trunc["effective_shape"], "truncated_length")
        self.assertEqual(r_trunc["effective_raw_length"], 16)

    def test_detect_prefix_trap_and_multi_source_conflict(self) -> None:
        tok_100 = "Z" * 100
        # Classic trap: DETECT_BLACKDUCK_API_TOKEN set without BLACKDUCK_API_TOKEN
        r_prefix = inspect_detect_token_hygiene(env={"DETECT_BLACKDUCK_API_TOKEN": tok_100})
        self.assertEqual(r_prefix["status"], "invalid")
        self.assertTrue(any("DETECT_BLACKDUCK_API_TOKEN" in i for i in r_prefix["issues"]))

        # Multi-source conflict: CLI --blackduck.api.token=empty overrides valid env token!
        r_conflict = inspect_detect_token_hygiene(
            existing_detect_args='--detect.project.name=demo --blackduck.api.token=""',
            env={"BLACKDUCK_API_TOKEN": tok_100},
        )
        self.assertEqual(r_conflict["status"], "invalid")
        self.assertEqual(r_conflict["effective_source"], "cli:--blackduck.api.token")
        self.assertEqual(r_conflict["effective_raw_length"], 0)
        self.assertTrue(r_conflict["multi_source_conflict"])

        # SPRING_APPLICATION_JSON extraction
        r_saj = inspect_detect_token_hygiene(
            env={"SPRING_APPLICATION_JSON": json.dumps({"blackduck.api.token": tok_100})}
        )
        self.assertEqual(r_saj["status"], "ok")
        self.assertEqual(r_saj["effective_source"], "env:SPRING_APPLICATION_JSON[blackduck.api.token]")
        self.assertEqual(r_saj["effective_raw_length"], 100)


if __name__ == "__main__":
    unittest.main()
