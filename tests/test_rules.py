from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from shotguard.rules import (
    BUILTIN_RULES,
    load_rules,
    redact_secret,
    scan_text,
    shannon_entropy,
)


class TestRules(unittest.TestCase):
    def test_shannon_entropy_and_redaction(self) -> None:
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertLess(shannon_entropy("aaaaaaaaaaaaaaaa"), 1.0)
        self.assertGreater(shannon_entropy("aB3dE6gH9jK2mN5pQ8rT"), 3.5)

        self.assertEqual(redact_secret("short"), "***")
        self.assertEqual(redact_secret("12345678901"), "***")
        self.assertEqual(redact_secret("123456789012"), "1234...9012")
        self.assertEqual(
            redact_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA...MPLE"
        )

    def test_builtin_rules_positive_and_negative(self) -> None:
        cases = [
            (
                "aws-access-key",
                "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE",
                "AWS_ACCESS_KEY_ID=" + "AKIA" + "12345",
            ),
            (
                "github-token",
                "token=" + "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
                "token=" + "ghp_" + "short123",
            ),
            (
                "github-token",
                "github_pat_" + "11ABCDEFG0123456789_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "github_pat_short",
            ),
            (
                "stripe-key",
                "STRIPE=" + "sk_" + "live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz",
                "STRIPE=" + "sk_" + "test_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz",
            ),
            (
                "slack-token",
                "SLACK=" + "xoxb" + "-123456789012-1234567890123-" + "aBcDeFgHiJkLmNoPqRsTuVwX",
                "SLACK=" + "xoxb" + "-short",
            ),
            (
                "openai-key",
                "OPENAI=" + "sk-" + "proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                "OPENAI=" + "sk-" + "short",
            ),
            (
                "anthropic-key",
                "ANTHROPIC=" + "sk-" + "ant-api03-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                "ANTHROPIC=" + "sk-" + "ant-short",
            ),
            (
                "google-api-key",
                ("GOOGLE=" + "AIza" + "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGt9example")[:46],
                "GOOGLE=" + "AIza" + "Short",
            ),
            (
                "discord-bot-token",
                "BOT=" + "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA1" + ".GhIjKl." + "AbCdEfGhIjKlMnOpQrStUvWxYz012345",
                "BOT=MTIz.abc.xyz",
            ),
            (
                "jwt",
                "AUTH=" + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                "AUTH=eyJshort.notjwt",
            ),
            (
                "pem-private-key",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN PUBLIC KEY-----",
            ),
            (
                "generic-secret",
                "api_key = 'aB3dE6gH9jK2mN5pQ8rT1vX4z'",
                "api_key = 'aaaaaaaaaaaaaaaaaaaa'",
            ),
        ]

        rules = list(BUILTIN_RULES)
        for rule_id, positive_text, negative_text in cases:
            with self.subTest(rule_id=rule_id):
                pos = scan_text(positive_text, rules, source="mem.png")
                self.assertTrue(
                    any(f.rule_id == rule_id for f in pos),
                    f"Expected {rule_id} to match {positive_text!r}, got {pos}",
                )
                for f in pos:
                    self.assertNotIn(positive_text.split("=")[-1].strip(" '\""), f.redacted)

                neg = scan_text(negative_text, rules, source="mem.png")
                self.assertFalse(
                    any(f.rule_id == rule_id for f in neg),
                    f"Did not expect {rule_id} to match {negative_text!r}, got {neg}",
                )

    def test_anthropic_does_not_double_match_openai(self) -> None:
        text = "key=" + "sk-" + "ant-api03-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        findings = scan_text(text, list(BUILTIN_RULES), source="test.png")
        rule_ids = [f.rule_id for f in findings]
        self.assertEqual(rule_ids, ["anthropic-key"])

    def test_ocr_line_wrap_rejoin_and_no_prose_false_positive(self) -> None:
        wrapped = (
            "GITHUB_TOKEN=" + "ghp_" + "a1B2c3D4e5F6g7H8i9J0\n"
            "k1L2m3N4o5P6q7R8s9T0\n"
            "configuration\n"
            "parameters\n"
        )
        findings = scan_text(wrapped, list(BUILTIN_RULES), source="wrap.png")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "github-token")
        self.assertEqual(findings[0].line, 1)

    def test_load_custom_rules_toml_and_json(self) -> None:
        example_toml = (
            Path(__file__).resolve().parent.parent / "rules" / "example-custom.toml"
        )
        rules = load_rules(example_toml)
        text = "token=int_svc_AbCdEfGhIjKlMnOpQrStUvWxYz01"
        findings = scan_text(text, rules, source="custom.png")
        self.assertTrue(any(f.rule_id == "internal-service-token" for f in findings))

        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "custom.json"
            json_path.write_text(
                json.dumps(
                    {
                        "rules": [
                            {
                                "id": "aws-access-key",
                                "name": "Custom Overridden AWS Rule",
                                "pattern": r"\b(CUSTOM_AWS_[A-Z0-9]{12})\b",
                                "severity": "critical",
                            },
                            {
                                "id": "keyword-gated",
                                "name": "Keyword Gated Secret",
                                "pattern": r"\b([A-Z0-9]{20})\b",
                                "severity": "low",
                                "keywords": ["deploy_pin"],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            merged = load_rules(json_path)
            overridden = [r for r in merged if r.id == "aws-access-key"][0]
            self.assertEqual(overridden.name, "Custom Overridden AWS Rule")

            no_kw = scan_text("ABCDEFGHIJ0123456789", merged, source="kw.png")
            self.assertFalse(any(f.rule_id == "keyword-gated" for f in no_kw))

            with_kw = scan_text(
                "deploy_pin ABCDEFGHIJ0123456789", merged, source="kw.png"
            )
            self.assertTrue(any(f.rule_id == "keyword-gated" for f in with_kw))


if __name__ == "__main__":
    unittest.main()
