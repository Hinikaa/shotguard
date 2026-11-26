from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from shotguard.cli import main as cli_main

from shotguard.github import (
    COMMENT_MARKER,
    build_sarif,
    detect_extension,
    download_media,
    format_comment,
    parse_event_payload,
    upsert_comment,
)
from shotguard.rules import Finding

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


class _MockState:
    def __init__(self) -> None:
        self.comments: list[dict] = []
        self.last_auth: str | None = None
        self.patch_calls: int = 0
        self.post_calls: int = 0


def _make_handler(state: _MockState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def do_GET(self) -> None:
            state.last_auth = self.headers.get("Authorization")
            if self.path.startswith("/assets/no-ext-png"):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(PNG_BYTES)))
                self.end_headers()
                self.wfile.write(PNG_BYTES)
                return

            if self.path.startswith("/assets/too-big"):
                payload = b"X" * 2048
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            if self.path.startswith("/repos/org/repo/issues/42/comments"):
                body = json.dumps(state.comments).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            data = json.loads(raw)
            state.post_calls += 1
            new_comment = {"id": 100 + len(state.comments), "body": data["body"]}
            state.comments.append(new_comment)
            resp = json.dumps(new_comment).encode("utf-8")
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_PATCH(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            data = json.loads(raw)
            state.patch_calls += 1
            comment_id = int(self.path.rsplit("/", 1)[-1])
            for comment in state.comments:
                if comment["id"] == comment_id:
                    comment["body"] = data["body"]
                    resp = json.dumps(comment).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp)))
                    self.end_headers()
                    self.wfile.write(resp)
                    return
            self.send_response(404)
            self.end_headers()

    return Handler


class TestGitHub(unittest.TestCase):
    def test_parse_event_payload_variants(self) -> None:
        issue_ctx = parse_event_payload(
            {
                "repository": {"full_name": "org/repo"},
                "issue": {"number": 7, "body": "issue body"},
            }
        )
        self.assertEqual(issue_ctx.event_name, "issues")
        self.assertEqual(issue_ctx.issue_number, 7)
        self.assertEqual(issue_ctx.body, "issue body")

        pr_ctx = parse_event_payload(
            {
                "repository": {"full_name": "org/repo"},
                "pull_request": {"number": 12, "body": "pr body"},
            }
        )
        self.assertEqual(pr_ctx.event_name, "pull_request")
        self.assertEqual(pr_ctx.issue_number, 12)
        self.assertEqual(pr_ctx.body, "pr body")

        comment_ctx = parse_event_payload(
            {
                "repository": {"full_name": "org/repo"},
                "issue": {"number": 99, "body": "parent"},
                "comment": {"body": "comment body"},
            }
        )
        self.assertEqual(comment_ctx.event_name, "issue_comment")
        self.assertEqual(comment_ctx.issue_number, 99)
        self.assertEqual(comment_ctx.body, "comment body")

    def test_detect_extension_magic_bytes(self) -> None:
        self.assertEqual(detect_extension(None, b"\x89PNG\r\n\x1a\n1234"), ".png")
        self.assertEqual(detect_extension(None, b"\xff\xd8\xff\xe0"), ".jpg")
        self.assertEqual(detect_extension(None, b"GIF89a......"), ".gif")
        self.assertEqual(detect_extension(None, b"RIFF1234WEBP"), ".webp")
        self.assertEqual(detect_extension(None, b"\x00\x00\x00\x18ftypisom"), ".mp4")
        self.assertEqual(detect_extension(None, b"\x1a\x45\xdf\xa3\x9f"), ".webm")
        self.assertEqual(detect_extension("image/png; charset=utf-8", b"unknown"), ".png")

    def test_download_upsert_comment_and_sarif(self) -> None:
        state = _MockState()
        server = HTTPServer(("127.0.0.1", 0), _make_handler(state))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with tempfile.TemporaryDirectory() as tmp:
                path = download_media(
                    f"{base}/assets/no-ext-png",
                    dest_dir=Path(tmp),
                    token="secret-token",
                    max_bytes=1024,
                )
                self.assertEqual(path.suffix, ".png")
                self.assertEqual(path.read_bytes(), PNG_BYTES)
                self.assertIsNone(state.last_auth)

                with self.assertRaises(ValueError):
                    download_media(
                        f"{base}/assets/too-big",
                        dest_dir=Path(tmp),
                        token=None,
                        max_bytes=512,
                    )

            findings = [
                Finding(
                    rule_id="aws-access-key",
                    rule_name="AWS Access Key ID",
                    severity="high",
                    source="https://github.com/user-attachments/assets/abc",
                    frame=None,
                    redacted="AKIA...MPLE",
                    line=1,
                    entropy=3.8,
                )
            ]
            body = format_comment(findings)
            self.assertTrue(body.startswith(COMMENT_MARKER))
            self.assertIn("AKIA...MPLE", body)
            self.assertIn("does not revoke leaked credentials", body)

            upsert_comment("org/repo", 42, body, token="ghs_tok", api_base=base)
            self.assertEqual(state.post_calls, 1)
            self.assertEqual(state.patch_calls, 0)

            updated = body + "\nUpdated\n"
            upsert_comment("org/repo", 42, updated, token="ghs_tok", api_base=base)
            self.assertEqual(state.post_calls, 1)
            self.assertEqual(state.patch_calls, 1)
            self.assertEqual(len(state.comments), 1)

            sarif = build_sarif(findings)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"]), 1)
            results = sarif["runs"][0]["results"]
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["ruleId"], "aws-access-key")
            self.assertEqual(results[0]["level"], "error")
            self.assertIn("AKIA...MPLE", results[0]["message"]["text"])
        finally:
            server.shutdown()
            server.server_close()

    def test_cli_event_writes_sarif_json_and_comments(self) -> None:
        state = _MockState()
        server = HTTPServer(("127.0.0.1", 0), _make_handler(state))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with tempfile.TemporaryDirectory() as tmp:
                tmp_dir = Path(tmp)
                event_path = tmp_dir / "event.json"
                sarif_path = tmp_dir / "out.sarif"
                json_path = tmp_dir / "report.json"
                dummy_png = tmp_dir / "shot.png"
                dummy_png.write_bytes(PNG_BYTES)

                event_path.write_text(
                    json.dumps(
                        {
                            "repository": {"full_name": "org/repo"},
                            "pull_request": {
                                "number": 42,
                                "body": (
                                    "![leak](https://github.com/user-attachments/assets/11111111-2222-3333-4444-555555555555)\n"
                                    "![blocked](http://127.0.0.1/bad.png)\n"
                                ),
                            },
                        }
                    ),
                    encoding="utf-8",
                )

                fake_finding = Finding(
                    rule_id="aws-access-key",
                    rule_name="AWS Access Key ID",
                    severity="high",
                    source="local",
                    frame=None,
                    redacted="AKIA...MPLE",
                    line=1,
                    entropy=3.8,
                )

                with (
                    patch("shotguard.cli.download_media", return_value=dummy_png),
                    patch("shotguard.cli.scan_media_file", return_value=[fake_finding]),
                ):
                    rc = cli_main(
                        [
                            "event",
                            str(event_path),
                            "--comment",
                            "--no-fail-on-finding",
                            "--token",
                            "ghs_test",
                            "--api-base",
                            base,
                            "--sarif",
                            str(sarif_path),
                            "--output-json",
                            str(json_path),
                        ]
                    )

                self.assertEqual(rc, 0)
                self.assertEqual(state.post_calls, 1)
                sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
                self.assertEqual(sarif_data["version"], "2.1.0")
                self.assertEqual(len(sarif_data["runs"][0]["results"]), 1)

                json_data = json.loads(json_path.read_text(encoding="utf-8"))
                self.assertEqual(json_data["findings_count"], 1)
                self.assertEqual(
                    json_data["urls_scanned"],
                    ["https://github.com/user-attachments/assets/11111111-2222-3333-4444-555555555555"],
                )
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
