from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from shotguard import __version__
from shotguard.extract import ALLOWED_GITHUB_HOSTS
from shotguard.rules import Finding

COMMENT_MARKER = "<!-- shotguard -->"

_CONTENT_TYPE_EXT: dict[str, str] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/bmp": ".bmp",
    "image/tiff": ".tiff",
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "video/quicktime": ".mov",
}


@dataclass
class EventContext:
    repo: str
    issue_number: int
    body: str
    event_name: str


def parse_event_payload(payload: dict) -> EventContext:
    repo_info = payload.get("repository")
    if not isinstance(repo_info, dict) or not repo_info.get("full_name"):
        raise ValueError("Event payload missing repository.full_name")
    repo = str(repo_info["full_name"])

    if isinstance(payload.get("comment"), dict) and isinstance(payload.get("issue"), dict):
        issue_number = int(payload["issue"]["number"])
        body = payload["comment"].get("body") or ""
        return EventContext(
            repo=repo,
            issue_number=issue_number,
            body=str(body),
            event_name="issue_comment",
        )

    if isinstance(payload.get("pull_request"), dict):
        pr = payload["pull_request"]
        issue_number = int(pr["number"])
        body = pr.get("body") or ""
        return EventContext(
            repo=repo,
            issue_number=issue_number,
            body=str(body),
            event_name="pull_request",
        )

    if isinstance(payload.get("issue"), dict):
        issue = payload["issue"]
        issue_number = int(issue["number"])
        body = issue.get("body") or ""
        return EventContext(
            repo=repo,
            issue_number=issue_number,
            body=str(body),
            event_name="issues",
        )

    raise ValueError(
        "Unsupported GitHub event payload: expected issue, pull_request, or issue_comment"
    )


def detect_extension(content_type: str | None, header: bytes) -> str:
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if header.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return ".webp"
    if header.startswith(b"BM"):
        return ".bmp"
    if header.startswith((b"II*\x00", b"MM\x00*")):
        return ".tiff"
    if len(header) >= 12 and header[4:8] == b"ftyp":
        if header[8:12] == b"qt  ":
            return ".mov"
        return ".mp4"
    if header.startswith(b"\x1a\x45\xdf\xa3"):
        return ".webm"

    if content_type:
        mime = content_type.split(";", 1)[0].strip().lower()
        if mime in _CONTENT_TYPE_EXT:
            return _CONTENT_TYPE_EXT[mime]

    raise ValueError(
        f"Unsupported or unrecognized media format (Content-Type: {content_type or 'none'})"
    )


def _is_github_host(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    return host in ALLOWED_GITHUB_HOSTS or host.endswith(".githubusercontent.com")


def download_media(
    url: str,
    dest_dir: Path,
    token: str | None,
    max_bytes: int,
    opener=None,
) -> Path:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be > 0")

    headers = {"User-Agent": f"shotguard/{__version__}"}
    # Only attach GitHub credentials when requesting GitHub-owned hosts.
    if token and _is_github_host(url):
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    if opener is not None:
        resp_ctx = opener.open(req, timeout=30)
    else:
        resp_ctx = urllib.request.urlopen(req, timeout=30)

    with resp_ctx as resp:
        content_length = resp.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                declared = -1
            if declared > max_bytes:
                raise ValueError(
                    f"Media size {declared} bytes exceeds max_bytes limit ({max_bytes})"
                )

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(
                    f"Media download exceeded max_bytes limit ({max_bytes})"
                )
            chunks.append(chunk)

        data = b"".join(chunks)
        ext = detect_extension(resp.headers.get("Content-Type"), data[:64])

    dest_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    out_path = dest_dir / f"{digest}{ext}"
    out_path.write_bytes(data)
    return out_path


def _escape_md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def format_comment(findings: list[Finding]) -> str:
    if not findings:
        return f"{COMMENT_MARKER}\n[PASS] No secrets detected in attached media.\n"

    lines = [
        COMMENT_MARKER,
        f"[!] shotguard detected {len(findings)} potential secret(s) in attached media.",
        "",
        "| Rule | Severity | Source | Frame | Line | Match (Redacted) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for finding in findings:
        frame_str = str(finding.frame) if finding.frame is not None else "-"
        lines.append(
            "| "
            + " | ".join(
                [
                    _escape_md_cell(finding.rule_id),
                    _escape_md_cell(finding.severity),
                    _escape_md_cell(finding.source),
                    frame_str,
                    str(finding.line),
                    f"`{_escape_md_cell(finding.redacted)}`",
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "Note: Deleting or editing the attachment does not revoke leaked credentials. Rotate all exposed secrets immediately.",
        ]
    )
    return "\n".join(lines) + "\n"


def _github_request(
    method: str,
    url: str,
    token: str,
    payload: dict | None = None,
) -> dict | list:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": f"shotguard/{__version__}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"GitHub API {method} {url} failed ({exc.code}): {err_body}"
        ) from exc


def upsert_comment(
    repo: str,
    issue_number: int,
    body: str,
    token: str,
    api_base: str = "https://api.github.com",
) -> None:
    if not token:
        raise ValueError("GitHub token is required to post or update comments")

    base = api_base.rstrip("/")
    existing_id: int | None = None
    page = 1
    while True:
        list_url = (
            f"{base}/repos/{repo}/issues/{issue_number}/comments"
            f"?per_page=100&page={page}"
        )
        comments = _github_request("GET", list_url, token)
        if not isinstance(comments, list) or not comments:
            break
        for comment in comments:
            if isinstance(comment, dict) and COMMENT_MARKER in (comment.get("body") or ""):
                existing_id = int(comment["id"])
                break
        if existing_id is not None or len(comments) < 100:
            break
        page += 1

    if existing_id is not None:
        patch_url = f"{base}/repos/{repo}/issues/comments/{existing_id}"
        _github_request("PATCH", patch_url, token, {"body": body})
    else:
        post_url = f"{base}/repos/{repo}/issues/{issue_number}/comments"
        _github_request("POST", post_url, token, {"body": body})


def _sarif_level(severity: str) -> str:
    sev = severity.lower()
    if sev in {"critical", "high", "error"}:
        return "error"
    if sev in {"medium", "warning"}:
        return "warning"
    return "note"


def build_sarif(findings: list[Finding]) -> dict:
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []

    for finding in findings:
        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": {"text": finding.rule_name},
                "defaultConfiguration": {"level": _sarif_level(finding.severity)},
            }

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {
                    "text": f"{finding.rule_name} detected (redacted: {finding.redacted})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.source},
                            "region": {"startLine": max(1, finding.line)},
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "entropy": finding.entropy,
                    "frame": finding.frame,
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "shotguard",
                        "version": __version__,
                        "informationUri": "https://github.com/Hinikaa/shotguard",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
