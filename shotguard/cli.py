from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import tomllib
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from shotguard import __version__
from shotguard.extract import extract_media_urls, is_allowed_url
from shotguard.github import (
    build_sarif,
    download_media,
    format_comment,
    parse_event_payload,
    upsert_comment,
)
from shotguard.ocr import IMAGE_EXTENSIONS, VIDEO_EXTENSIONS, scan_media_file
from shotguard.rules import Finding, load_rules


def _collect_scan_files(paths: list[str], scan_video: bool) -> list[Path]:
    allowed_dir_exts = set(IMAGE_EXTENSIONS)
    if scan_video:
        allowed_dir_exts |= VIDEO_EXTENSIONS

    collected: list[Path] = []
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            raise FileNotFoundError(f"Path not found: {path}")
        if path.is_file():
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                collected.append(path)
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in allowed_dir_exts:
                    resolved = child.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        collected.append(child)
        else:
            raise ValueError(f"Unsupported path type: {path}")
    return collected


def _format_text_findings(findings: list[Finding]) -> str:
    if not findings:
        return "PASS: 0 findings detected."
    lines = [f"[!] {len(findings)} finding(s) detected:"]
    for f in findings:
        frame_part = f" frame={f.frame}" if f.frame is not None else ""
        lines.append(
            f"  FAIL [{f.severity}] {f.rule_id} source={f.source}{frame_part} "
            f"line={f.line} match={f.redacted} entropy={f.entropy}"
        )
    return "\n".join(lines)


def _findings_json_payload(findings: list[Finding], extra: dict | None = None) -> dict:
    payload: dict = {
        "version": __version__,
        "findings_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    if extra:
        payload.update(extra)
    return payload


def _run_scan(args: argparse.Namespace) -> int:
    rules = load_rules(Path(args.rules) if args.rules else None)
    files = _collect_scan_files(args.paths, scan_video=args.scan_video)

    findings: list[Finding] = []
    for file_path in files:
        findings.extend(
            scan_media_file(
                file_path,
                rules=rules,
                max_frames=args.max_frames,
                lang=args.lang,
            )
        )

    if args.format == "text":
        print(_format_text_findings(findings))
    elif args.format == "json":
        print(
            json.dumps(
                _findings_json_payload(findings, {"files_scanned": len(files)}),
                indent=2,
            )
        )
    elif args.format == "sarif":
        print(json.dumps(build_sarif(findings), indent=2))

    return 1 if findings else 0


def _run_event(args: argparse.Namespace) -> int:
    event_path = Path(args.event_json)
    if not event_path.is_file():
        raise FileNotFoundError(f"Event JSON file not found: {event_path}")

    payload = json.loads(event_path.read_text(encoding="utf-8"))
    ctx = parse_event_payload(payload)
    rules = load_rules(Path(args.rules) if args.rules else None)
    token = args.token if args.token is not None else os.environ.get("GITHUB_TOKEN")

    all_urls = extract_media_urls(ctx.body)
    allowed_urls: list[str] = []
    for url in all_urls:
        if is_allowed_url(url, allow_any_host=args.allow_any_host):
            allowed_urls.append(url)
        else:
            print(f"WARN: skipped disallowed URL: {url}", file=sys.stderr)

    findings: list[Finding] = []
    scanned_urls: list[str] = []
    with tempfile.TemporaryDirectory(prefix="shotguard_dl_") as tmp_dir:
        dl_dir = Path(tmp_dir)
        for url in allowed_urls:
            media_path = download_media(
                url,
                dest_dir=dl_dir,
                token=token,
                max_bytes=args.max_bytes,
            )
            if media_path.suffix.lower() in VIDEO_EXTENSIONS and not args.scan_video:
                print(
                    f"WARN: skipped animated/video attachment (enable --scan-video): {url}",
                    file=sys.stderr,
                )
                continue
            scanned_urls.append(url)
            url_findings = scan_media_file(
                media_path,
                rules=rules,
                max_frames=args.max_frames,
                lang=args.lang,
            )
            for finding in url_findings:
                finding.source = url
            findings.extend(url_findings)

    if args.sarif:
        sarif_path = Path(args.sarif)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(
            json.dumps(build_sarif(findings), indent=2) + "\n",
            encoding="utf-8",
        )

    if args.output_json:
        json_path = Path(args.output_json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        report = _findings_json_payload(
            findings,
            {
                "event": {
                    "repo": ctx.repo,
                    "issue_number": ctx.issue_number,
                    "event_name": ctx.event_name,
                },
                "urls_scanned": scanned_urls,
            },
        )
        json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(_format_text_findings(findings))

    if args.comment and findings:
        if not token:
            raise ValueError("--comment requires --token or GITHUB_TOKEN")
        comment_body = format_comment(findings)
        upsert_comment(
            repo=ctx.repo,
            issue_number=ctx.issue_number,
            body=comment_body,
            token=token,
            api_base=args.api_base,
        )

    if findings and args.fail_on_finding:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shotguard",
        description="OCR secret scanner for images and video attachments.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan local images, directories, or videos.",
    )
    scan_parser.add_argument(
        "paths",
        nargs="+",
        help="Image/video file paths or directories to scan.",
    )
    scan_parser.add_argument(
        "--rules",
        default=None,
        help="Path to custom JSON or TOML rules file.",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Output format (default: text).",
    )
    scan_parser.add_argument(
        "--max-frames",
        type=int,
        default=10,
        help="Maximum frames sampled from GIF/video files (default: 10).",
    )
    scan_parser.add_argument(
        "--lang",
        default="eng",
        help="Tesseract language code (default: eng).",
    )
    scan_parser.add_argument(
        "--scan-video",
        action="store_true",
        help="Include GIF/video files when scanning directories.",
    )

    event_parser = subparsers.add_parser(
        "event",
        help="Scan media attachments referenced in a GitHub event JSON file.",
    )
    event_parser.add_argument(
        "event_json",
        help="Path to GitHub Actions event JSON payload.",
    )
    event_parser.add_argument(
        "--rules",
        default=None,
        help="Path to custom JSON or TOML rules file.",
    )
    event_parser.add_argument(
        "--comment",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Post or update a redacted summary comment when findings exist.",
    )
    event_parser.add_argument(
        "--fail-on-finding",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Exit with code 1 when findings are detected (default: true).",
    )
    event_parser.add_argument(
        "--allow-any-host",
        action="store_true",
        default=False,
        help="Allow HTTPS media URLs outside GitHub asset hosts.",
    )
    event_parser.add_argument(
        "--max-frames",
        type=int,
        default=10,
        help="Maximum frames sampled per GIF/video attachment (default: 10).",
    )
    event_parser.add_argument(
        "--max-bytes",
        type=int,
        default=15728640,
        help="Maximum download size per attachment in bytes (default: 15728640).",
    )
    event_parser.add_argument(
        "--lang",
        default="eng",
        help="Tesseract language code (default: eng).",
    )
    event_parser.add_argument(
        "--scan-video",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Scan GIF/video attachments using ffmpeg.",
    )
    event_parser.add_argument(
        "--sarif",
        default=None,
        help="Write SARIF 2.1.0 output to this file path.",
    )
    event_parser.add_argument(
        "--output-json",
        default=None,
        help="Write redacted JSON report to this file path.",
    )
    event_parser.add_argument(
        "--token",
        default=None,
        help="GitHub token (defaults to GITHUB_TOKEN environment variable).",
    )
    event_parser.add_argument(
        "--api-base",
        default="https://api.github.com",
        help="GitHub REST API base URL.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "event":
            return _run_event(args)
        parser.print_help(sys.stderr)
        return 2
    except (
        OSError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
