from __future__ import annotations

import json
import math
import re
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_OCR_TRANS = str.maketrans(
    {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2013": "-",
        "\u2014": "-",
    }
)
_TOKEN_CHAR_RE = re.compile(r"^[A-Za-z0-9_./+=-]+$")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str
    min_entropy: float = 0.0
    keywords: tuple[str, ...] = ()


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    source: str
    frame: int | None
    redacted: str
    line: int
    entropy: float


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule(
        id="aws-access-key",
        name="AWS Access Key ID",
        pattern=re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        severity="high",
    ),
    Rule(
        id="github-token",
        name="GitHub Token",
        pattern=re.compile(
            r"\b((?:ghp|gho|ghs|ghu)_[A-Za-z0-9_]{32,251}|github_pat_[A-Za-z0-9_]{22,255})\b"
        ),
        severity="high",
    ),
    Rule(
        id="stripe-key",
        name="Stripe Live Key",
        pattern=re.compile(r"\b([sr]k_live_[0-9a-zA-Z]{24,99})\b"),
        severity="high",
    ),
    Rule(
        id="slack-token",
        name="Slack Token",
        pattern=re.compile(
            r"\b(xox[bpa]-[0-9A-Za-z-]{20,200}|xapp-[0-9A-Za-z-]{20,200})\b"
        ),
        severity="high",
    ),
    Rule(
        id="anthropic-key",
        name="Anthropic API Key",
        pattern=re.compile(r"\b(sk-ant-(?:api\d+-)?[A-Za-z0-9_-]{20,200})\b"),
        severity="high",
    ),
    Rule(
        id="openai-key",
        name="OpenAI API Key",
        pattern=re.compile(
            r"\b(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200})\b"
        ),
        severity="high",
    ),
    Rule(
        id="google-api-key",
        name="Google API Key",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        severity="high",
    ),
    Rule(
        id="discord-bot-token",
        name="Discord Bot Token",
        pattern=re.compile(
            r"\b([MN][A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b"
        ),
        severity="high",
    ),
    Rule(
        id="jwt",
        name="JSON Web Token",
        pattern=re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,})\b"
        ),
        severity="medium",
    ),
    Rule(
        id="pem-private-key",
        name="PEM Private Key Header",
        pattern=re.compile(r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)"),
        severity="critical",
    ),
    Rule(
        id="generic-secret",
        name="Generic High-Entropy Secret",
        pattern=re.compile(
            r"""(?i)\b(?:api_key|apikey|secret|token|password|passwd|auth_token)\b\s*[:=]\s*['"]?([A-Za-z0-9_./+=-]{16,})['"]?"""
        ),
        severity="medium",
        min_entropy=3.3,
    ),
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact_secret(s: str) -> str:
    if len(s) >= 12:
        return f"{s[:4]}...{s[-4:]}"
    return "***"


def _parse_rule_entry(entry: dict) -> Rule:
    for key in ("id", "name", "pattern"):
        if not entry.get(key) or not isinstance(entry[key], str):
            raise ValueError(f"Custom rule missing required string field '{key}'")
    severity = str(entry.get("severity", "medium")).lower()
    min_entropy = float(entry.get("min_entropy", 0.0))
    raw_keywords = entry.get("keywords", ())
    if isinstance(raw_keywords, str):
        keywords = (raw_keywords,)
    else:
        keywords = tuple(str(k) for k in raw_keywords)
    return Rule(
        id=entry["id"],
        name=entry["name"],
        pattern=re.compile(entry["pattern"]),
        severity=severity,
        min_entropy=min_entropy,
        keywords=keywords,
    )


def load_rules(extra_path: Path | None = None) -> list[Rule]:
    rules = list(BUILTIN_RULES)
    if extra_path is None:
        return rules

    raw_text = extra_path.read_text(encoding="utf-8")
    suffix = extra_path.suffix.lower()
    if suffix == ".toml":
        data = tomllib.loads(raw_text)
        entries = data.get("rules", [])
    elif suffix == ".json":
        data = json.loads(raw_text)
        entries = data if isinstance(data, list) else data.get("rules", [])
    else:
        raise ValueError(f"Unsupported rules file format: {extra_path.suffix or '<none>'}")

    if not isinstance(entries, list):
        raise ValueError("Custom rules file must contain a list of rules")

    index_by_id = {rule.id: idx for idx, rule in enumerate(rules)}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each custom rule must be an object/table")
        rule = _parse_rule_entry(entry)
        if rule.id in index_by_id:
            rules[index_by_id[rule.id]] = rule
        else:
            index_by_id[rule.id] = len(rules)
            rules.append(rule)
    return rules


def _normalize_line(line: str) -> str:
    # Normalize OCR smart quotes/dashes and collapse horizontal whitespace runs.
    return re.sub(r"[ \t]+", " ", line.translate(_OCR_TRANS)).rstrip()


def _extract_secret(match: re.Match[str]) -> str:
    if match.lastindex and match.group(1) is not None:
        return match.group(1)
    return match.group(0)


def _scan_line(
    line_text: str,
    line_no: int,
    rules: list[Rule],
    source: str,
    frame: int | None,
    seen: set[tuple[int, str]],
    matched_secrets_on_line: set[tuple[int, str]],
) -> list[Finding]:
    found: list[Finding] = []
    lower_line = line_text.lower()
    for rule in rules:
        if rule.keywords and not any(kw.lower() in lower_line for kw in rule.keywords):
            continue
        for match in rule.pattern.finditer(line_text):
            secret = _extract_secret(match)
            entropy = shannon_entropy(secret)
            if rule.min_entropy > 0.0 and entropy < rule.min_entropy:
                continue
            # Avoid duplicate generic-secret alert when a specific rule matched the same value.
            if rule.id == "generic-secret" and (line_no, secret) in matched_secrets_on_line:
                continue
            dedupe_key = (line_no, f"{rule.id}:{secret}")
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            matched_secrets_on_line.add((line_no, secret))
            found.append(
                Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    source=source,
                    frame=frame,
                    redacted=redact_secret(secret),
                    line=line_no,
                    entropy=round(entropy, 3),
                )
            )
    return found


def scan_text(
    text: str,
    rules: list[Rule],
    source: str,
    frame: int | None = None,
) -> list[Finding]:
    if not text:
        return []

    raw_lines = [_normalize_line(line) for line in text.splitlines()]
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    matched_secrets_on_line: set[tuple[int, str]] = set()

    for idx, line_text in enumerate(raw_lines, start=1):
        if not line_text.strip():
            continue
        findings.extend(
            _scan_line(
                line_text,
                idx,
                rules,
                source,
                frame,
                seen,
                matched_secrets_on_line,
            )
        )

    # Rejoin terminal/screenshot line-wrapped tokens without merging indented prose.
    for idx in range(len(raw_lines) - 1):
        cur = raw_lines[idx]
        nxt = raw_lines[idx + 1]
        if not cur or not nxt or nxt[0].isspace():
            continue
        tail_match = re.search(r"([^\s:=]+)$", cur)
        head_match = re.match(r"^([^\s:=]+)", nxt)
        if not tail_match or not head_match:
            continue
        tail = tail_match.group(1)
        head = head_match.group(1)
        if len(tail) < 12 or len(head) < 4:
            continue
        if not (_TOKEN_CHAR_RE.match(tail) and _TOKEN_CHAR_RE.match(head)):
            continue
        joined = cur + head
        line_no = idx + 1
        for finding in _scan_line(
            joined,
            line_no,
            rules,
            source,
            frame,
            seen,
            matched_secrets_on_line,
        ):
            findings.append(finding)

    return findings
