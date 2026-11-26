from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

ALLOWED_GITHUB_HOSTS: frozenset[str] = frozenset(
    {
        "github.com",
        "user-images.githubusercontent.com",
        "raw.githubusercontent.com",
        "private-user-images.githubusercontent.com",
        "objects.githubusercontent.com",
    }
)

_MARKDOWN_IMAGE_RE = re.compile(
    r"!\[[^\]]*\]\(\s*<?([^\s<>()]+)>?(?:\s+[\"'][^\"']*[\"'])?\s*\)"
)
_HTML_MEDIA_RE = re.compile(
    r"""<(?:img|video|source)\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""",
    re.IGNORECASE,
)
_BARE_GITHUB_ASSET_RE = re.compile(
    r"""https?://(?:github\.com/user-attachments/assets/[A-Za-z0-9-]+|(?:private-)?user-images\.githubusercontent\.com/[^\s<>"')]+)""",
    re.IGNORECASE,
)


def _clean_url(raw: str) -> str:
    url = raw.strip()
    while url.endswith((".", ",", ";")) and not url.endswith(".."):
        url = url[:-1]
    return url


def extract_media_urls(markdown: str) -> list[str]:
    if not markdown:
        return []

    matches: list[tuple[int, str]] = []
    for match in _MARKDOWN_IMAGE_RE.finditer(markdown):
        url = _clean_url(match.group(1))
        if url:
            matches.append((match.start(), url))

    for match in _HTML_MEDIA_RE.finditer(markdown):
        raw_url = match.group(1) or match.group(2) or match.group(3) or ""
        url = _clean_url(raw_url)
        if url:
            matches.append((match.start(), url))

    for match in _BARE_GITHUB_ASSET_RE.finditer(markdown):
        url = _clean_url(match.group(0))
        if url:
            matches.append((match.start(), url))

    matches.sort(key=lambda item: item[0])

    seen: set[str] = set()
    ordered: list[str] = []
    for _, url in matches:
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    return ordered


def is_allowed_url(url: str, allow_any_host: bool = False) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    if parsed.scheme.lower() != "https":
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    host = hostname.lower().rstrip(".")
    if (
        host == "localhost"
        or host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
    ):
        return False

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    if not allow_any_host:
        return host in ALLOWED_GITHUB_HOSTS

    return True
