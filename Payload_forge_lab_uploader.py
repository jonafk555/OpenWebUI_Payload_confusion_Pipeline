"""
payload_forge_lab_uploader.py

Helper module for uploading generated artifacts to AUTHORIZED LAB infra
(your own internal HTTP listener / SMB share, on a closed network).

This module is import-only — not a standalone Open WebUI function.
The pipe imports `upload_artifact()` and calls it after generation.

DESIGN PRINCIPLES:
- Allow-listed targets only. Refuses to upload to anything not in valves.
- No outbound traffic to the public internet by default.
- Returns metadata (URL, hash) for the pipe to surface via __event_emitter__.
- Graceful failure — if listener is down, pipe still returns the artifact
  inline; lab integration is opt-in convenience, not a hard dependency.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional


@dataclass
class UploadResult:
    ok: bool
    url: Optional[str]
    sha256: str
    size: int
    error: Optional[str] = None


# RFC1918 + loopback + link-local. Outside this set, we refuse to upload.
def _is_private_host(host: str) -> bool:
    try:
        # Resolve host first; some lab listeners use mDNS / hosts entries
        addr = socket.gethostbyname(host)
        ip = ipaddress.ip_address(addr)
    except (socket.gaierror, ValueError):
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
    )


def upload_artifact(
    artifact: str,
    *,
    listener_url: str,
    allowed_hosts: list[str],
    engagement_id: str,
    timeout_sec: float = 5.0,
    auth_token: Optional[str] = None,
) -> UploadResult:
    """
    Upload `artifact` to a lab listener via HTTP POST.

    Refuses if:
    - listener host is not RFC1918 / loopback / link-local
    - listener host is not in `allowed_hosts`
    - URL scheme is not http/https
    """
    digest = hashlib.sha256(artifact.encode("utf-8", errors="replace")).hexdigest()
    size = len(artifact.encode("utf-8", errors="replace"))

    parsed = urllib.parse.urlparse(listener_url)
    if parsed.scheme not in ("http", "https"):
        return UploadResult(False, None, digest, size,
                            f"scheme not allowed: {parsed.scheme}")
    host = parsed.hostname or ""
    if host not in [h.strip() for h in allowed_hosts if h.strip()]:
        return UploadResult(False, None, digest, size,
                            f"host {host!r} not in allow-list")
    if not _is_private_host(host):
        return UploadResult(False, None, digest, size,
                            f"host {host!r} resolves outside private ranges")

    body = artifact.encode("utf-8", errors="replace")
    req = urllib.request.Request(
        listener_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Engagement-Id": engagement_id,
            "X-Artifact-SHA256": digest,
            **({"Authorization": f"Bearer {auth_token}"} if auth_token else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            location = resp.headers.get("Location") or listener_url
            return UploadResult(True, location, digest, size)
    except Exception as e:  # network / timeout / HTTP error
        return UploadResult(False, None, digest, size, repr(e))
