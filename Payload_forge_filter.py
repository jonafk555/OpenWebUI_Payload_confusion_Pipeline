"""
title: Payload Forge Guardrail Filter
author: redteam-research
version: 0.1.0
required_open_webui_version: 0.3.9
description: |
  Companion filter for payload_forge manifold pipe.
  - inlet:  blocks unauthorized keywords / enforces engagement scope
  - outlet: appends fingerprint (engagement_id + artifact hash + timestamp)
            so artifacts found in the wild can be traced to a sanctioned test.
  Lab / authorized engagements only.
"""

import hashlib
import json
import os
import re
import time
from typing import Awaitable, Callable, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Default deny-list. These are words that must NOT appear in spec for this
# filter to pass. The intent is to keep authorized scope explicit:
# users running the pipe in a sanctioned engagement should not be referencing
# production targets, named real persons, or out-of-scope networks.
# ---------------------------------------------------------------------------
DEFAULT_DENY_PATTERNS = [
    # production / out-of-scope hosts (lab should overwrite via Valves)
    r"\bprod[\-_.]",
    r"\.gov\b",
    r"\.mil\b",
    # placeholder for "real person targeting" guard (engagement-specific)
    r"\bssn\b",
    r"\bpassport\b",
]


def _hash_artifact(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _last_user_message(messages: list[dict]) -> str:
    for m in reversed(messages or []):
        if m.get("role") == "user":
            c = m.get("content", "")
            if isinstance(c, list):
                return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
            return str(c)
    return ""


def _last_assistant_message_idx(messages: list[dict]) -> int:
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "assistant":
            return i
    return -1


class Filter:
    class Valves(BaseModel):
        ENABLED: bool = Field(
            default=True,
            description="Master switch for the guardrail filter.",
        )
        TARGET_PIPE_IDS: str = Field(
            default="payload_forge",
            description="Comma-separated pipe ids this filter applies to. Empty = all.",
        )
        EXTRA_DENY_PATTERNS: str = Field(
            default="",
            description=(
                "Newline-separated regex patterns ADDED to the default deny-list. "
                "Use this to encode engagement scope (out-of-scope hostnames, "
                "named individuals, domains, etc.)."
            ),
        )
        ALLOW_LIST_OVERRIDE: str = Field(
            default="",
            description=(
                "Newline-separated regex patterns to subtract from the deny-list. "
                "Use sparingly; engagement scope changes should be documented."
            ),
        )
        ENGAGEMENT_ID: str = Field(
            default="ENG-UNSET",
            description="Engagement / Statement-of-Work identifier embedded in fingerprint.",
        )
        FINGERPRINT_FORMAT: str = Field(
            default="comment",
            description=(
                "How to embed fingerprint in artifact: "
                "'comment' (language-aware comment line), "
                "'header' (markdown header above the code block), "
                "'none' (do not embed; only log)."
            ),
        )
        FINGERPRINT_LOG_PATH: str = Field(
            default="/tmp/payload_forge_fingerprints.log",
            description="Append-only log of every fingerprint emitted.",
        )

    def __init__(self) -> None:
        self.valves = self.Valves()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _applies_to(self, body: dict) -> bool:
        targets = [t.strip() for t in self.valves.TARGET_PIPE_IDS.split(",") if t.strip()]
        if not targets:
            return True
        model = body.get("model", "")
        # body["model"] for manifold looks like "payload_forge.shellcode"
        root = model.split(".", 1)[0]
        return root in targets

    def _compiled_deny(self) -> list[re.Pattern]:
        patterns = list(DEFAULT_DENY_PATTERNS)
        for line in self.valves.EXTRA_DENY_PATTERNS.splitlines():
            line = line.strip()
            if line:
                patterns.append(line)
        allow = [
            line.strip()
            for line in self.valves.ALLOW_LIST_OVERRIDE.splitlines()
            if line.strip()
        ]
        kept = [p for p in patterns if p not in allow]
        return [re.compile(p, re.IGNORECASE) for p in kept]

    def _scan(self, text: str) -> list[str]:
        """Return list of matched deny-pattern strings (empty = clean)."""
        return [
            pat.pattern
            for pat in self._compiled_deny()
            if pat.search(text)
        ]

    def _fingerprint(self, artifact_text: str) -> dict:
        return {
            "engagement_id": self.valves.ENGAGEMENT_ID,
            "artifact_sha256_16": _hash_artifact(artifact_text),
            "ts_utc": int(time.time()),
        }

    def _log_fingerprint(self, fp: dict, model: str, user: Optional[dict]) -> None:
        try:
            with open(self.valves.FINGERPRINT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    **fp,
                    "model": model,
                    "user": (user or {}).get("email", "anonymous"),
                }) + "\n")
        except OSError:
            pass

    @staticmethod
    def _comment_for_lang(lang: str, line: str) -> str:
        if lang in {"c", "cpp", "rust", "go", "java", "javascript", "typescript"}:
            return f"// {line}"
        if lang in {"python", "powershell", "ruby", "shell", "bash"}:
            return f"# {line}"
        if lang in {"sql"}:
            return f"-- {line}"
        return f"# {line}"

    # ------------------------------------------------------------------
    # Open WebUI hooks
    # ------------------------------------------------------------------

    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
    ) -> dict:
        if not self.valves.ENABLED or not self._applies_to(body):
            return body

        user_msg = _last_user_message(body.get("messages", []))
        hits = self._scan(user_msg)
        if hits:
            blocked = (
                "❌ Guardrail filter blocked this request.\n\n"
                f"Matched deny-patterns: `{hits}`\n\n"
                "If this is in scope for the current engagement, update "
                "`EXTRA_DENY_PATTERNS` / `ALLOW_LIST_OVERRIDE` valves and retry."
            )
            # Replace user message so the pipe sees the block notice and refuses.
            # The pipe's spec parser will fail to find a real cmd and return safely.
            body.setdefault("messages", []).append({
                "role": "system",
                "content": f"[GUARDRAIL_BLOCK] {hits}",
            })
            # Most reliable: rewrite last user message to a refusal sentinel.
            for m in reversed(body["messages"]):
                if m.get("role") == "user":
                    m["content"] = blocked
                    break
        return body

    async def outlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
    ) -> dict:
        if not self.valves.ENABLED or not self._applies_to(body):
            return body
        if self.valves.FINGERPRINT_FORMAT == "none":
            return body

        messages = body.get("messages", [])
        idx = _last_assistant_message_idx(messages)
        if idx < 0:
            return body

        content = messages[idx].get("content", "")
        if not isinstance(content, str) or not content.strip():
            return body

        # Find the fenced code block(s); fingerprint only the first one.
        m = re.search(r"```([a-zA-Z0-9_+\-]*)\n(.*?)```", content, re.S)
        if not m:
            # No code block — just append a header fingerprint
            fp = self._fingerprint(content)
            self._log_fingerprint(fp, body.get("model", ""), __user__)
            tag = (
                f"\n\n> 🔖 fingerprint `{fp['engagement_id']}` "
                f"sha256/16=`{fp['artifact_sha256_16']}` ts=`{fp['ts_utc']}`"
            )
            messages[idx]["content"] = content + tag
            return body

        lang = m.group(1).lower() or "text"
        artifact = m.group(2)
        fp = self._fingerprint(artifact)
        self._log_fingerprint(fp, body.get("model", ""), __user__)

        if self.valves.FINGERPRINT_FORMAT == "header":
            tag = (
                f"\n\n> 🔖 **fingerprint** `engagement={fp['engagement_id']}` "
                f"`sha256/16={fp['artifact_sha256_16']}` `ts={fp['ts_utc']}`\n"
            )
            messages[idx]["content"] = content[: m.start()] + tag + content[m.start():]
            return body

        # Default: language-aware comment injected as first line of the code
        comment_line = self._comment_for_lang(
            lang,
            f"FORGE-FP engagement={fp['engagement_id']} "
            f"sha={fp['artifact_sha256_16']} ts={fp['ts_utc']}",
        )
        new_artifact = comment_line + "\n" + artifact
        new_block = f"```{m.group(1)}\n{new_artifact}```"
        messages[idx]["content"] = content[: m.start()] + new_block + content[m.end():]
        return body
