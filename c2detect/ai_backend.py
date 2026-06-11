"""Cognis shared AI backend — pluggable, opt-in LLM layer for all Cognis scanners.

This is the *canonical* AI backend that every Cognis scanner/tool copies in.
It is **OFF BY DEFAULT** so scanners stay deterministic and reproducible: with no
configuration, ``is_enabled()`` is ``False`` and ``analyze_code(...)`` returns ``[]``.

Enable it by pointing at one of the user's LOCAL fleet repos, which expose
OpenAI-compatible llama.cpp / Ollama endpoints (nothing leaves the box):

  * ``uncensored-fleet`` — local multi-model fleet. The abliterated *commander*
    slot serves on ``http://127.0.0.1:8774/v1`` (model ``Josiefied-Qwen3-8B-abliterated``).
    See _extra/uncensored-fleet/README.md (slot table: reasoning 8771, math 8772,
    coding 8773, uncensored/commander 8774, vision 8775).
  * ``cognis-code`` — local uncensored coding suite. ``cognis-code serve`` exposes an
    OpenAI-compatible endpoint at ``http://127.0.0.1:11434/v1`` (model ``coder``).
    See _extra/cognis-code/README.md.

Configuration precedence (highest first):
    1. explicit constructor / function arguments
    2. environment variables:
         COGNIS_AI_BACKEND   — preset name ("uncensored-fleet" | "cognis-code")
         COGNIS_AI_ENDPOINT  — full base URL override (e.g. http://127.0.0.1:8774/v1)
         COGNIS_AI_MODEL     — model name override
         COGNIS_AI_KEY       — API key (llama.cpp/Ollama ignore it; sent if set)
    3. preset defaults (only applied once a backend is *named*)

Design contract: this module is stdlib-only (urllib, json, os, re) and
``analyze_code`` NEVER raises — any error, timeout, disablement, or malformed
response yields an empty list so the calling scanner degrades gracefully to its
deterministic signature-based findings.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

# --------------------------------------------------------------------------- #
# Presets — derived from the fleet READMEs (ports are authoritative).
# --------------------------------------------------------------------------- #
PRESETS = {
    # uncensored-fleet: abliterated "commander" slot, OpenAI-compatible llama.cpp.
    "uncensored-fleet": {
        "base_url": "http://127.0.0.1:8774/v1",
        "default_model": "Josiefied-Qwen3-8B-abliterated",
        "port": 8774,
    },
    # cognis-code: `cognis-code serve` → OpenAI-compatible endpoint at :11434/v1.
    "cognis-code": {
        "base_url": "http://127.0.0.1:11434/v1",
        "default_model": "coder",
        "port": 11434,
    },
}

DEFAULT_TIMEOUT = 60          # seconds for the chat/completions call
HEALTH_TIMEOUT = 3            # seconds for the health probe

SYSTEM_PROMPT = (
    "You are a senior application-security analyst performing a rigorous code review. "
    "Hunt for real, exploitable vulnerabilities. Go BEYOND known signatures and CWE "
    "pattern-matching: actively reason about NOVEL logic flaws, broken invariants, "
    "trust-boundary mistakes, auth/authz gaps, race conditions, insecure defaults, and "
    "business-logic abuse that a naive linter would miss. Only report issues you can "
    "justify from the code itself; do not invent problems. "
    "Respond with a STRICT JSON array (and nothing else) of finding objects, each with "
    "exactly these keys: "
    '"title" (string), "severity" (one of "critical","high","medium","low","info"), '
    '"cwe" (string like "CWE-89" or "" if none), "line" (integer line number or 0 if '
    'unknown), "evidence" (the relevant code snippet/string), "why" (concise impact + '
    'exploit reasoning), "confidence" (float 0..1), "novel" (boolean — true if this is a '
    "logic/business flaw beyond a standard signature). "
    "If there are no findings, return []."
)


class CognisAIBackend:
    """Opt-in OpenAI-compatible LLM client for security code analysis.

    Off by default: an instance is only *enabled* when a backend has been
    explicitly named via argument or the COGNIS_AI_* environment variables.
    """

    def __init__(self, backend=None, endpoint=None, model=None, api_key=None, timeout=None):
        # ---- resolve backend / preset name -----------------------------------
        self.backend = backend or os.environ.get("COGNIS_AI_BACKEND") or None
        preset = PRESETS.get(self.backend, {}) if self.backend else {}

        # ---- resolve endpoint (base_url) -------------------------------------
        self.base_url = (
            endpoint
            or os.environ.get("COGNIS_AI_ENDPOINT")
            or preset.get("base_url")
            or None
        )
        if self.base_url:
            self.base_url = self.base_url.rstrip("/")

        # ---- resolve model ---------------------------------------------------
        self.model = (
            model
            or os.environ.get("COGNIS_AI_MODEL")
            or preset.get("default_model")
            or None
        )

        # ---- resolve api key (optional; llama.cpp/Ollama ignore it) ----------
        self.api_key = api_key or os.environ.get("COGNIS_AI_KEY") or None

        self.timeout = timeout if timeout is not None else DEFAULT_TIMEOUT

    # ------------------------------------------------------------------ #
    # State
    # ------------------------------------------------------------------ #
    def is_enabled(self):
        """True only when a backend endpoint has been explicitly configured.

        Requires a usable base_url AND that the user opted in either by naming a
        preset (COGNIS_AI_BACKEND / arg) or by supplying an explicit endpoint
        (COGNIS_AI_ENDPOINT / arg). Bare preset defaults never auto-enable.
        """
        return bool(self.base_url and self.model)

    def health(self):
        """Quick liveness probe. Returns True only if the endpoint answers fast.

        Tries GET /v1/models then GET /health. Never raises.
        """
        if not self.is_enabled():
            return False
        # base_url already ends in /v1 for presets; derive the server root too.
        root = self.base_url[:-3].rstrip("/") if self.base_url.endswith("/v1") else self.base_url
        candidates = [
            self.base_url + "/models",
            root + "/health",
            root + "/v1/models",
        ]
        for url in candidates:
            try:
                req = urllib.request.Request(url, method="GET")
                if self.api_key:
                    req.add_header("Authorization", "Bearer " + self.api_key)
                with urllib.request.urlopen(req, timeout=HEALTH_TIMEOUT) as resp:
                    if 200 <= getattr(resp, "status", resp.getcode()) < 300:
                        return True
            except Exception:
                continue
        return False

    # ------------------------------------------------------------------ #
    # Core analysis
    # ------------------------------------------------------------------ #
    def analyze_code(self, code, context=None, focus=None):
        """Run an LLM security review over ``code``. Returns list[dict] of findings.

        NEVER raises: on disabled backend, network error, timeout, or unparseable
        response it returns ``[]`` so the scanner falls back to deterministic rules.
        """
        if not self.is_enabled():
            return []
        if not code or not str(code).strip():
            return []

        user_prompt = self._build_user_prompt(code, context=context, focus=focus)
        try:
            content = self._chat(SYSTEM_PROMPT, user_prompt)
        except Exception:
            return []
        if not content:
            return []

        findings = self._parse_findings(content)
        return findings

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_user_prompt(code, context=None, focus=None):
        parts = []
        if context:
            parts.append("CONTEXT:\n" + str(context).strip())
        if focus:
            parts.append("FOCUS — pay special attention to:\n" + str(focus).strip())
        parts.append(
            "Review the following code and return the JSON array of findings as instructed."
        )
        parts.append("```\n" + str(code) + "\n```")
        return "\n\n".join(parts)

    def _chat(self, system_prompt, user_prompt):
        """POST to /chat/completions and return the assistant message content."""
        url = self.base_url + "/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        obj = json.loads(raw)
        choices = obj.get("choices") or []
        if not choices:
            return ""
        msg = choices[0].get("message") or {}
        return msg.get("content") or ""

    @staticmethod
    def _strip_think(text):
        """Remove <think>...</think> reasoning blocks (R1/Qwen-style)."""
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
        # Tolerate an unterminated opening <think> tag.
        text = re.sub(r"<think>.*$", "", text, flags=re.DOTALL | re.IGNORECASE)
        return text.strip()

    @classmethod
    def _extract_json_array(cls, text):
        """Pull a JSON array out of raw model text, tolerating code fences/prose."""
        text = cls._strip_think(text)

        # 1) Fenced ```json ... ``` or ``` ... ``` blocks.
        fence = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
        if fence:
            candidate = fence.group(1).strip()
            arr = cls._first_array(candidate)
            if arr is not None:
                return arr

        # 2) Whole-string array.
        arr = cls._first_array(text)
        return arr

    @staticmethod
    def _first_array(text):
        """Return the first balanced top-level [...] substring, or None."""
        start = text.find("[")
        if start == -1:
            return None
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        return None

    @classmethod
    def _parse_findings(cls, content):
        """Parse model output into a normalized list of finding dicts. Never raises."""
        try:
            blob = cls._extract_json_array(content)
            if not blob:
                return []
            parsed = json.loads(blob)
        except Exception:
            return []
        if not isinstance(parsed, list):
            return []

        out = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            out.append(cls._normalize_finding(item))
        return out

    @staticmethod
    def _normalize_finding(item):
        def _s(v):
            return "" if v is None else str(v)

        # line -> int
        line = item.get("line", 0)
        try:
            line = int(line)
        except (TypeError, ValueError):
            line = 0

        # confidence -> float in [0,1]
        conf = item.get("confidence", 0.0)
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = 0.0
        if conf < 0.0:
            conf = 0.0
        elif conf > 1.0:
            conf = 1.0

        sev = _s(item.get("severity")).strip().lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"

        return {
            "title": _s(item.get("title")).strip(),
            "severity": sev,
            "cwe": _s(item.get("cwe")).strip(),
            "line": line,
            "evidence": _s(item.get("evidence")),
            "why": _s(item.get("why")).strip(),
            "confidence": conf,
            "novel": bool(item.get("novel", False)),
        }


# --------------------------------------------------------------------------- #
# Module-level convenience wrappers (default singleton, env-driven).
# --------------------------------------------------------------------------- #
_default = None


def _backend():
    global _default
    if _default is None:
        _default = CognisAIBackend()
    return _default


def is_enabled():
    """True only when a backend is explicitly configured (off by default)."""
    return _backend().is_enabled()


def health():
    """Quick liveness probe against the configured endpoint."""
    return _backend().health()


def analyze_code(code, context=None, focus=None):
    """Module-level convenience: analyze code with the env-configured backend."""
    return _backend().analyze_code(code, context=context, focus=focus)


if __name__ == "__main__":
    b = CognisAIBackend()
    print("backend :", b.backend)
    print("base_url:", b.base_url)
    print("model   :", b.model)
    print("enabled :", b.is_enabled())
    print("health  :", b.health())
    print("presets :", json.dumps(PRESETS, indent=2))
