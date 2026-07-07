"""Coverage for the opt-in AI backend (default OFF, never-raises contract).

No network: tests assert the disabled-by-default behaviour and exercise the pure
parsing/normalization helpers (JSON-array extraction from fenced/prose/think
output, finding normalization, the never-raises ``analyze_code`` contract when a
backend is configured but ``_chat`` is stubbed). Env is scrubbed per test.
"""

from __future__ import annotations

import pytest

from c2detect.ai_backend import CognisAIBackend

_AI_ENV = ("COGNIS_AI_BACKEND", "COGNIS_AI_ENDPOINT", "COGNIS_AI_MODEL",
           "COGNIS_AI_KEY")


@pytest.fixture(autouse=True)
def _scrub_env(monkeypatch):
    for k in _AI_ENV:
        monkeypatch.delenv(k, raising=False)
    yield


# --------------------------------------------------------------------------- #
# Disabled by default
# --------------------------------------------------------------------------- #
class TestDisabledDefault:
    def test_not_enabled_without_config(self):
        assert CognisAIBackend().is_enabled() is False

    def test_health_false_when_disabled(self):
        assert CognisAIBackend().health() is False

    def test_analyze_returns_empty_when_disabled(self):
        assert CognisAIBackend().analyze_code("anything") == []

    def test_enabled_with_explicit_endpoint(self, monkeypatch):
        monkeypatch.setenv("COGNIS_AI_ENDPOINT", "http://127.0.0.1:9/v1")
        monkeypatch.setenv("COGNIS_AI_MODEL", "test-model")
        assert CognisAIBackend().is_enabled() is True

    def test_analyze_empty_code_returns_empty(self, monkeypatch):
        monkeypatch.setenv("COGNIS_AI_ENDPOINT", "http://127.0.0.1:9/v1")
        monkeypatch.setenv("COGNIS_AI_MODEL", "m")
        assert CognisAIBackend().analyze_code("   ") == []


# --------------------------------------------------------------------------- #
# JSON array extraction
# --------------------------------------------------------------------------- #
class TestExtractJsonArray:
    def test_plain_array(self):
        assert CognisAIBackend._extract_json_array('[{"a": 1}]') == '[{"a": 1}]'

    def test_fenced_json_block(self):
        text = "Here:\n```json\n[{\"a\": 1}]\n```\ndone"
        assert CognisAIBackend._extract_json_array(text) == '[{"a": 1}]'

    def test_fenced_plain_block(self):
        text = "```\n[1, 2, 3]\n```"
        assert CognisAIBackend._extract_json_array(text) == "[1, 2, 3]"

    def test_array_amid_prose(self):
        text = "The findings are [{\"x\": 1}] and that's all."
        assert CognisAIBackend._extract_json_array(text) == '[{"x": 1}]'

    def test_think_block_stripped(self):
        text = "<think>let me reason</think>[{\"a\": 1}]"
        assert CognisAIBackend._extract_json_array(text) == '[{"a": 1}]'

    def test_unterminated_think_stripped(self):
        assert CognisAIBackend._extract_json_array("<think>blah blah") is None

    def test_no_array_returns_none(self):
        assert CognisAIBackend._extract_json_array("no array here") is None

    def test_nested_array_balanced(self):
        text = '[{"x": [1, 2]}, {"y": 3}]'
        assert CognisAIBackend._extract_json_array(text) == text

    def test_bracket_inside_string_not_miscounted(self):
        text = '[{"note": "has a ] in it"}]'
        assert CognisAIBackend._extract_json_array(text) == text


# --------------------------------------------------------------------------- #
# Finding parsing + normalization
# --------------------------------------------------------------------------- #
class TestParseFindings:
    def test_parses_valid_array(self):
        out = CognisAIBackend._parse_findings('[{"title": "X", "severity": "high"}]')
        assert len(out) == 1 and out[0]["title"] == "X"
        assert out[0]["severity"] == "high"

    def test_skips_non_dict_items(self):
        out = CognisAIBackend._parse_findings('[{"title": "X"}, 42, "str"]')
        assert len(out) == 1

    def test_invalid_json_returns_empty(self):
        assert CognisAIBackend._parse_findings("not json at all") == []

    def test_non_array_returns_empty(self):
        assert CognisAIBackend._parse_findings('{"title": "X"}') == []

    def test_severity_normalized_to_info(self):
        out = CognisAIBackend._parse_findings('[{"title": "x", "severity": "BOGUS"}]')
        assert out[0]["severity"] == "info"

    def test_confidence_clamped(self):
        out = CognisAIBackend._parse_findings('[{"title": "x", "confidence": 5}]')
        assert out[0]["confidence"] == 1.0
        out2 = CognisAIBackend._parse_findings('[{"title": "x", "confidence": -3}]')
        assert out2[0]["confidence"] == 0.0

    def test_line_coerced_to_int(self):
        out = CognisAIBackend._parse_findings('[{"title": "x", "line": "not-a-num"}]')
        assert out[0]["line"] == 0

    def test_novel_flag_bool(self):
        out = CognisAIBackend._parse_findings('[{"title": "x", "novel": true}]')
        assert out[0]["novel"] is True

    def test_all_fields_present(self):
        out = CognisAIBackend._parse_findings('[{"title": "x"}]')
        for key in ("title", "severity", "cwe", "line", "evidence", "why",
                    "confidence", "novel"):
            assert key in out[0]


# --------------------------------------------------------------------------- #
# analyze_code never raises even when _chat misbehaves
# --------------------------------------------------------------------------- #
class TestNeverRaises:
    def _enabled(self, monkeypatch):
        monkeypatch.setenv("COGNIS_AI_ENDPOINT", "http://127.0.0.1:9/v1")
        monkeypatch.setenv("COGNIS_AI_MODEL", "m")
        return CognisAIBackend()

    def test_chat_raises_returns_empty(self, monkeypatch):
        be = self._enabled(monkeypatch)
        monkeypatch.setattr(be, "_chat",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        assert be.analyze_code("code") == []

    def test_chat_empty_returns_empty(self, monkeypatch):
        be = self._enabled(monkeypatch)
        monkeypatch.setattr(be, "_chat", lambda *a, **k: "")
        assert be.analyze_code("code") == []

    def test_chat_returns_findings(self, monkeypatch):
        be = self._enabled(monkeypatch)
        monkeypatch.setattr(
            be, "_chat",
            lambda *a, **k: '[{"title": "Suspicious beacon", "severity": "high"}]')
        out = be.analyze_code("code")
        assert len(out) == 1 and out[0]["title"] == "Suspicious beacon"

    def test_chat_returns_garbage_returns_empty(self, monkeypatch):
        be = self._enabled(monkeypatch)
        monkeypatch.setattr(be, "_chat", lambda *a, **k: "I could not find anything.")
        assert be.analyze_code("code") == []


# --------------------------------------------------------------------------- #
# prompt construction
# --------------------------------------------------------------------------- #
class TestPrompt:
    def test_includes_code(self):
        p = CognisAIBackend._build_user_prompt("THECODE")
        assert "THECODE" in p

    def test_includes_context_and_focus(self):
        p = CognisAIBackend._build_user_prompt("c", context="CTX", focus="FOC")
        assert "CTX" in p and "FOC" in p

    def test_strip_think_removes_block(self):
        assert "reason" not in CognisAIBackend._strip_think("<think>reason</think>ok")
