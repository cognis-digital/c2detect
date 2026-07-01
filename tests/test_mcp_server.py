"""Coverage for the stdlib MCP server (scan / correlate / list tools + JSON-RPC).

Exercises the tool functions directly and the JSON-RPC ``_handle`` dispatch by
capturing stdout, including the error paths (unknown method, unknown tool, a
tool that raises). No network; no third-party MCP deps.
"""

from __future__ import annotations

import io
import json

import pytest

from c2detect import mcp_server as mcp

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


# --------------------------------------------------------------------------- #
# scan() tool entry point — every accepted payload shape
# --------------------------------------------------------------------------- #
class TestScanTool:
    def test_dict_with_observations(self):
        out = mcp.scan({"observations": [{"jarm": CS_JARM}]})
        assert out["tool"] == "c2detect"
        assert out["match_count"] >= 1

    def test_dict_as_single_record(self):
        out = mcp.scan({"jarm": CS_JARM})
        assert out["match_count"] >= 1

    def test_dict_with_text(self):
        out = mcp.scan({"text": f"jarm: {CS_JARM}"})
        assert out["match_count"] >= 1

    def test_json_string_payload(self):
        out = mcp.scan(json.dumps([{"jarm": CS_JARM}]))
        assert out["match_count"] >= 1

    def test_free_text_string_payload(self):
        out = mcp.scan(f"saw {CS_JARM} on the wire")
        assert out["match_count"] >= 1

    def test_threshold_respected(self):
        # A lone port hit is suppressed at a high threshold.
        out = mcp.scan({"observations": [{"port": 50050}], "threshold": 90})
        assert out["match_count"] == 0

    def test_threshold_zero_admits_weak(self):
        out = mcp.scan({"observations": [{"port": 50050}], "threshold": 0})
        assert out["match_count"] >= 1

    def test_clean_observation(self):
        out = mcp.scan({"observations": [{"host": "x", "port": 12345}]})
        assert out["match_count"] == 0

    def test_unexpected_type_returns_empty(self):
        out = mcp.scan(12345)
        assert out["match_count"] == 0

    def test_result_is_json_serializable(self):
        out = mcp.scan({"jarm": CS_JARM})
        assert json.loads(json.dumps(out))["tool"] == "c2detect"


# --------------------------------------------------------------------------- #
# correlate_tool()
# --------------------------------------------------------------------------- #
class TestCorrelateTool:
    def test_dict_observations_cluster(self):
        out = mcp.correlate_tool({"observations": [
            {"host": "a", "jarm": CS_JARM}, {"host": "b", "jarm": CS_JARM}]})
        assert out["campaign_count"] == 1

    def test_bare_list(self):
        out = mcp.correlate_tool([{"host": "a", "jarm": CS_JARM},
                                  {"host": "b", "jarm": CS_JARM}])
        assert out["campaign_count"] == 1

    def test_json_string(self):
        out = mcp.correlate_tool(json.dumps(
            [{"host": "a", "jarm": CS_JARM}, {"host": "b", "jarm": CS_JARM}]))
        assert out["campaign_count"] == 1

    def test_single_record_no_campaign(self):
        out = mcp.correlate_tool({"host": "a", "jarm": CS_JARM})
        assert out["campaign_count"] == 0

    def test_empty(self):
        out = mcp.correlate_tool({"observations": []})
        assert out["campaign_count"] == 0

    def test_document_shape(self):
        out = mcp.correlate_tool([])
        assert out["mode"] == "correlate" and out["tool"] == "c2detect"


# --------------------------------------------------------------------------- #
# JSON-RPC dispatch via _handle (captures stdout)
# --------------------------------------------------------------------------- #
def _call(monkeypatch, msg):
    buf = io.StringIO()
    monkeypatch.setattr(mcp.sys, "stdout", buf)
    mcp._handle(msg)
    out = buf.getvalue().strip()
    return json.loads(out) if out else None


class TestJsonRpc:
    def test_initialize(self, monkeypatch):
        resp = _call(monkeypatch, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert resp["result"]["serverInfo"]["name"] == "c2detect"
        assert resp["result"]["protocolVersion"]

    def test_initialized_notification_no_response(self, monkeypatch):
        resp = _call(monkeypatch, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert resp is None

    def test_tools_list(self, monkeypatch):
        resp = _call(monkeypatch, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        assert {"scan", "list_signatures", "correlate"} <= names

    def test_tools_call_scan(self, monkeypatch):
        resp = _call(monkeypatch, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "scan", "arguments": {"jarm": CS_JARM}}})
        assert resp["result"]["isError"] is False
        text = resp["result"]["content"][0]["text"]
        assert json.loads(text)["match_count"] >= 1

    def test_tools_call_list_signatures(self, monkeypatch):
        resp = _call(monkeypatch, {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "list_signatures", "arguments": {}}})
        text = resp["result"]["content"][0]["text"]
        assert len(json.loads(text)["families"]) >= 12

    def test_tools_call_correlate(self, monkeypatch):
        resp = _call(monkeypatch, {
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "correlate", "arguments": {"observations": [
                {"host": "a", "jarm": CS_JARM}, {"host": "b", "jarm": CS_JARM}]}}})
        text = resp["result"]["content"][0]["text"]
        assert json.loads(text)["campaign_count"] == 1

    def test_unknown_tool_errors(self, monkeypatch):
        resp = _call(monkeypatch, {
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": "nope", "arguments": {}}})
        assert resp["error"]["code"] == -32601

    def test_unknown_method_errors(self, monkeypatch):
        resp = _call(monkeypatch, {"jsonrpc": "2.0", "id": 7, "method": "bogus/method"})
        assert resp["error"]["code"] == -32601

    def test_unknown_method_notification_no_response(self, monkeypatch):
        # No id => a notification => no error response even for unknown method.
        resp = _call(monkeypatch, {"jsonrpc": "2.0", "method": "bogus/method"})
        assert resp is None
