"""Coverage for the new MCP tools: export / beacon / generate_rules."""
from __future__ import annotations

import io
import json

from c2detect import mcp_server as mcp

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


class TestExportTool:
    def test_stix_default(self):
        out = mcp.export_tool({"observations": [{"host": "1.1.1.1", "jarm": CS_JARM}]})
        assert out["type"] == "bundle"
        assert any(o["type"] == "indicator" for o in out["objects"])

    def test_misp_format(self):
        out = mcp.export_tool({"format": "misp",
                               "observations": [{"host": "1.1.1.1", "jarm": CS_JARM}]})
        assert "Event" in out

    def test_string_payload(self):
        out = mcp.export_tool(json.dumps([{"jarm": CS_JARM}]))
        assert out["type"] == "bundle"

    def test_single_record(self):
        out = mcp.export_tool({"jarm": CS_JARM})
        assert out["objects"]


class TestBeaconTool:
    def test_timestamps_array(self):
        out = mcp.beacon_tool({"timestamps": [0, 60, 120, 180, 240], "dest": "x"})
        assert out["verdict"] == "beacon"
        assert out["dest"] == "x"

    def test_text_blob(self):
        txt = "\n".join(str(1700000000 + i * 60) for i in range(8))
        out = mcp.beacon_tool({"text": txt})
        assert out["is_beacon"] is True

    def test_raw_list(self):
        out = mcp.beacon_tool([0, 60, 120, 180, 240])
        assert out["verdict"] == "beacon"

    def test_raw_string(self):
        txt = "\n".join(str(1700000000 + i * 30) for i in range(8))
        out = mcp.beacon_tool(txt)
        assert out["mean_interval"] == 30.0

    def test_empty(self):
        out = mcp.beacon_tool({})
        assert out["verdict"] == "insufficient-data"


class TestRulesTool:
    def test_sigma_default(self):
        out = mcp.rules_tool({})
        assert out["format"] == "sigma"
        assert out["rules"].startswith("title:")

    def test_each_format(self):
        for fmt in ("suricata", "kql", "splunk", "eql", "yara"):
            out = mcp.rules_tool({"format": fmt})
            assert out["format"] == fmt
            assert out["rules"].strip()

    def test_bad_format(self):
        out = mcp.rules_tool({"format": "nope"})
        assert "error" in out


def _call(monkeypatch, msg):
    buf = io.StringIO()
    monkeypatch.setattr(mcp.sys, "stdout", buf)
    mcp._handle(msg)
    out = buf.getvalue().strip()
    return json.loads(out) if out else None


class TestJsonRpcNewTools:
    def test_call_export(self, monkeypatch):
        resp = _call(monkeypatch, {
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "export", "arguments": {"jarm": CS_JARM}}})
        assert resp["result"]["isError"] is False
        assert json.loads(resp["result"]["content"][0]["text"])["type"] == "bundle"

    def test_call_beacon(self, monkeypatch):
        resp = _call(monkeypatch, {
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": {"name": "beacon",
                       "arguments": {"timestamps": [0, 60, 120, 180, 240]}}})
        assert json.loads(resp["result"]["content"][0]["text"])["verdict"] == "beacon"

    def test_call_generate_rules(self, monkeypatch):
        resp = _call(monkeypatch, {
            "jsonrpc": "2.0", "id": 12, "method": "tools/call",
            "params": {"name": "generate_rules", "arguments": {"format": "yara"}}})
        text = json.loads(resp["result"]["content"][0]["text"])
        assert text["format"] == "yara"
