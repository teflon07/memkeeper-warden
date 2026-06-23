import json
import pytest
import warden_mcp as w


def test_build_request_line_is_flat_json():
    line = w.build_request_line("morning-note", "fs:read", "/a/b.csv")
    obj = json.loads(line)
    assert obj == {"skill": "morning-note", "capability": "fs:read", "target": "/a/b.csv"}


def test_rejects_oversized_target():
    big = "x" * (w.MAX_TARGET_BYTES + 1)
    with pytest.raises(ValueError):
        w.build_request_line("s", "fs:read", big)


def test_rejects_unknown_capability_class():
    with pytest.raises(ValueError):
        w.build_request_line("s", "teleport", "/a")


def test_parse_response_extracts_decision():
    resp = w.parse_response(json.dumps({"decision": "deny", "reason": "no grant"}))
    assert resp["decision"] == "deny"
    assert resp["reason"] == "no grant"
