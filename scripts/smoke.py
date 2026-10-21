#!/usr/bin/env python3
"""End-to-end smoke test against a relay: python3 scripts/smoke.py <base-url> <signup-code>

Creates two throwaway owners with one agent each, checks the contact gate, connects them
by invite, and exchanges messages over both REST and MCP. Owners get a random suffix so
it can run against production repeatedly.
"""
import json, secrets, sys, urllib.request, urllib.error

BASE, CODE = sys.argv[1].rstrip("/"), sys.argv[2]
SUFFIX = secrets.token_hex(3)


def call(method, path, token=None, body=None, expect=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=None if body is None else json.dumps(body).encode())
    # Cloudflare's browser check bans Python-urllib's default UA (error 1010).
    req.add_header("user-agent", "agent-relay-smoke/1.0")
    req.add_header("content-type", "application/json")
    req.add_header("accept", "application/json, text/event-stream")
    if token:
        req.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    data = json.loads(raw) if raw else None
    if expect is not None:
        assert status == expect, f"{method} {path}: expected {expect}, got {status}: {data}"
    return status, data


def rpc(token, method, params=None, id=1):
    msg = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        msg["id"] = id
    if params is not None:
        msg["params"] = params
    return call("POST", "/mcp", token, msg)


def tool(token, name, args=None):
    s, d = rpc(token, "tools/call", {"name": name, "arguments": args or {}})
    assert s == 200, d
    return d["result"]


ok = lambda m: print("  ok -", m)

# owners + agents
_, d = call("POST", "/v1/owners", body={"name": f"x{SUFFIX}", "signup_code": "wrong"}, expect=403)
assert d == {"error": "invalid signup code"}, d; ok("signup code enforced")
_, a = call("POST", "/v1/owners", body={"name": f"alice-{SUFFIX}", "signup_code": CODE}, expect=201)
_, b = call("POST", "/v1/owners", body={"name": f"bob-{SUFFIX}", "signup_code": CODE}, expect=201)
call("POST", "/v1/owners", body={"name": f"alice-{SUFFIX}", "signup_code": CODE}, expect=409); ok("duplicate owner rejected")
_, a1 = call("POST", "/v1/agents", a["owner_token"], {"name": "research", "description": "Alice's research agent"}, expect=201)
_, a2 = call("POST", "/v1/agents", a["owner_token"], {"name": "home", "description": "Alice's home box"}, expect=201)
_, b1 = call("POST", "/v1/agents", b["owner_token"], {"name": "planner", "description": "Bob's planner"}, expect=201)
call("POST", "/v1/agents", a1["agent_token"], {"name": "evil"}, expect=401); ok("agent token can't create agents")
A1, A2, B1 = a1["agent_token"], a2["agent_token"], b1["agent_token"]

# same-owner messaging works without contacts; cross-owner is gated
call("POST", "/v1/messages", A1, {"to": a2["handle"], "text": "hi sibling"}, expect=201); ok("same-owner send")
call("POST", "/v1/messages", A1, {"to": b1["handle"], "text": "hi stranger"}, expect=403); ok("stranger blocked")
call("POST", "/v1/messages", A1, {"to": "nobody/none", "text": "?"}, expect=404); ok("unknown handle 404")

# invite flow
_, inv = call("POST", "/v1/invites", A1, expect=201)
call("POST", "/v1/invites/accept", A2, {"code": inv["code"]}, expect=400); ok("own invite rejected")
_, acc = call("POST", "/v1/invites/accept", B1, {"code": inv["code"]}, expect=200)
assert acc["connected"] == f"alice-{SUFFIX}"
call("POST", "/v1/invites/accept", B1, {"code": inv["code"]}, expect=410); ok("invite single-use")

# MCP protocol
s, d = rpc(B1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0"}})
assert s == 200 and d["result"]["protocolVersion"] == "2025-06-18", d
s, _ = rpc(B1, "notifications/initialized", id=None); assert s == 202, s
s, d = rpc(B1, "tools/list"); names = {t["name"] for t in d["result"]["tools"]}
assert {"send_message", "check_inbox", "list_contacts", "create_invite", "accept_invite", "whoami"} <= names, names
s, _ = rpc("ara_bogus", "tools/list"); assert s == 401, s
ok("MCP initialize / notification / tools/list / auth")

contacts = json.loads(tool(B1, "list_contacts")["content"][0]["text"])
assert {x["handle"] for x in contacts["agents"]} == {a1["handle"], a2["handle"]}, contacts; ok("contacts show other side's agents")

r = tool(B1, "send_message", {"to": a1["handle"], "text": "Lunch Thursday?", "data": {"when": "thu 13:00"}})
sent = json.loads(r["content"][0]["text"]); ok("MCP send across owners")
r = tool(A1, "check_inbox"); text = r["content"][0]["text"]
assert "Lunch Thursday?" in text and "untrusted" in text and sent["context_id"] in text, text; ok("MCP inbox shows message + untrusted note")
assert tool(A1, "check_inbox")["content"][0]["text"] == "No unread messages."; ok("read messages not redelivered")

tool(A1, "send_message", {"to": b1["handle"], "text": "Yes!", "context_id": sent["context_id"], "reply_to": sent["message_id"]})
_, box = call("GET", "/v1/inbox", B1, expect=200)
assert box["messages"][0]["context_id"] == sent["context_id"] and box["messages"][0]["reply_to"] == sent["message_id"]; ok("reply threads via context_id")

r = tool(A1, "send_message", {"to": b1["handle"], "text": "x" * 40000})
assert r.get("isError"), r; ok("oversize message rejected as tool error")

_, rot = call("POST", f"/v1/agents/planner/rotate", b["owner_token"], expect=200)
call("GET", "/v1/me", B1, expect=401); call("GET", "/v1/me", rot["agent_token"], expect=200); ok("token rotation")

print(f"PASS ({BASE}, owners alice-{SUFFIX} / bob-{SUFFIX})")
