#!/usr/bin/env python3
"""OAuth sign-in test against a LOCAL relay: python3 scripts/oauth_smoke.py <base-url> <signup-code>

Plays the MCP client and the browser, with a stub GitHub on localhost:8798 (the relay's
.dev.vars must point GITHUB_BASE/GITHUB_API there). Covers discovery from the 401, dynamic
client registration, consent, GitHub sign-in with PKCE, token exchange, MCP calls, refresh,
reconnecting an agent, the signup-code gate, and pre-claiming a GitHub login.
"""
import base64, hashlib, html, json, re, secrets, sys, threading, urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE, CODE = sys.argv[1].rstrip("/"), sys.argv[2]
SUFFIX = secrets.token_hex(3)
GH = {"user": None, "codes": {}}  # stub state: who signs in next; code -> (challenge, user)


class StubGitHub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, body=None, location=None):
        self.send_response(status)
        if location:
            self.send_header("location", location)
        self.send_header("content-type", "application/json")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/login/oauth/authorize":
            assert q["client_id"] == "stub-client" and q["code_challenge_method"] == "S256"
            code = secrets.token_hex(8)
            GH["codes"][code] = (q["code_challenge"], GH["user"])
            sep = "&" if "?" in q["redirect_uri"] else "?"
            return self.reply(302, location=f"{q['redirect_uri']}{sep}code={code}&state={urllib.parse.quote(q['state'])}")
        if u.path == "/user":
            tok = self.headers.get("authorization", "").removeprefix("Bearer ")
            return self.reply(200, GH["tokens"][tok]) if tok in GH.get("tokens", {}) else self.reply(401, {})
        self.reply(404, {})

    def do_POST(self):
        b = json.loads(self.rfile.read(int(self.headers["content-length"])))
        challenge, user = GH["codes"].pop(b.get("code"), (None, None))
        ok = challenge and b["client_secret"] == "stub-secret" and s256(b["code_verifier"]) == challenge
        if not ok:
            return self.reply(200, {"error": "bad_verification_code"})
        tok = secrets.token_hex(8)
        GH.setdefault("tokens", {})[tok] = user
        self.reply(200, {"access_token": tok, "token_type": "bearer"})


def s256(v):
    return base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def http(method, url, data=None, headers=None, form=False):
    h = {"user-agent": "agent-relay-oauth-smoke/1.0", **(headers or {})}
    if data is not None and form:
        data, h["content-type"] = urllib.parse.urlencode(data, doseq=True).encode(), "application/x-www-form-urlencoded"
    elif data is not None:
        data, h["content-type"] = json.dumps(data).encode(), "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        r = OPENER.open(req)
    except urllib.error.HTTPError as e:
        r = e
    return r.status, r.headers, r.read().decode()


class Browser:
    """Cookie handling by hand: http.cookiejar won't send __Host-/Secure cookies over http://localhost."""

    def __init__(self):
        self.cookies = {}

    def go(self, method, url, data=None):
        h = {"cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())} if self.cookies else {}
        status, headers, body = http(method, url, data, h, form=True)
        for c in headers.get_all("set-cookie") or []:
            k, v = c.split(";", 1)[0].split("=", 1)
            if "max-age=0" in c.lower() or not v:
                self.cookies.pop(k, None)
            else:
                self.cookies[k] = v
        return status, headers, body


passed = 0


def check(name, cond, detail=""):
    global passed
    assert cond, f"FAIL {name}: {detail}"
    passed += 1
    print(f"ok  {name}")


def discover():
    status, headers, _ = http("POST", f"{BASE}/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    www = headers.get("www-authenticate", "")
    check("unauthenticated /mcp -> 401 with resource_metadata", status == 401 and "resource_metadata" in www, www)
    prm_url = re.search(r'resource_metadata="([^"]+)"', www).group(1)
    prm = json.loads(http("GET", prm_url)[2])
    as_meta = json.loads(http("GET", f"{prm['authorization_servers'][0]}/.well-known/oauth-authorization-server")[2])
    check("discovery: resource + AS metadata", prm["resource"] == f"{BASE}/mcp" and "registration_endpoint" in as_meta, as_meta)
    return prm["resource"], as_meta


def register(as_meta):
    status, _, body = http("POST", as_meta["registration_endpoint"], {
        "client_name": "Smoke Client", "redirect_uris": ["http://127.0.0.1:33418/callback"],
        "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    })
    check("dynamic client registration", status == 201, body)
    return json.loads(body)["client_id"]


def sign_in(resource, as_meta, client_id, gh_user, agent, signup_code=CODE):
    """Full browser flow. Returns (status, location-or-body) at the end."""
    GH["user"] = gh_user
    b, verifier, state = Browser(), secrets.token_urlsafe(40), secrets.token_hex(8)
    q = urllib.parse.urlencode({"response_type": "code", "client_id": client_id, "redirect_uri": "http://127.0.0.1:33418/callback",
                                "code_challenge": s256(verifier), "code_challenge_method": "S256", "state": state,
                                "resource": resource, "scope": "relay"})
    status, _, page = b.go("GET", f"{as_meta['authorization_endpoint']}?{q}")
    assert status == 200 and "Smoke Client" in page, page[:500]
    handle = html.unescape(re.search(r'name="handle" value="([^"]+)"', page).group(1))
    status, h, body = b.go("POST", as_meta["authorization_endpoint"],
                           {"handle": handle, "agent": agent, "signup_code": signup_code, "decision": "approve"})
    assert status == 302 and h["location"].startswith("http://localhost:8798/"), (status, body)
    status, h, _ = b.go("GET", h["location"])  # stub GitHub bounces back to the relay callback
    status, h, body = b.go("GET", h["location"])
    if status != 302:
        return status, body, None
    loc = urllib.parse.urlparse(h["location"])
    params = dict(urllib.parse.parse_qsl(loc.query))
    assert params.get("state") == state, params
    status, _, body = http("POST", as_meta["token_endpoint"], {
        "grant_type": "authorization_code", "code": params["code"], "redirect_uri": "http://127.0.0.1:33418/callback",
        "client_id": client_id, "code_verifier": verifier, "resource": resource}, form=True)
    return status, json.loads(body), verifier


def mcp(token, method, params=None):
    status, _, body = http("POST", f"{BASE}/mcp", {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
                           {"authorization": f"Bearer {token}", "accept": "application/json, text/event-stream"})
    return status, (json.loads(body) if body else None)


def whoami(token):
    status, r = mcp(token, "tools/call", {"name": "whoami", "arguments": {}})
    return json.loads(r["result"]["content"][0]["text"]) if status == 200 else status


threading.Thread(target=HTTPServer(("127.0.0.1", 8798), StubGitHub).serve_forever, daemon=True).start()

resource, as_meta = discover()
client_id = register(as_meta)

login = f"octo-{SUFFIX}"
user = {"id": int(SUFFIX, 16) + 1_000_000, "login": login}
status, tok, _ = sign_in(resource, as_meta, client_id, user, "laptop")
check("sign-in -> token exchange", status == 200 and "access_token" in tok and "refresh_token" in tok, tok)
me = whoami(tok["access_token"])
check("OAuth token works at /mcp; owner from GitHub login", me.get("handle") == f"{login}/laptop", me)

status, r = mcp(tok["access_token"], "tools/list")
check("tools/list over OAuth", status == 200 and len(r["result"]["tools"]) == 6, r)

status, _, body = http("POST", as_meta["token_endpoint"], {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                                          "client_id": client_id}, form=True)
check("refresh token", status == 200 and whoami(json.loads(body)["access_token"]).get("handle") == f"{login}/laptop", body)

status, tok2, _ = sign_in(resource, as_meta, client_id, user, "laptop")
check("re-sign-in with same agent name reconnects it", whoami(tok2["access_token"]).get("handle") == f"{login}/laptop")

status, tok3, _ = sign_in(resource, as_meta, register(as_meta), user, "desk")
check("second agent under same owner", whoami(tok3["access_token"]).get("handle") == f"{login}/desk")
status, r = mcp(tok3["access_token"], "tools/call", {"name": "send_message", "arguments": {"to": f"{login}/laptop", "text": "hi via oauth"}})
status, r = mcp(tok2["access_token"], "tools/call", {"name": "check_inbox", "arguments": {}})
check("OAuth agents exchange a message", "hi via oauth" in r["result"]["content"][0]["text"], r)

status, body, _ = sign_in(resource, as_meta, client_id, {"id": user["id"] + 1, "login": f"new-{SUFFIX}"}, "x1", signup_code="wrong")
check("new GitHub user with bad signup code is refused", status == 403 and "signup code" in body, (status, body[:300]))

# Pre-claim: an owner made the old way links to a GitHub account on first sign-in.
status, _, body = http("POST", f"{BASE}/v1/owners", {"name": f"carol-{SUFFIX}", "signup_code": CODE})
owner_token = json.loads(body)["owner_token"]
status, _, body = http("POST", f"{BASE}/v1/owners/github", {"login": f"Carol-GH-{SUFFIX}"}, {"authorization": f"Bearer {owner_token}"})
check("pre-claim GitHub login", status == 200, body)
status, tok4, _ = sign_in(resource, as_meta, client_id, {"id": user["id"] + 2, "login": f"Carol-GH-{SUFFIX}"}, "phone", signup_code="")
check("pre-claimed login lands on existing owner (no signup code)", whoami(tok4["access_token"]).get("handle") == f"carol-{SUFFIX}/phone")

status, _, body = http("POST", f"{BASE}/v1/agents", {"name": "legacy"}, {"authorization": f"Bearer {owner_token}"})
legacy = json.loads(body)["agent_token"]
check("legacy ara_ token still works at /mcp", whoami(legacy).get("handle") == f"carol-{SUFFIX}/legacy")
check("bogus token -> 401", mcp("ara_nope", "ping")[0] == 401 and mcp("x:y:z", "ping")[0] == 401)

print(f"\nall {passed} checks passed")
