// Browser sign-in for MCP clients: OAuth 2.1 (via @cloudflare/workers-oauth-provider) with
// GitHub as the identity step. One authorization = one agent; the consent page names it.

import { AuthorizationError, CimdFetchError, authorizationErrorRedirect, type OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export interface OAuthEnv {
  DB: D1Database;
  OAUTH_PROVIDER: OAuthHelpers;
  SIGNUP_CODE?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  // Overridable so local tests can point at a stub instead of github.com.
  GITHUB_BASE?: string;
  GITHUB_API?: string;
}

type Upstream = { verifier: string; agentName: string; signupCode: string; clientName: string };

const NAME_RE = /^[a-z0-9][a-z0-9-]{1,30}$/;

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function slug(s: string): string {
  const v = s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 31).replace(/-+$/, "");
  return NAME_RE.test(v) ? v : "agent";
}

async function s256(v: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)));
  return btoa(String.fromCharCode(...d)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function page(title: string, body: string, headers = new Headers(), status = 200): Response {
  headers.set("content-type", "text/html; charset=utf-8");
  return new Response(
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>
body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 16px;color:#1a1a1a;background:#fff}
@media (prefers-color-scheme:dark){body{color:#eee;background:#161616}input{background:#222;color:#eee;border-color:#444}}
input{font:inherit;padding:.4rem .6rem;width:100%;box-sizing:border-box;border:1px solid #bbb;border-radius:6px}
label{display:block;margin:1rem 0 .25rem;font-weight:600}small{color:#888}
button{font:inherit;padding:.5rem 1.1rem;border-radius:6px;border:1px solid #888;cursor:pointer;margin-right:.5rem}
button.primary{background:#1a7f37;color:#fff;border-color:#1a7f37}.warn{background:#fff4ce;color:#5c4400;padding:.6rem .8rem;border-radius:6px}
</style></head><body>${body}</body></html>`,
    { status, headers },
  );
}

const errorPage = (msg: string, status = 400) => page("agent-relay", `<h1>Couldn't connect</h1><p>${esc(msg)}</p>`, new Headers(), status);

export async function handleOAuth(req: Request, env: OAuthEnv, url: URL): Promise<Response | null> {
  try {
    if (url.pathname === "/authorize" && req.method === "GET") return await consent(req, env);
    if (url.pathname === "/authorize" && req.method === "POST") return await approve(req, env, url);
    if (url.pathname === "/oauth/github/callback" && req.method === "GET") return await callback(req, env, url);
    return null;
  } catch (e) {
    if (e instanceof AuthorizationError && e.redirectTo) return Response.redirect(e.redirectTo, 302);
    if (e instanceof AuthorizationError) return errorPage(`${e.description ?? e.message} Start again from your agent.`);
    if (e instanceof CimdFetchError) return errorPage("This app could not be verified.");
    if (e instanceof SignInError) return errorPage(e.message, 403);
    throw e;
  }
}

class SignInError extends Error {}

async function consent(req: Request, env: OAuthEnv): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  const request = await oauth.parseAuthRequest(req);
  const d = await oauth.describeConsent(request);
  const { handle, headers } = await oauth.beginConsent(request);
  const name = esc(d.clientName);
  const origin = d.clientDomain
    ? `Published by <strong>${esc(d.clientDomain)}</strong>.`
    : "This app registered itself, so its name is not verified.";
  return page(
    `Connect ${d.clientName} to agent-relay`,
    `<h1>Connect ${name} to agent-relay</h1>
<p>This creates a relay agent for <strong>${name}</strong> so it can message your contacts' agents.
${origin} Access goes to <strong>${esc(d.redirectHost)}</strong>.</p>
${d.redirectIsLoopback ? '<p class="warn">This sends access to an app on your computer. Continue only if you just started connecting from it.</p>' : ""}
<form method="post">
<input type="hidden" name="handle" value="${esc(handle)}">
<label for="agent">Agent name</label>
<input id="agent" name="agent" value="${esc(slug(d.clientName))}" pattern="[a-z0-9][a-z0-9-]{1,30}" required>
<small>Lowercase letters, digits, '-'. Your agent becomes <em>your-github-name/this-name</em>. Reusing a name reconnects that agent.</small>
${env.SIGNUP_CODE ? '<label for="code">Signup code</label><input id="code" name="signup_code" autocomplete="off"><small>Only needed the first time you sign in.</small>' : ""}
<p style="margin-top:1.5rem"><button class="primary" name="decision" value="approve">Continue with GitHub</button><button name="decision" value="deny">Cancel</button></p>
</form>`,
    headers,
  );
}

async function approve(req: Request, env: OAuthEnv, url: URL): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  const form = await req.formData();
  const handle = String(form.get("handle") ?? "");
  if (form.get("decision") !== "approve") {
    const denied = await oauth.denyConsent(req, handle);
    return new Response(null, { status: 302, headers: denied.headers });
  }
  const agentName = String(form.get("agent") ?? "").trim().toLowerCase();
  if (!NAME_RE.test(agentName)) return errorPage("Agent name must be 2-31 chars of a-z, 0-9, '-'. Go back and fix it.");
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) throw new Error("GitHub OAuth app not configured");

  const approved = await oauth.approveConsent(req, handle, { scope: ["relay"] });
  const clientName = (await oauth.describeConsent(approved.request)).clientName;
  const verifier = crypto.randomUUID() + crypto.randomUUID();
  const data: Upstream = { verifier, agentName, signupCode: String(form.get("signup_code") ?? ""), clientName };
  const { state, headers } = await oauth.beginUpstream(approved.request, { data, headers: approved.headers });
  const gh = new URL(`${env.GITHUB_BASE ?? "https://github.com"}/login/oauth/authorize`);
  gh.search = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: `${url.origin}/oauth/github/callback`,
    state,
    code_challenge: await s256(verifier),
    code_challenge_method: "S256",
  }).toString();
  headers.set("location", gh.toString());
  return new Response(null, { status: 302, headers });
}

async function callback(req: Request, env: OAuthEnv, url: URL): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  const { request, data, headers } = await oauth.finishUpstream<Upstream>(req);
  if (url.searchParams.get("error") || !url.searchParams.get("code")) {
    headers.set("location", authorizationErrorRedirect(request, "access_denied"));
    return new Response(null, { status: 302, headers });
  }

  const tokRes = await fetch(`${env.GITHUB_BASE ?? "https://github.com"}/login/oauth/access_token`, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code: url.searchParams.get("code"),
      redirect_uri: `${url.origin}/oauth/github/callback`,
      code_verifier: data.verifier,
    }),
  });
  const tok = (await tokRes.json().catch(() => ({}))) as { access_token?: string; error?: string };
  if (!tok.access_token) throw new SignInError(`GitHub sign-in failed (${tok.error ?? tokRes.status}).`);
  const userRes = await fetch(`${env.GITHUB_API ?? "https://api.github.com"}/user`, {
    headers: { authorization: `Bearer ${tok.access_token}`, accept: "application/vnd.github+json", "user-agent": "agent-relay" },
  });
  const user = (await userRes.json().catch(() => ({}))) as { id?: number; login?: string };
  if (!userRes.ok || typeof user.id !== "number" || typeof user.login !== "string")
    throw new SignInError("Couldn't read your GitHub profile.");
  // The GitHub token was only needed to learn who this is; it isn't stored.

  const owner = await ownerForGithub(env, user.id, user.login, data.signupCode);
  const handle = `${owner}/${data.agentName}`;
  await env.DB.prepare(
    `INSERT INTO agents (handle, owner, name, description, token_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(handle) DO NOTHING`,
  ).bind(handle, owner, data.agentName, `Connected via ${data.clientName}`.slice(0, 500), `oauth:${crypto.randomUUID()}`, Date.now()).run();

  const { redirectTo } = await oauth.completeAuthorization({
    request,
    userId: encodeURIComponent(handle),
    metadata: { github_login: user.login },
    scope: ["relay"],
    props: { handle },
  });
  headers.set("location", redirectTo);
  return new Response(null, { status: 302, headers });
}

// Find the owner for a GitHub account, linking a pre-claimed owner or creating a new one.
async function ownerForGithub(env: OAuthEnv, id: number, login: string, signupCode: string): Promise<string> {
  const byId = await env.DB.prepare("SELECT name FROM owners WHERE github_id = ?").bind(id).first<{ name: string }>();
  if (byId) return byId.name;
  const lc = login.toLowerCase();
  const claimed = await env.DB.prepare("SELECT name FROM owners WHERE github_login = ? AND github_id IS NULL")
    .bind(lc).first<{ name: string }>();
  if (claimed) {
    await env.DB.prepare("UPDATE owners SET github_id = ? WHERE name = ?").bind(id, claimed.name).run();
    return claimed.name;
  }
  if (env.SIGNUP_CODE && signupCode !== env.SIGNUP_CODE)
    throw new SignInError("First sign-in needs a valid signup code. Ask whoever invited you, then connect again.");
  let base = slug(lc);
  if (base.length < 2 || base === "agent") base = `gh-${id}`;
  for (let i = 1; i <= 20; i++) {
    const name = i === 1 ? base : `${base.slice(0, 28)}-${i}`;
    // Owner tokens aren't used for OAuth owners; the placeholder keeps token_hash unique.
    const r = await env.DB.prepare(
      "INSERT OR IGNORE INTO owners (name, token_hash, created_at, github_id) VALUES (?, ?, ?, ?)",
    ).bind(name, `oauth:${crypto.randomUUID()}`, Date.now(), id).run();
    if (r.meta.changes) return name;
  }
  throw new SignInError("Couldn't pick an owner name; contact the relay operator.");
}
