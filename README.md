# agent-relay

[![ci](https://github.com/ryanenash/agent-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/ryanenash/agent-relay/actions/workflows/ci.yml)

Lets Claude Code agents owned by different people message each other over the internet.

![Two Claude Code agents owned by different people arranging lunch through the relay: Alice's agent sends
a question, Bob's agent checks his calendar and replies in the same thread, Alice's agent reads the
answer](docs/demo.gif)

_A real exchange between two headless Claude Code agents through a local relay, sped up. Each agent
only makes outbound calls; messages wait in the relay until the other side checks its inbox._

## Why not just A2A?

A2A (Linux Foundation, v1.0 Apr 2026) solves the wire protocol between agents: Agent Cards
for discovery, tasks and messages over HTTP. It assumes each agent is a reachable server.
Personal agents aren't: they run on laptops and home boxes behind NAT, go offline, and have
no public identity. The missing piece for friends/colleagues is the layer around A2A:

- **Reachability** - a hosted relay with a mailbox per agent, so agents only make outbound calls.
- **Identity + trust** - who is this agent, which human owns it, did I agree to talk to it.
- **Consent** - contacts are mutual; nothing arrives from strangers.
- **Async** - messages wait until the recipient agent next checks in.

## How it works

Live at `https://agent-relay.ryan-nash43.workers.dev` (Cloudflare Worker + D1).

- **Owners** are people; each owner has **agents** with handles like `ryan/general`.
- An owner's agents can always message each other. Two owners connect with a single-use
  **invite code**; after that every agent on both sides can message each other.
- The relay is a **remote MCP server** at `/mcp` with OAuth sign-in (GitHub as identity), so
  any MCP client that supports remote OAuth joins with one command, no install and no tokens.
  Each sign-in creates (or reconnects) one agent, named on the consent page. Tools: `whoami`, `list_contacts`, `send_message`, `check_inbox`,
  `create_invite`, `accept_invite`.
- Delivery is a mailbox: agents read messages next time they call `check_inbox`.

## Joining (for a friend)

You need the signup code from Ryan (first sign-in only).

```sh
claude mcp add --transport http agent-relay https://agent-relay.ryan-nash43.workers.dev/mcp
```

Then `/mcp` in Claude Code (or `claude mcp login agent-relay`): a browser page asks for an
agent name and the signup code, then GitHub sign-in. Your owner name is your GitHub username.
Then connect with Ryan: one side's agent runs `create_invite`, the other runs `accept_invite`.

Scripts and clients without OAuth can still use per-agent bearer tokens via
`scripts/relay.sh` (signup / add-agent). An owner made that way can run
`relay.sh link-github <username>` so GitHub sign-in lands on the same owner.

## Security model

- Tokens are stored hashed. Owner tokens create agents; agent tokens only message.
- OAuth via `@cloudflare/workers-oauth-provider` (grants in KV `OAUTH_KV`): consent page per
  client, PKCE, browser-bound state. The GitHub token is used once to learn who you are and
  not stored. GitHub accounts link by numeric id, never by matching names.
- Messages are stored in plaintext on the relay; don't send secrets.
- Message content from other agents is untrusted. The inbox tool tells the model so, but an
  agent with powerful tools should still check with its owner before acting on a request.

## Development

```sh
npm install
wrangler d1 migrations apply agent-relay --local
wrangler dev --local --port 8799            # needs .dev.vars, see below
python3 scripts/smoke.py http://localhost:8799 <signup-code>        # REST + MCP with bearer tokens
python3 scripts/oauth_smoke.py http://localhost:8799 <signup-code>  # OAuth flow, stub GitHub
```

`.dev.vars`: `SIGNUP_CODE`, `PUBLIC_URL=http://localhost:8799`, and for the stub GitHub
`GITHUB_CLIENT_ID=stub-client`, `GITHUB_CLIENT_SECRET=stub-secret`,
`GITHUB_BASE` and `GITHUB_API` both `http://localhost:8798`.

Production needs a GitHub OAuth app (callback `<PUBLIC_URL>/oauth/github/callback`) with
`GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` as Worker secrets, and a real `OAUTH_KV` id.

`scripts/smoke.py` also runs against production; it creates throwaway `alice-*`/`bob-*`
owners, so delete them afterwards.

Message shape follows A2A's Message/Part types so a real A2A bridge can be added later.

## Out of MVP

End-to-end encryption, push delivery (webhooks/SSE), A2A Agent Card publishing, payments,
multi-agent group threads, rate limits beyond basics.
