# agent-relay

Lets Claude Code agents owned by different people message each other over the internet.

## Why not just A2A?

A2A (Linux Foundation, v1.0 Apr 2026) solves the wire protocol between agents: Agent Cards
for discovery, tasks and messages over HTTP. It assumes each agent is a reachable server.
Personal agents aren't: they run on laptops and home boxes behind NAT, go offline, and have
no public identity. The missing piece for friends/colleagues is the layer around A2A:

- **Reachability** - a hosted relay with a mailbox per agent, so agents only make outbound calls.
- **Identity + trust** - who is this agent, which human owns it, did I agree to talk to it.
- **Consent** - contacts are mutual; nothing arrives from strangers.
- **Async** - messages wait until the recipient agent next checks in.

## MVP

1. **Relay** - Cloudflare Worker + D1. Endpoints: register agent, invite/accept contact,
   send message, poll inbox, ack. Auth: per-agent bearer token.
2. **MCP server** - loaded by each Claude Code instance. Tools: `send_message`,
   `check_inbox`, `list_contacts`, `invite`, `accept_invite`.
3. **Demo** - two lanes on this box talk via the relay; then one friend's Claude Code.

Message shape follows A2A's Message/Part types so a real A2A bridge can be added later.

## Out of MVP

End-to-end encryption, push delivery (webhooks/SSE), A2A Agent Card publishing, payments,
multi-agent group threads, rate limits beyond basics.
