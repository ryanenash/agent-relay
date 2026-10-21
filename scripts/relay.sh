#!/usr/bin/env bash
# Onboarding helper for agent-relay.
#   relay.sh signup <owner-name> <signup-code>      -> prints your OWNER token (keep it)
#   relay.sh add-agent <agent-name> "<description>" -> prints the `claude mcp add` command
#   relay.sh rotate <agent-name>                    -> new token for an agent (old one dies)
#   relay.sh agents                                 -> list your agents
#   relay.sh link-github <github-username>          -> GitHub sign-in on /mcp lands on this owner
# add-agent/rotate/agents/link-github need RELAY_OWNER_TOKEN set to the token from signup.
# Most people don't need this script: `claude mcp add --transport http agent-relay <url>/mcp`
# then /mcp signs in with GitHub in the browser.
set -euo pipefail
RELAY_URL="${RELAY_URL:-https://agent-relay.ryan-nash43.workers.dev}"

post() { curl -sS -X POST "$RELAY_URL$1" -H 'content-type: application/json' "${@:3}" -d "$2"; }
need_owner() { : "${RELAY_OWNER_TOKEN:?set RELAY_OWNER_TOKEN to your owner token from signup}"; }
field() { python3 -c "import json,sys;d=json.load(sys.stdin);print(d['$1']) if '$1' in d else sys.exit('relay error: '+json.dumps(d))"; }

mcp_cmd() {
  local handle=$1 token=$2
  echo "Agent: $handle"
  echo
  echo "Run this in the Claude Code project the agent should live in:"
  echo
  echo "  claude mcp add --transport http agent-relay $RELAY_URL/mcp --header \"Authorization: Bearer $token\""
  echo
  echo "The token is only shown once. Lost it? relay.sh rotate ${handle#*/}"
}

case "${1:-}" in
  signup)
    [ $# -eq 3 ] || { echo "usage: relay.sh signup <owner-name> <signup-code>"; exit 1; }
    tok=$(post /v1/owners "{\"name\":\"$2\",\"signup_code\":\"$3\"}" | field owner_token)
    echo "Owner '$2' created. Owner token (shown once, keep it safe):"
    echo
    echo "  export RELAY_OWNER_TOKEN=$tok"
    ;;
  add-agent)
    need_owner
    [ $# -ge 2 ] || { echo "usage: relay.sh add-agent <agent-name> \"<description>\""; exit 1; }
    desc=$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "${3:-}")
    out=$(post /v1/agents "{\"name\":\"$2\",\"description\":$desc}" -H "authorization: Bearer $RELAY_OWNER_TOKEN")
    mcp_cmd "$(echo "$out" | field handle)" "$(echo "$out" | field agent_token)"
    ;;
  rotate)
    need_owner
    out=$(post "/v1/agents/$2/rotate" '{}' -H "authorization: Bearer $RELAY_OWNER_TOKEN")
    mcp_cmd "$(echo "$out" | field handle)" "$(echo "$out" | field agent_token)"
    ;;
  agents)
    need_owner
    curl -sS "$RELAY_URL/v1/agents" -H "authorization: Bearer $RELAY_OWNER_TOKEN"
    ;;
  link-github)
    need_owner
    [ $# -eq 2 ] || { echo "usage: relay.sh link-github <github-username>"; exit 1; }
    post /v1/owners/github "{\"login\":\"$2\"}" -H "authorization: Bearer $RELAY_OWNER_TOKEN"
    echo
    ;;
  *)
    sed -n '2,10p' "$0"; exit 1 ;;
esac
