#!/usr/bin/env bash
# Starts the stack inside a codespace. The public verifier runs in the visitor's BROWSER and talks to the log and witnesses directly,
# so it needs their forwarded https URLs (not localhost) and those ports must be public (private ones answer cross-origin fetches with a login redirect).
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -n "${CODESPACE_NAME:-}" ]; then
  u() { echo "https://${CODESPACE_NAME}-$1.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"; }
  export PUBLIC_LOG_URL="$(u 4000)" PUBLIC_WITNESS_URLS="$(u 4101),$(u 4102),$(u 4103)"
fi
docker compose up -d --build
for _ in $(seq 60); do curl -sf -o /dev/null http://localhost:4000/entries && break; sleep 2; done
if [ -n "${CODESPACE_NAME:-}" ]; then
  gh codespace ports visibility 4000:public 4101:public 4102:public 4103:public -c "$CODESPACE_NAME" \
    || echo "could not make ports 4000 and 4101-4103 public: the Verify page needs them (Ports tab, right-click, Port Visibility, Public)"
fi
echo "Quorum is up: open port 3000 in the Ports tab (the dashboard)."
