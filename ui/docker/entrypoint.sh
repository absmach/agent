#!/bin/sh
set -eu

cat > /usr/share/nginx/html/ui/config.js <<EOF
window.__AGENT_UI_CONFIG__ = {
  gatewayUrl: "${AGENT_UI_GATEWAY_URL:-/gateway}",
  agentId: "${AGENT_UI_AGENT_ID:-}",
  token: "${AGENT_UI_TOKEN:-}"
};
EOF

exec nginx -g 'daemon off;'
