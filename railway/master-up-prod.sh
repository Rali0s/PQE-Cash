#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROJECT_NAME="${PROJECT_NAME:-bluearc-live-testnet-prod}"
WORKSPACE="${WORKSPACE:-}"
ENVIRONMENT="${ENVIRONMENT:-production}"
PROJECT_ID="${PROJECT_ID:-}"

RELAYER_ENV_FILE="${RELAYER_ENV_FILE:-$SCRIPT_DIR/relayer.env.production.template}"
WEB_ENV_FILE="${WEB_ENV_FILE:-$SCRIPT_DIR/web.env.production.template}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

log() {
  printf "[railway-prod] %s\n" "$*"
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required env: $name" >&2
    exit 1
  fi
}

require_cmd railway
require_cmd bash

# Required production secrets/URLs (do not commit values)
require_env SIGNER_SERVICE_URL
require_env SIGNER_ADDRESS
require_env CORS_ORIGIN
require_env RELAYER_PUBLIC_URL

if ! railway whoami >/dev/null 2>&1; then
  echo "Railway CLI is not authenticated. Run: railway login" >&2
  exit 1
fi

log "Bootstrapping services and databases with base template"
PROJECT_NAME="$PROJECT_NAME" \
WORKSPACE="$WORKSPACE" \
ENVIRONMENT="$ENVIRONMENT" \
PROJECT_ID="$PROJECT_ID" \
RELAYER_ENV_FILE="$RELAYER_ENV_FILE" \
WEB_ENV_FILE="$WEB_ENV_FILE" \
DEPLOY=false \
"$SCRIPT_DIR/master-up.sh"

log "Applying strict production variables"
railway variable set --service relayer "SIGNER_MODE=remote" --skip-deploys >/dev/null
railway variable set --service relayer "SIGNER_SERVICE_URL=$SIGNER_SERVICE_URL" --skip-deploys >/dev/null
railway variable set --service relayer "SIGNER_ADDRESS=$SIGNER_ADDRESS" --skip-deploys >/dev/null
railway variable set --service relayer "CORS_ORIGIN=$CORS_ORIGIN" --skip-deploys >/dev/null
railway variable set --service relayer "ALLOW_INSECURE_HTTP=false" --skip-deploys >/dev/null
railway variable set --service relayer "RUNTIME_POOL_VERSION=v2" --skip-deploys >/dev/null
railway variable set --service relayer "PROOF_VERSION_REQUIRED=bluearc-v2" --skip-deploys >/dev/null

if [[ -n "${SIGNER_SERVICE_API_KEY:-}" ]]; then
  railway variable set --service relayer "SIGNER_SERVICE_API_KEY=$SIGNER_SERVICE_API_KEY" --skip-deploys >/dev/null
fi
if [[ -n "${POSTGRES_URL:-}" ]]; then
  railway variable set --service relayer "POSTGRES_URL=$POSTGRES_URL" --skip-deploys >/dev/null
fi
if [[ -n "${REDIS_URL:-}" ]]; then
  railway variable set --service relayer "REDIS_URL=$REDIS_URL" --skip-deploys >/dev/null
fi

railway variable set --service web "VITE_RELAYER_URL=$RELAYER_PUBLIC_URL" --skip-deploys >/dev/null
railway variable set --service web "VITE_POOL_ADDRESS=0xBeBE31Bf60f55CfE7caC13162e88a628eB637667" --skip-deploys >/dev/null
railway variable set --service web "VITE_POOL_VERSION=v2" --skip-deploys >/dev/null
railway variable set --service web "VITE_PROOF_VERSION=bluearc-v2" --skip-deploys >/dev/null

log "Deploying relayer and web"
railway up --service relayer --path-as-root --detach "$REPO_ROOT/relayer" >/dev/null
railway up --service web --path-as-root --detach "$REPO_ROOT/web" >/dev/null

log "Production bootstrap submitted"
log "Run: railway service status --all"
log "Verify: relayer /health has chainId=11155111, poolVersion=v2, requiredProofVersion=bluearc-v2"
