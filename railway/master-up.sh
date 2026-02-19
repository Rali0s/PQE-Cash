#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROJECT_NAME="${PROJECT_NAME:-bluearc-testnet}"
WORKSPACE="${WORKSPACE:-}"
ENVIRONMENT="${ENVIRONMENT:-}"
PROJECT_ID="${PROJECT_ID:-}"
RELAYER_ENV_FILE="${RELAYER_ENV_FILE:-$SCRIPT_DIR/relayer.env.template}"
WEB_ENV_FILE="${WEB_ENV_FILE:-$SCRIPT_DIR/web.env.template}"
DEPLOY="${DEPLOY:-true}"

log() {
  printf "[railway-master] %s\n" "$*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require_cmd railway
require_cmd node

if ! railway whoami >/dev/null 2>&1; then
  echo "Railway CLI is not authenticated. Run: railway login" >&2
  exit 1
fi

link_or_init_project() {
  if railway status --json >/dev/null 2>&1; then
    log "Using existing linked Railway project"
    return
  fi

  if [[ -n "$PROJECT_ID" ]]; then
    log "Linking to existing project id: $PROJECT_ID"
    railway link --project "$PROJECT_ID" ${WORKSPACE:+--workspace "$WORKSPACE"} >/dev/null
  else
    log "Initializing new project: $PROJECT_NAME"
    railway init --name "$PROJECT_NAME" ${WORKSPACE:+--workspace "$WORKSPACE"} >/dev/null
  fi

  if [[ -n "$ENVIRONMENT" ]]; then
    log "Linking environment: $ENVIRONMENT"
    railway environment link "$ENVIRONMENT" >/dev/null
  fi
}

service_exists() {
  local target="$1"
  local json
  json="$(railway service status --all --json 2>/dev/null || echo '{}')"
  node -e '
const fs = require("fs");
const target = process.argv[1].toLowerCase();
const raw = fs.readFileSync(0, "utf8");
let parsed;
try { parsed = JSON.parse(raw); } catch { process.exit(1); }
const seen = new Set();
function walk(x) {
  if (!x || typeof x !== "object") return;
  if (Array.isArray(x)) return x.forEach(walk);
  const name = typeof x.name === "string" ? x.name.toLowerCase() : "";
  if (name) seen.add(name);
  for (const v of Object.values(x)) walk(v);
}
walk(parsed);
process.exit(seen.has(target) ? 0 : 1);
' "$target" <<<"$json"
}

database_exists() {
  local target="$1"
  local json
  json="$(railway service status --all --json 2>/dev/null || echo '{}')"
  node -e '
const fs = require("fs");
const target = process.argv[1].toLowerCase();
const raw = fs.readFileSync(0, "utf8");
let parsed;
try { parsed = JSON.parse(raw); } catch { process.exit(1); }
const names = [];
function walk(x) {
  if (!x || typeof x !== "object") return;
  if (Array.isArray(x)) return x.forEach(walk);
  if (typeof x.name === "string") names.push(x.name.toLowerCase());
  for (const v of Object.values(x)) walk(v);
}
walk(parsed);
process.exit(names.some((n) => n.includes(target)) ? 0 : 1);
' "$target" <<<"$json"
}

ensure_service() {
  local name="$1"
  if service_exists "$name"; then
    log "Service exists: $name"
  else
    log "Creating service: $name"
    railway add --service "$name" >/dev/null
  fi
}

ensure_database() {
  local db="$1"
  if database_exists "$db"; then
    log "Database plugin exists: $db"
  else
    log "Creating database plugin: $db"
    railway add --database "$db" >/dev/null || true
  fi
}

apply_env_file() {
  local service="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    log "Skipping env load for $service (file not found): $file"
    return
  fi

  log "Applying env vars to $service from $(basename "$file")"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" != *=* ]]; then
      continue
    fi

    key="${line%%=*}"
    value="${line#*=}"

    key="$(echo "$key" | xargs)"
    value="$(echo "$value" | sed 's/^ *//;s/ *$//')"

    [[ -z "$key" ]] && continue
    if [[ "$value" == REPLACE_WITH_* ]]; then
      log "Skipping placeholder variable $key"
      continue
    fi
    if [[ -z "$value" ]]; then
      log "Skipping empty variable $key"
      continue
    fi

    railway variable set --service "$service" "$key=$value" --skip-deploys >/dev/null
  done <"$file"
}

deploy_service() {
  local service="$1"
  local path="$2"
  log "Deploying service '$service' from path '$path'"
  railway up --service "$service" --path-as-root --detach "$path" >/dev/null
}

link_or_init_project

ensure_service "relayer"
ensure_service "web"
ensure_database "postgres"
ensure_database "redis"

apply_env_file "relayer" "$RELAYER_ENV_FILE"
apply_env_file "web" "$WEB_ENV_FILE"

if [[ "$DEPLOY" == "true" ]]; then
  deploy_service "relayer" "$REPO_ROOT/relayer"
  deploy_service "web" "$REPO_ROOT/web"
  log "Deployment submitted for relayer + web"
  log "Tip: run 'railway service status --all' to watch rollout"
else
  log "DEPLOY=false, skipped 'railway up' step"
fi
