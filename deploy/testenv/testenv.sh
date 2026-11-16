#!/usr/bin/env bash
# Local NetCrawl test environment (loopback pilot only).
#
#   ./testenv.sh up       start everything and set up admin, crawler and agent
#   ./testenv.sh scan     run host discovery and port scan of the test network right away
#   ./testenv.sh events   show inventory events (changes)
#   ./testenv.sh hosts    show the inventory
#   ./testenv.sh job      create a single test job (the agent picks it up within 60 s)
#   ./testenv.sh status   show crawlers and jobs
#   ./testenv.sh result   show the newest job with its result
#   ./testenv.sh login    show how to log in to the admin API
#   ./testenv.sh logs     follow server and agent logs
#   ./testenv.sh down     stop and delete everything (database included)
set -euo pipefail
cd "$(dirname "$0")"

DATA=./data
ENVFILE=./.env
export HOST_UID=$(id -u) HOST_GID=$(id -g)
# Shown in the web UI; the git state of this checkout unless set.
export NETCRAWL_VERSION=${NETCRAWL_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}

compose() { docker compose --env-file "$ENVFILE" "$@"; }
server() { compose run --rm -T server "$@"; }
port() { grep '^NETCRAWL_PORT=' "$ENVFILE" | cut -d= -f2; }
target_port() { grep '^NETCRAWL_TARGET_PORT=' "$ENVFILE" | cut -d= -f2; }
rand() { head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24; }

# healthy checks the server from the host. --noproxy: a configured
# http_proxy must not intercept requests to 127.0.0.1.
healthy() { curl -sf --noproxy '*' --max-time 2 "http://127.0.0.1:$(port)/healthz" >/dev/null 2>&1; }

diagnose() {
  echo >&2
  echo "Server is not reachable on http://127.0.0.1:$(port)." >&2
  echo "--- container state" >&2
  compose ps -a >&2 || true
  echo "--- last server log lines" >&2
  compose logs --tail 40 server >&2 || true
  echo "--- what is listening on the server and database ports" >&2
  for p in "$(port)" "$(grep '^NETCRAWL_DB_PORT=' "$ENVFILE" | cut -d= -f2)"; do
    [[ -n $p ]] || continue
    echo "port $p:" >&2
    (command -v ss >/dev/null && ss -ltnp 2>/dev/null | grep -E ":$p\b") >&2 || echo "  (ss not available or nothing listening)" >&2
  done
  echo >&2
  echo "Please send this output. To retry: ./testenv.sh down && ./testenv.sh up" >&2
}

need_env() {
  [[ -f $ENVFILE ]] || { echo "Not set up yet, run: ./testenv.sh up" >&2; exit 1; }
}

cmd_up() {
  command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
  command -v curl >/dev/null || { echo "curl is required (e.g. apt install curl)" >&2; exit 1; }
  docker compose version >/dev/null 2>&1 || { echo "docker compose (v2) is required" >&2; exit 1; }
  mkdir -p "$DATA"
  chmod 700 "$DATA"
  if [[ ! -f $ENVFILE ]]; then
    umask 077
    {
      echo "NETCRAWL_DB_PASSWORD=$(rand)"
      echo "NETCRAWL_PORT=${NETCRAWL_PORT:-8080}"
      echo "NETCRAWL_TARGET_PORT=${NETCRAWL_TARGET_PORT:-18081}"
      echo "NETCRAWL_DB_PORT=${NETCRAWL_DB_PORT:-55432}"
    } > "$ENVFILE"
    umask 022
  fi

  echo "==> Building images and starting database, server and test target"
  compose up -d --build db server target

  echo -n "==> Waiting for the server "
  for _ in $(seq 1 90); do
    if healthy; then echo " ok"; break; fi
    if [[ $(compose ps -a --format '{{.State}}' server 2>/dev/null) == exited ]]; then break; fi
    echo -n "."; sleep 1
  done
  healthy || { diagnose; exit 1; }

  if [[ ! -f $DATA/admin-password.txt ]]; then
    echo "==> Setting the admin password"
    (umask 077; rand > "$DATA/admin-password.txt")
    server admin set-password --username admin < "$DATA/admin-password.txt" >/dev/null 2>&1
  fi

  if [[ ! -f $DATA/agent.secret ]]; then
    echo "==> Registering crawler pilot-1 (released for 127.0.0.0/29)"
    out=$(server crawler add --id pilot-1 --allow 127.0.0.0/29 --max-hosts 8)
    (umask 077; printf '%s\n' "$(printf '%s\n' "$out" | tail -n 1)" > "$DATA/agent.secret")
  fi

  cat > "$DATA/agent.json" <<JSON
{
  "version": 1,
  "crawler_id": "pilot-1",
  "server_url": "http://127.0.0.1:$(port)",
  "secret_file": "agent.secret",
  "polling": { "interval_seconds": 60 },
  "limits": { "allow": ["127.0.0.0/29"], "max_hosts": 8 },
  "lock_file": "agent.lock"
}
JSON

  if ! server network list | grep -q Testnetz; then
    echo "==> Creating network Testnetz (127.0.0.1-127.0.0.4, 127.0.0.4 denied)"
    tp=$(target_port)
    server network add --crawler pilot-1 --name Testnetz --target 127.0.0.1-127.0.0.4 --deny 127.0.0.4 \
      --discovery-ports "22,80,443,$tp" --scan-ports "22,80,443,8080,$tp,$((tp + 1))" \
      --discovery-interval 5m --portscan-interval 1h --no-reverse-dns >/dev/null
  fi
  mkdir -p "$DATA/events"

  echo "==> Starting the crawler (polls every 60 s)"
  compose up -d --build agent

  cat <<INFO

Test environment is running.

  Web UI / API   http://127.0.0.1:$(port)   (user admin, password: $(cat "$DATA/admin-password.txt"))
  Scan target    http://127.0.0.1:$(target_port)   (tiny web server, port $(target_port) open)
  Crawler        pilot-1, released for 127.0.0.0/29
  Network        Testnetz: 127.0.0.1-127.0.0.4 (127.0.0.4 denied), discovery every 5 min, port scan hourly
  Event log      deploy/testenv/data/events/

Next steps:
  ./testenv.sh scan     discovery + port scan right away
  ./testenv.sh events   show changes (try: start/stop something on 127.0.0.1:$(( $(target_port) + 1 )), then scan)
  ./testenv.sh login    log in to the admin API
  ./testenv.sh down     remove everything
INFO
}

create_job() {
  server job create --crawler pilot-1 --target 127.0.0.1/32 --ports "22,80,443,$(target_port),$(( $(target_port) + 1 ))"
}

cmd_job() { need_env; create_job; echo "The crawler picks it up within 60 s. Then: ./testenv.sh result"; }

run_agent_once() {
  compose run --rm agent --config /data/agent.json --once >/dev/null 2>&1 || true
}

cmd_scan() {
  need_env
  id=$(server network list | awk '$2 == "Testnetz" {print $1}')
  [[ -n $id ]] || { echo "Testnetz not found, run: ./testenv.sh up" >&2; exit 1; }
  # The background crawler holds the lock; pause it for the one-off runs.
  compose stop agent >/dev/null 2>&1 || true
  echo "==> Host discovery"
  server network scan --id "$id" --kind discovery >/dev/null || true
  run_agent_once
  echo "==> Port scan"
  server network scan --id "$id" --kind ports >/dev/null || true
  run_agent_once
  compose start agent >/dev/null 2>&1 || true
  cmd_hosts
  echo
  cmd_events
}

cmd_hosts() { need_env; echo "== Inventory"; server hosts; }
cmd_events() { need_env; echo "== Events (changes, newest first)"; server events --limit 20 --baseline; }

cmd_status() {
  need_env
  echo "== Crawlers"; server crawler list
  echo; echo "== Networks"; server network list
  echo; echo "== Jobs"; server job list --limit 10
}

cmd_result() {
  need_env
  id=$(server job list --limit 1 | awk 'NR==2 {print $1}')
  [[ -n $id ]] || { echo "No jobs yet, run: ./testenv.sh scan"; return; }
  server job show "$id"
}

cmd_login() {
  need_env
  cat <<INFO
Browser: http://127.0.0.1:$(port)  –  user admin, password: $(cat "$DATA/admin-password.txt")

API with curl (stores the session cookie in cookies.txt):

  curl -c cookies.txt -H 'Content-Type: application/json' \\
    -d "{\"username\":\"admin\",\"password\":\"\$(cat $DATA/admin-password.txt)\"}" \\
    http://127.0.0.1:$(port)/api/v1/admin/login

Then for example:

  curl -b cookies.txt http://127.0.0.1:$(port)/api/v1/admin/crawlers
  curl -b cookies.txt http://127.0.0.1:$(port)/api/v1/admin/jobs
  curl -b cookies.txt http://127.0.0.1:$(port)/api/v1/admin/audit
INFO
}

cmd_logs() { need_env; compose logs -f server agent; }

cmd_down() {
  [[ -f $ENVFILE ]] && compose down -v --remove-orphans || true
  rm -rf "$DATA" "$ENVFILE"
  echo "Test environment removed."
}

case "${1:-}" in
  up) cmd_up ;;
  job) cmd_job ;;
  scan) cmd_scan ;;
  hosts) cmd_hosts ;;
  events) cmd_events ;;
  status) cmd_status ;;
  result) cmd_result ;;
  login) cmd_login ;;
  logs) cmd_logs ;;
  down) cmd_down ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
