#!/usr/bin/env bash
# Local NetCrawl test environment (loopback pilot only).
#
#   ./testenv.sh up       start everything and set up admin, crawler and agent
#   ./testenv.sh job      create a test job (the agent picks it up within 60 s)
#   ./testenv.sh scan     create a test job and run the agent once right away
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

compose() { docker compose --env-file "$ENVFILE" "$@"; }
server() { compose run --rm -T server "$@"; }
port() { grep '^NETCRAWL_PORT=' "$ENVFILE" | cut -d= -f2; }
target_port() { grep '^NETCRAWL_TARGET_PORT=' "$ENVFILE" | cut -d= -f2; }
rand() { head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24; }

need_env() {
  [[ -f $ENVFILE ]] || { echo "Not set up yet, run: ./testenv.sh up" >&2; exit 1; }
}

cmd_up() {
  command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
  mkdir -p "$DATA"
  chmod 700 "$DATA"
  if [[ ! -f $ENVFILE ]]; then
    umask 077
    {
      echo "NETCRAWL_DB_PASSWORD=$(rand)"
      echo "NETCRAWL_PORT=${NETCRAWL_PORT:-8080}"
      echo "NETCRAWL_TARGET_PORT=${NETCRAWL_TARGET_PORT:-18081}"
    } > "$ENVFILE"
    umask 022
  fi

  echo "==> Building images and starting database, server and test target"
  compose up -d --build db server target

  echo -n "==> Waiting for the server "
  for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$(port)/healthz" >/dev/null; then echo " ok"; break; fi
    echo -n "."; sleep 1
  done
  curl -sf "http://127.0.0.1:$(port)/healthz" >/dev/null || { echo; echo "Server did not start, see: ./testenv.sh logs" >&2; exit 1; }

  if [[ ! -f $DATA/admin-password.txt ]]; then
    echo "==> Setting the admin password"
    (umask 077; rand > "$DATA/admin-password.txt")
    server admin set-password --username admin < "$DATA/admin-password.txt" >/dev/null 2>&1
  fi

  if [[ ! -f $DATA/agent.secret ]]; then
    echo "==> Registering crawler pilot-1"
    out=$(server crawler add --id pilot-1 --allow 127.0.0.1/32 --max-hosts 1)
    (umask 077; printf '%s\n' "$(printf '%s\n' "$out" | tail -n 1)" > "$DATA/agent.secret")
  fi

  cat > "$DATA/agent.json" <<JSON
{
  "version": 1,
  "crawler_id": "pilot-1",
  "server_url": "http://127.0.0.1:$(port)",
  "secret_file": "agent.secret",
  "polling": { "interval_seconds": 60 },
  "limits": { "allow": ["127.0.0.1/32"], "max_hosts": 1 },
  "lock_file": "agent.lock"
}
JSON

  echo "==> Starting the crawler (polls every 60 s)"
  compose up -d --build agent

  cat <<INFO

Test environment is running.

  Web UI / API   http://127.0.0.1:$(port)   (user admin, password: $(cat "$DATA/admin-password.txt"))
  Scan target    http://127.0.0.1:$(target_port)   (tiny web server, port $(target_port) open)
  Crawler        pilot-1, scans only 127.0.0.1

Next steps:
  ./testenv.sh scan     create a job and scan right away
  ./testenv.sh result   show the result
  ./testenv.sh login    log in to the admin API
  ./testenv.sh down     remove everything
INFO
}

create_job() {
  server job create --crawler pilot-1 --target 127.0.0.1/32 --ports "22,80,443,$(target_port),$(( $(target_port) + 1 ))"
}

cmd_job() { need_env; create_job; echo "The crawler picks it up within 60 s. Then: ./testenv.sh result"; }

cmd_scan() {
  need_env
  create_job
  echo "==> Running the crawler once"
  # The background crawler holds the lock; pause it for the one-off run.
  compose stop agent >/dev/null 2>&1 || true
  compose run --rm agent --config /data/agent.json --once || true
  compose start agent >/dev/null 2>&1 || true
  cmd_result
}

cmd_status() {
  need_env
  echo "== Crawlers"; server crawler list
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
  status) cmd_status ;;
  result) cmd_result ;;
  login) cmd_login ;;
  logs) cmd_logs ;;
  down) cmd_down ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
