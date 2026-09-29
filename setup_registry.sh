#!/bin/sh
# AICyberAuditBox -- install, or update, from Artifact Registry.
#
#   First install:  sudo sh setup_registry.sh /path/to/artifact-key.json
#   Update:         set APP_VERSION in .env, then  sudo sh setup_registry.sh
#
# Run it in the folder that holds docker-compose.registry.yml (for example
# /opt/aicyberauditbox). It logs Docker in with the read-only JSON key, creates
# .env with a random database password the first time, pulls the images,
# starts the stack and waits until the application answers.
#
# Needs: Docker Engine with the compose plugin, and internet access to
# asia-south1-docker.pkg.dev. Nothing is built on this machine.
set -e

COMPOSE="docker-compose.registry.yml"
REGISTRY_HOST="https://asia-south1-docker.pkg.dev"
KEY="$1"

cd "$(dirname "$0")"

say() { printf '%s\n' "$*"; }
fail() { say ""; say "  [X] $*"; exit 1; }

say "==========================================================================="
say "  AICyberAuditBox -- install / update from Artifact Registry"
say "==========================================================================="

command -v docker >/dev/null 2>&1 || fail "Docker is not installed. Install Docker Engine and the compose plugin first."
docker compose version >/dev/null 2>&1 || fail "The Docker compose plugin is missing (docker-compose-plugin)."
docker info >/dev/null 2>&1 || fail "Docker is not running, or this user may not use it. Run with sudo."
[ -f "$COMPOSE" ] || fail "$COMPOSE is not in $(pwd). Put this script beside it."

# 1. Log in with the read-only key. The key file is read, never copied.
if [ -n "$KEY" ]; then
    [ -f "$KEY" ] || fail "Key file not found: $KEY"
    say "---> Logging in to the registry"
    docker login -u _json_key --password-stdin "$REGISTRY_HOST" < "$KEY" >/dev/null \
        || fail "Login refused. Check the key file (it must be the JSON key you were given)."
    say "  [ok] logged in"
fi

# 2. .env -- once. The database is created with this password and only ever
#    opens with it, so an existing database is never given a new one.
FIRST_INSTALL=0
if [ ! -f .env ]; then
    FIRST_INSTALL=1
    if docker volume ls -q | grep -q "_pgdata$"; then
        fail ".env is missing but a database volume already exists. Restore the .env it was created with -- a new password would lock the application out of it."
    fi
    say "---> Creating .env (database password generated here, never sent anywhere)"
    PW=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
    umask 077
    cat > .env <<EOF
POSTGRES_PASSWORD=$PW
# Versions to run. An update: change APP_VERSION and run this script again.
APP_VERSION=1.2.4
LLM_VERSION=1.2
DB_VERSION=1.1
EOF
    chmod 600 .env
    say "  [ok] .env created -- keep a copy of it with your backups"
fi

# 3. Check, pull, start.
say "---> Checking the configuration"
docker compose -f "$COMPOSE" config -q || fail "The configuration has an error (see above)."
say "---> Downloading images (first time: about 15 GB)"
docker compose -f "$COMPOSE" pull || fail "Download failed. Check internet access and the login."
say "---> Starting"
docker compose -f "$COMPOSE" up -d

# 4. Wait for the application. The model server loads ~13 GB of weights first.
say "---> Waiting for the application (the AI model takes a few minutes to load)"
i=0
until curl -fs -o /dev/null http://localhost:8000/; do
    i=$((i + 1))
    [ "$i" -gt 120 ] && fail "The application did not answer after 10 minutes. See: docker compose -f $COMPOSE logs app"
    sleep 5
done

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
say ""
say "  [ok] AICyberAuditBox is running."
say "       Open: http://${IP:-SERVER-IP}:8000"

# 5. First install only: the administrator's password. The application makes a
#    random one on its first start and prints it once, in its own log.
if [ "$FIRST_INSTALL" = 1 ]; then
    ADMIN_PW=$(docker compose -f "$COMPOSE" logs --no-color app 2>/dev/null \
        | grep -A2 "generated a random admin password" | tail -1 \
        | sed 's/^[^|]*|//; s/^[[:space:]]*//; s/[[:space:]]*$//')
    if [ -n "$ADMIN_PW" ]; then
        umask 077
        printf 'AICyberAuditBox first login\n  address:  http://%s:8000\n  username: admin\n  password: %s\nThen scan the QR code with an authenticator app on your phone.\nKeep this safe, then delete this file.\n' \
            "${IP:-SERVER-IP}" "$ADMIN_PW" > FIRST-LOGIN.txt
        chmod 600 FIRST-LOGIN.txt
        say ""
        say "  ================================================================"
        say "   ADMINISTRATOR LOGIN -- WRITE THIS DOWN NOW"
        say "     username:  admin"
        say "     password:  $ADMIN_PW"
        say "   (also saved in $(pwd)/FIRST-LOGIN.txt -- delete it once stored safely)"
        say "  ================================================================"
    fi
fi
docker compose -f "$COMPOSE" logs llm 2>/dev/null | grep "LLM ENTRYPOINT\] Detected" | tail -1 | sed 's/^.*\] /       AI model: /'
say ""
say "  Status:  docker compose -f $COMPOSE ps"
say "  Logs:    docker compose -f $COMPOSE logs -f app"
say "  Only port 8000 needs to be reachable from the network."
