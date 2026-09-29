#!/bin/sh
# AICyberAuditBox -- applies an LLM startup-settings update (Linux).
#
#   sudo sh apply_llm_config.sh
#
# The Linux twin of apply_llm_config.ps1 (which apply_llm_config.bat runs on
# Windows). The model weights are not in this package and do not need to be:
# the new settings are a few KB of shell script, layered onto the LLM image
# this machine already holds, so the ~12.6GB of weights are inherited rather
# than transferred. The rebuild takes seconds and needs no internet.
#
# An installation that pulls from Artifact Registry is updated by setting
# LLM_VERSION in its .env and running setup_registry.sh; this says so and stops.

HERE=$(cd "$(dirname "$0")" && pwd)

COMPOSE_CHANGED=0
COMPOSE=""
COMPOSE_BACKUP=""

say()  { printf '  %s\n' "$*"; }
step() { printf '\n%s\n' "$*"; }

die() {
    printf '\n  STOPPED: %s\n\n' "$*"
    if [ "$COMPOSE_CHANGED" = 1 ]; then
        say "The configuration WAS updated before this failed. To put it back:"
        say "    cp \"$COMPOSE_BACKUP\" \"$COMPOSE\""
        say "    docker compose -f \"$COMPOSE\" up -d"
    else
        say "Nothing has been changed."
    fi
    say ""
    say "Send this message to your supplier."
    say ""
    exit 1
}

current_version() {
    sed -nE "s/.*image:[[:space:]]*$2:([0-9][0-9.]*).*/\1/p" "$1" | head -1
}

versions_of() {
    grep -o "$2:[0-9][0-9.]*" "$1" 2>/dev/null | tr '\n' ','
}

echo ""
echo "==========================================================="
echo "  AICyberAuditBox - LLM Startup Settings Update"
echo "==========================================================="

for need in Dockerfile.llm.rebase docker/llm-entrypoint.sh; do
    [ -f "$HERE/$need" ] || die "$need is missing from this folder."
done
# -U: read the bytes as they are. Without it GNU grep on Windows (Git Bash)
# drops the CRs before matching; on Linux it changes nothing.
if grep -qU "$(printf '\r')" "$HERE/docker/llm-entrypoint.sh"; then
    die "docker/llm-entrypoint.sh has Windows line endings and would not run.
           Extract the zip again without converting line endings."
fi

step "[1/4] Checking Docker"
docker info >/dev/null 2>&1 || die "Docker is not running, or this user may not use it. Run with sudo."
say "Docker is running."

# ------------------------------------------------- find the current install
step "[2/4] Finding your installation"
PROJECT=""
FOUND=$(docker compose ls -a --format json 2>/dev/null | tr '}' '\n' | while IFS= read -r entry; do
    cfg=$(printf '%s' "$entry" | sed -n 's/.*"ConfigFiles":"\([^"]*\)".*/\1/p' | cut -d, -f1)
    name=$(printf '%s' "$entry" | sed -n 's/.*"Name":"\([^"]*\)".*/\1/p')
    if [ -n "$cfg" ] && [ -f "$cfg" ] && grep -q "aicyberauditbox" "$cfg"; then
        printf '%s|%s\n' "$name" "$cfg"
        break
    fi
done)
[ -n "$FOUND" ] || die "could not find the docker-compose.yml this installation runs from.
           Start the product once, then run this again."
PROJECT=${FOUND%%|*}
COMPOSE=${FOUND#*|}
say "Compose file: $COMPOSE"

BASE=$(current_version "$COMPOSE" "aicyberauditbox-llm")
if [ -z "$BASE" ]; then
    if grep -q "docker.pkg.dev" "$COMPOSE"; then
        die "this installation pulls its images from Artifact Registry. In $(dirname "$COMPOSE"):
               set LLM_VERSION in .env to the new version
               sudo sh setup_registry.sh"
    fi
    die "no aicyberauditbox-llm image line in the compose file."
fi
say "Current LLM : $BASE"
docker image inspect "aicyberauditbox-llm:$BASE" >/dev/null 2>&1 \
    || die "aicyberauditbox-llm:$BASE is named in the compose file but is not on this machine."

# The new tag: the last number of the base, plus one -- a settings change is
# visibly a new version without anyone having to invent one.
NEWV=$(printf '%s' "$BASE" | awk -F. -v OFS=. '{ $NF = $NF + 1; print }')
say "New LLM     : $NEWV  (settings only; weights inherited)"

# ----------------------------------------------------------------- rebuild
step "[3/4] Rebuilding on top of the image you already have (seconds)"
( cd "$HERE" && docker build -f Dockerfile.llm.rebase \
      --build-arg LLM_BASE_IMAGE="aicyberauditbox-llm:$BASE" \
      -t "aicyberauditbox-llm:$NEWV" . ) || die "the rebuild failed."
# The embedding server is the same image under a second tag.
docker tag "aicyberauditbox-llm:$NEWV" "aicyberauditbox-llm-embed:$NEWV" \
    || die "could not tag the embedding image."
say "Built aicyberauditbox-llm:$NEWV and -llm-embed:$NEWV"

# ----------------------------------------------------------------- compose
step "[4/4] Switching over and restarting the model servers"
BEFORE="$(versions_of "$COMPOSE" aicyberauditbox-app)|$(versions_of "$COMPOSE" aicyberauditbox-shakthidb)"
COMPOSE_BACKUP="$COMPOSE.before-llm-$NEWV.bak"
cp "$COMPOSE" "$COMPOSE_BACKUP" || die "cannot back up the compose file."

TMP="$COMPOSE.updating"
base_re=$(printf '%s' "$BASE" | sed 's/\./\\./g')
sed -E -e "s/(aicyberauditbox-llm):$base_re([^0-9.]|\$)/\1:$NEWV\2/g" \
       -e "s/(aicyberauditbox-llm-embed):[0-9][0-9.]*/\1:$NEWV/g" "$COMPOSE" > "$TMP" \
    || { rm -f "$TMP"; die "could not rewrite the compose file."; }
cat "$TMP" > "$COMPOSE"
rm -f "$TMP"

AFTER="$(versions_of "$COMPOSE" aicyberauditbox-app)|$(versions_of "$COMPOSE" aicyberauditbox-shakthidb)"
if [ "$(current_version "$COMPOSE" aicyberauditbox-llm)" != "$NEWV" ] \
        || [ "$(current_version "$COMPOSE" aicyberauditbox-llm-embed)" != "$NEWV" ]; then
    cat "$COMPOSE_BACKUP" > "$COMPOSE"
    die "the compose file did not update as expected. It has been restored from the backup."
fi
if [ "$BEFORE" != "$AFTER" ]; then
    cat "$COMPOSE_BACKUP" > "$COMPOSE"
    die "the application or database line would have been changed. Restored from the backup."
fi
COMPOSE_CHANGED=1

( cd "$(dirname "$COMPOSE")" && docker compose -f "$COMPOSE" ${PROJECT:+-p "$PROJECT"} up -d llm llm-embed ) \
    || die "the model servers did not restart. The message above says why."

RUNNING=$(docker inspect --format '{{.Config.Image}}' aicyberauditbox_llm 2>/dev/null)
[ "$RUNNING" = "aicyberauditbox-llm:$NEWV" ] \
    || die "the LLM is still running ${RUNNING:-nothing}, not aicyberauditbox-llm:$NEWV."

echo ""
echo "==========================================================="
say "Done. LLM now running aicyberauditbox-llm:$NEWV"
echo "==========================================================="
echo ""
say "The model reloads on start -- allow 3-5 minutes before running an audit."
say "Check it sized itself correctly:"
say "  docker compose -f \"$COMPOSE\" logs llm | grep 'LLM ENTRYPOINT'"
echo ""
say "To roll back:"
say "  cp \"$COMPOSE_BACKUP\" \"$COMPOSE\""
say "  docker compose -f \"$COMPOSE\" up -d llm llm-embed"
echo ""
