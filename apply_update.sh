#!/bin/sh
# AICyberAuditBox -- applies an update at a customer site (Linux).
#
#   sudo sh apply_update.sh
#
# The Linux twin of apply_update.ps1 (which apply_update.bat runs on Windows),
# step for step. It works out which component the tar beside it is -- the
# application, the LLM or the database -- verifies the download, backs up the
# audit results and the uploaded evidence, loads the image, repoints only that
# component's image lines in the installation's compose file, restarts only
# that component, and proves the new image is the one running.
#
# It does not ask for a path or a version: it finds the installation through
# Docker, and it refuses rather than guesses. Every step of doing this by hand
# has gone wrong somewhere before.
#
# An installation that pulls from Artifact Registry (docker-compose.registry.yml)
# is not updated with a tar: set the version in its .env and run
# setup_registry.sh. This script says so and stops.

HERE=$(cd "$(dirname "$0")" && pwd)

COMPOSE_CHANGED=0
COMPOSE=""
COMPOSE_BACKUP=""

say()  { printf '  %s\n' "$*"; }
step() { printf '\n%s\n' "$*"; }

die() {
    printf '\n  STOPPED: %s\n\n' "$*"
    if [ "$COMPOSE_CHANGED" = 1 ]; then
        say "The configuration WAS updated before this failed."
        say "To put it back exactly as it was:"
        say ""
        say "    cp \"$COMPOSE_BACKUP\" \"$COMPOSE\""
        say "    docker compose -f \"$COMPOSE\" up -d"
        say ""
        say "The previous images are still on this machine, so that"
        say "restores the versions you were running before."
    else
        say "Nothing has been changed."
    fi
    say ""
    say "Send this message to your supplier."
    say ""
    exit 1
}

# The version on an image line, e.g. 1.2.3 for "image: aicyberauditbox-app:1.2.3".
# "aicyberauditbox-llm:" does not match the -llm-embed line: the colon must follow.
current_version() {
    sed -nE "s/.*image:[[:space:]]*$2:([0-9][0-9.]*).*/\1/p" "$1" | head -1
}

# Every version an image name carries anywhere in the file, as one string, so
# a before/after comparison proves the lines this update does not own are
# byte-for-byte what they were.
versions_of() {
    grep -o "$2:[0-9][0-9.]*" "$1" 2>/dev/null | tr '\n' ','
}

echo ""
echo "==========================================================="
echo "  AICyberAuditBox - Update"
echo "==========================================================="
echo ""

# ------------------------------------------------------------ what was sent
TAR=$(ls -t "$HERE"/aicyberauditbox-*.tar 2>/dev/null | head -1)
[ -n "$TAR" ] || die "no aicyberauditbox-<component>-<version>.tar in this folder ($HERE)."
NAME=$(basename "$TAR")
KEY=$(printf '%s' "$NAME" | sed -nE 's/^aicyberauditbox-(app|llm|shakthidb)-([0-9][0-9.]*)\.tar$/\1/p')
NEW=$(printf '%s' "$NAME" | sed -nE 's/^aicyberauditbox-(app|llm|shakthidb)-([0-9][0-9.]*)\.tar$/\2/p')
[ -n "$KEY" ] && [ -n "$NEW" ] || die "cannot tell what $NAME is. Expected a name like aicyberauditbox-app-1.2.4.tar."

# The LLM ships as one image under two tags -- the completion server and the
# embedding server are the same build started with a different LLM_MODE -- so
# both lines move together or the compose names an image this machine lacks.
case "$KEY" in
    app)
        LABEL="Application"; IMAGES="aicyberauditbox-app"; SERVICES="app"
        CONTAINER="aicyberauditbox_app"
        NOTE="The AI model and database are not restarted." ;;
    llm)
        LABEL="LLM (model server)"; IMAGES="aicyberauditbox-llm aicyberauditbox-llm-embed"
        SERVICES="llm llm-embed"; CONTAINER="aicyberauditbox_llm"
        NOTE="The model reloads on start -- allow 3-5 minutes before auditing." ;;
    shakthidb)
        LABEL="Database"; IMAGES="aicyberauditbox-shakthidb"; SERVICES="shakthidb"
        CONTAINER="shakthidb_service"
        NOTE="Your audit data lives in a Docker volume and is NOT replaced." ;;
esac
FIRST_IMAGE=${IMAGES%% *}

say "Update file : $NAME"
say "Component   : $LABEL"
say "New version : $NEW"

# ------------------------------------------------------------------- docker
step "[1/6] Checking Docker"
docker info >/dev/null 2>&1 || die "Docker is not running, or this user may not use it. Run with sudo."
say "Docker is running."

# ----------------------------------------------------------------- checksum
step "[2/6] Verifying the file arrived intact"
if [ -f "$TAR.sha256" ]; then
    # Written on Windows: upper case, CRLF. Keep only the hex digits.
    EXPECTED=$(tr -dc '0-9a-fA-F' < "$TAR.sha256" | tr 'A-F' 'a-f')
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "$TAR" | awk '{print $1}')
    else
        ACTUAL=$(shasum -a 256 "$TAR" | awk '{print $1}')
    fi
    [ "$EXPECTED" = "$ACTUAL" ] || die "the file is damaged (checksum does not match). Ask for it to be sent again.
           expected $EXPECTED
           actual   $ACTUAL"
    say "Checksum matches."
else
    say "No .sha256 beside the tar -- skipping the integrity check."
fi

# ------------------------------------------------------ find the installation
# Ask Docker where the running stack was started from rather than searching
# the disk: a search finds copies -- an old extracted bundle, a spare folder --
# and the wrong one leads everything afterwards astray.
PROJECT=""
FOUND=$(docker compose ls -a --format json 2>/dev/null | tr '}' '\n' | while IFS= read -r entry; do
    cfg=$(printf '%s' "$entry" | sed -n 's/.*"ConfigFiles":"\([^"]*\)".*/\1/p' | cut -d, -f1)
    name=$(printf '%s' "$entry" | sed -n 's/.*"Name":"\([^"]*\)".*/\1/p')
    if [ -n "$cfg" ] && [ -f "$cfg" ] && grep -q "aicyberauditbox" "$cfg"; then
        printf '%s|%s\n' "$name" "$cfg"
        break
    fi
done)
if [ -n "$FOUND" ]; then
    PROJECT=${FOUND%%|*}
    COMPOSE=${FOUND#*|}
elif [ -f "$HERE/docker-compose.yml" ] && grep -q "aicyberauditbox-" "$HERE/docker-compose.yml"; then
    COMPOSE="$HERE/docker-compose.yml"
fi

if [ -n "$COMPOSE" ] && ! grep -q "image:[[:space:]]*aicyberauditbox-" "$COMPOSE" \
        && grep -q "docker.pkg.dev" "$COMPOSE"; then
    die "this installation pulls its images from Artifact Registry, so it is not
           updated with a tar. In $(dirname "$COMPOSE"):
               set the new version in .env (APP_VERSION / LLM_VERSION / DB_VERSION)
               sudo sh setup_registry.sh"
fi

# ------------------------------------------------------------------- backup
# Taken before anything is touched, because that is the only moment it is worth
# anything. Both halves or neither: the audit results are rows in the database,
# the evidence they cite is files in the app's data volume, and restoring one
# without the other looks like a complete backup and is not one.
step "[3/6] Backing up before anything is changed"
STAMP=$(date +%Y%m%d-%H%M)
if [ -n "$COMPOSE" ]; then BACKUP_BASE=$(dirname "$COMPOSE"); else BACKUP_BASE="$HERE"; fi
BACKUP_ROOT="$BACKUP_BASE/backups"
DB_FILE="$BACKUP_ROOT/db_before_${NEW}_$STAMP.sql"
FILES_DIR="$BACKUP_ROOT/files_before_${NEW}_$STAMP"

DB_STATE=$(docker inspect -f '{{.State.Running}}' shakthidb_service 2>/dev/null)
if [ -z "$DB_STATE" ]; then
    say "The database container does not exist yet, so there is nothing to back up."
    say "This is normal on a site that has not been started."
elif [ "$DB_STATE" != "true" ]; then
    die "the database container is stopped, so its data cannot be backed up.
           Start the product first (docker compose up -d), then run this again."
else
    mkdir -p "$BACKUP_ROOT" || die "cannot create $BACKUP_ROOT."
    say "Audit results -> $(basename "$DB_FILE")"
    # pg_dumpall, not pg_dump of POSTGRES_DB: the compose names "shakthidb",
    # but the audits live in shakthidb_master (and its two replicas).
    ( umask 077; docker exec shakthidb_service pg_dumpall -U postgres -p 15234 > "$DB_FILE" 2>/dev/null ) \
        || die "the database backup failed, so this update has not been applied."
    SIZE=$(wc -c < "$DB_FILE" 2>/dev/null || echo 0)
    [ "$SIZE" -ge 1024 ] 2>/dev/null || die "the database backup came out empty, so this update has not been applied."
    grep -q "shakthidb_master" "$DB_FILE" || die "the database backup does not contain shakthidb_master, which is where the
           audits live. Not proceeding on a backup that would not restore anything.
           Saved for inspection: $DB_FILE"
    say "Audit results saved ($SIZE bytes, includes shakthidb_master)"

    if docker inspect aicyberauditbox_app >/dev/null 2>&1; then
        say "Uploaded evidence -> $(basename "$FILES_DIR")"
        docker cp aicyberauditbox_app:/app/data "$FILES_DIR" >/dev/null 2>&1 && [ -d "$FILES_DIR" ] \
            || die "the evidence backup failed, so this update has not been applied.
           The audit results were saved to $DB_FILE,
           but without the evidence files that backup is not a complete one."
        say "Uploaded evidence saved"
    else
        say "The application container does not exist yet, so there is no uploaded evidence to back up."
    fi
    say "Both are in: $BACKUP_ROOT"
    say "Keep them until the update has been used and looks right."
fi

# --------------------------------------------------------------------- load
step "[4/6] Loading the new image (several minutes, prints nothing while it works)"
docker load -i "$TAR" || die "docker load failed."
for img in $IMAGES; do
    docker image inspect "$img:$NEW" >/dev/null 2>&1 || die "the image did not load. Expected $img:$NEW."
done
say "Loaded: $(for img in $IMAGES; do printf '%s:%s ' "$img" "$NEW"; done)"

# ------------------------------------------------------------------ compose
step "[5/6] Pointing the installation at the new image"
[ -n "$COMPOSE" ] || die "could not find the docker-compose.yml this installation runs from.
           Start the product once, then run this again -- or run this from the install folder."
say "Compose file: $COMPOSE"

UNTOUCHED=""
for other in aicyberauditbox-app aicyberauditbox-llm aicyberauditbox-llm-embed aicyberauditbox-shakthidb; do
    case " $IMAGES " in *" $other "*) ;; *) UNTOUCHED="$UNTOUCHED $other" ;; esac
done

NEEDS_CHANGE=0
for img in $IMAGES; do
    cur=$(current_version "$COMPOSE" "$img")
    [ -n "$cur" ] || die "no $img image line in the compose file."
    [ "$cur" = "$NEW" ] || NEEDS_CHANGE=1
done

if [ "$NEEDS_CHANGE" = 0 ]; then
    say "Already pointing at $NEW -- no change needed."
else
    BEFORE=""
    for other in $UNTOUCHED; do BEFORE="$BEFORE|$(versions_of "$COMPOSE" "$other")"; done

    COMPOSE_BACKUP="$COMPOSE.before-$KEY-$NEW.bak"
    cp "$COMPOSE" "$COMPOSE_BACKUP" || die "cannot back up the compose file."
    say "Backup     : $COMPOSE_BACKUP"

    TMP="$COMPOSE.updating"
    cp "$COMPOSE" "$TMP" || die "cannot write beside the compose file."
    for img in $IMAGES; do
        old=$(current_version "$COMPOSE" "$img")
        old_re=$(printf '%s' "$old" | sed 's/\./\\./g')
        sed -E "s/($img):$old_re([^0-9.]|\$)/\1:$NEW\2/g" "$TMP" > "$TMP.2" && mv "$TMP.2" "$TMP" \
            || { rm -f "$TMP" "$TMP.2"; die "could not rewrite the compose file."; }
    done
    # cat, not mv: keeps the file's owner and permissions.
    cat "$TMP" > "$COMPOSE"
    rm -f "$TMP"

    for img in $IMAGES; do
        if [ "$(current_version "$COMPOSE" "$img")" != "$NEW" ]; then
            cat "$COMPOSE_BACKUP" > "$COMPOSE"
            die "the compose file did not update as expected. It has been restored from the backup."
        fi
    done
    AFTER=""
    for other in $UNTOUCHED; do AFTER="$AFTER|$(versions_of "$COMPOSE" "$other")"; done
    if [ "$BEFORE" != "$AFTER" ]; then
        cat "$COMPOSE_BACKUP" > "$COMPOSE"
        die "an image this update does not own would have been changed. Restored from the backup."
    fi
    COMPOSE_CHANGED=1
    say "Updated to $NEW. Untouched:$UNTOUCHED"
fi

# ------------------------------------------------------------------ restart
step "[6/6] Restarting $LABEL"
# shellcheck disable=SC2086
( cd "$(dirname "$COMPOSE")" && docker compose -f "$COMPOSE" ${PROJECT:+-p "$PROJECT"} up -d $SERVICES ) \
    || die "the service did not restart. The message just above says why.
           A missing POSTGRES_PASSWORD in the .env beside the compose is the
           usual cause, and is nothing to do with this update."

# `docker compose up` reports success whether or not the compose edit saved, so
# the only proof is what the running container is actually built from.
RUNNING=$(docker inspect --format '{{.Config.Image}}' "$CONTAINER" 2>/dev/null)
[ -n "$RUNNING" ] || die "could not read the running container's image."
[ "$RUNNING" = "$FIRST_IMAGE:$NEW" ] || die "$CONTAINER is still running $RUNNING, not $FIRST_IMAGE:$NEW."

echo ""
echo "==========================================================="
say "Update complete. $LABEL is running $RUNNING"
echo "==========================================================="
echo ""
say "$NOTE"
if [ -n "$COMPOSE_BACKUP" ]; then
    echo ""
    say "To roll back:"
    say "  cp \"$COMPOSE_BACKUP\" \"$COMPOSE\""
    say "  docker compose -f \"$COMPOSE\" up -d"
fi
echo ""
