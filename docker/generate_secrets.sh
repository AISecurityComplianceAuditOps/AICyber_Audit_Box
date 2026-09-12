#!/bin/sh
# Generates a random JWT_SECRET on first container start and persists it to a
# volume-backed file, so it's unique per deployment but stable across
# restarts (a secret that changes on every restart would invalidate every
# logged-in user's session each time the container restarts).
#
# Lives outside src/ deliberately -- auth.py already reads JWT_SECRET from
# the environment (os.environ.get("JWT_SECRET", "...")) with no code change
# needed; this script's only job is to make sure that env var is set to
# something random-and-persisted instead of left at the hardcoded default,
# without touching auth.py itself.
#
# If the operator explicitly set JWT_SECRET in the compose environment
# already, this is a no-op -- an explicit value always wins.

SECRET_FILE="/app/data/jwt_secret.txt"

if [ -n "$JWT_SECRET" ]; then
    echo "[SECRETS] JWT_SECRET already set via environment -- using that."
    exit 0
fi

mkdir -p /app/data

if [ -f "$SECRET_FILE" ]; then
    echo "[SECRETS] Reusing existing persisted JWT_SECRET from $SECRET_FILE."
else
    echo "[SECRETS] No JWT_SECRET provided -- generating a new one and persisting it to $SECRET_FILE."
    python -c "import secrets; print(secrets.token_hex(32))" > "$SECRET_FILE"
fi

# Write to a sourced env file so the parent shell (the CMD chain in
# Dockerfile.app) can pick it up for the uvicorn process that follows.
echo "JWT_SECRET=$(cat "$SECRET_FILE")" > /app/data/.generated_env
