# -*- coding: utf-8 -*-
"""
Docker-only pre-flight check. Lives outside src/ deliberately -- it does not
touch the application codebase at all.

Runs before uvicorn starts inside the app container. Blocks container startup
until Postgres/ShaktiDB is confirmed reachable and exits non-zero (Docker sees
this as a failed/crash-looping container, loud and visible) if it never comes
up within the timeout.

Why this exists instead of relying on src/db/database.py's own connection
logic: that code has a documented SQLite fallback for local/native dev
convenience, which is exactly right for that use case but wrong for a
customer's server -- a silent fallback there means real audit data quietly
lands in a throwaway container-local file with zero indication anything's
wrong. Rather than change that shared file's behavior, this script stops the
container before the application ever gets a chance to run into that branch:
if Postgres isn't reachable, the app process is never started at all.

Connection target matches exactly what src/db/database.py itself expects
(hardcoded localhost:15234 / postgres / ShakthiDB@2026) -- the docker-compose
networking is arranged so "localhost:15234" from inside the app container
genuinely reaches the shakthidb container (see docker-compose.yml).
"""
import os
import sys
import time

DB_HOST = os.environ.get("PGHOST", "localhost")
DB_PORT = int(os.environ.get("PGPORT", "15234"))
DB_USER = os.environ.get("PGUSER", "postgres")
DB_PASSWORD = os.environ.get("PGPASSWORD", "ShakthiDB@2026")
DB_NAME = os.environ.get("PGDATABASE", "shakthidb")
MAX_WAIT_SECONDS = int(os.environ.get("POSTGRES_WAIT_TIMEOUT", "60"))
INTERVAL_SECONDS = 2


def main():
    import psycopg2

    attempts = max(1, MAX_WAIT_SECONDS // INTERVAL_SECONDS)
    last_err = None

    for attempt in range(1, attempts + 1):
        for target_db in [DB_NAME, "shakthidb", "postgres"]:
            try:
                conn = psycopg2.connect(
                    host=DB_HOST, port=DB_PORT, user=DB_USER,
                    password=DB_PASSWORD, dbname=target_db,
                    connect_timeout=3,
                )
                conn.close()
                print(f"[PREFLIGHT] PostgreSQL/ShaktiDB is reachable at {DB_HOST}:{DB_PORT} (db: {target_db}) "
                      f"(attempt {attempt}/{attempts}). Starting application.", flush=True)
                return 0
            except Exception as e:
                last_err = e

        if attempt == 1:
            print(f"[PREFLIGHT] PostgreSQL/ShaktiDB not ready yet at {DB_HOST}:{DB_PORT}, "
                  f"retrying for up to {MAX_WAIT_SECONDS}s...", flush=True)
        if attempt < attempts:
            time.sleep(INTERVAL_SECONDS)


    print(f"[PREFLIGHT FATAL] PostgreSQL/ShaktiDB never became reachable at "
          f"{DB_HOST}:{DB_PORT} within {MAX_WAIT_SECONDS}s. Last error: {last_err}. "
          f"Refusing to start the application -- this deployment requires a real "
          f"database connection, not a silent local fallback.", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
