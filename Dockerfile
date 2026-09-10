FROM pgvector/pgvector:pg16

# Set environment variables
# POSTGRES_PASSWORD is deliberately NOT set here. Baked into the image, every
# database built from it started with the same password -- and the value was
# readable by anyone with the image or the source. It is supplied at runtime by
# docker compose (from .env) or run_all.bat instead.
ENV POSTGRES_DB=shakthidb

# Copy initialization script (schema + data)
# This script runs automatically when the container starts for the first time
COPY init.sql /docker-entrypoint-initdb.d/

# Expose the standard Postgres port
EXPOSE 5432
