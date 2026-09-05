FROM pgvector/pgvector:pg16

# Set environment variables
ENV POSTGRES_PASSWORD=ShakthiDB@2026
ENV POSTGRES_DB=shakthidb

# Copy initialization script (schema + data)
# This script runs automatically when the container starts for the first time
COPY init.sql /docker-entrypoint-initdb.d/

# Expose the standard Postgres port
EXPOSE 5432
