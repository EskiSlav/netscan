#!/bin/bash
set -e
export PGPASSWORD=$POSTGRES_PASSWORD;

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  CREATE USER $DJANGO_DB_USER WITH PASSWORD '$DJANGO_DB_PASSWORD';
  CREATE USER root WITH PASSWORD '$DJANGO_DB_PASSWORD';
  CREATE DATABASE $DJANGO_DB_NAME;
  GRANT ALL PRIVILEGES ON DATABASE $DJANGO_DB_NAME TO $DJANGO_DB_USER;
  ALTER USER $DJANGO_DB_USER CREATEDB;
  \connect $DJANGO_DB_NAME $DJANGO_DB_USER
  CREATE EXTENSION pg_trgm;

EOSQL

# psql -v ON_ERROR_STOP=1 --username "$DJANGO_DB_USER" --dbname "$DJANGO_DB_NAME" -f /opt/seed-data/seed.sql
