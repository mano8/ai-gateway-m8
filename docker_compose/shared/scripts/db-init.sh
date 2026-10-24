#!/bin/sh
# The db-init one-shot (D-04): creates or re-syncs the database roles and
# databases, on every start, before ai-migrate. Idempotent; it never drops.
#
#   ai_owner    owns ai_db and its public schema; used only by ai-migrate.
#   ai_runtime  CONNECT and schema USAGE only; ai-migrate's migration grants
#               it DML on the operational tables and INSERT/SELECT only on
#               the audit tables, and no DDL.
#   AUTH_DB_USER owns the issuer's AUTH_DB_NAME.
#
# Passwords are read from the mounted Docker secrets and passed to psql as
# variables (:'name' quoting), never on a command line.
set -eu

read_secret() { tr -d '\r\n' < "/run/secrets/$1"; }

export PGHOST="${PGHOST:-m8_db}"
export PGPORT="${PGPORT:-5432}"
export PGUSER="${PGUSER:-postgres}"
PGPASSWORD="$(read_secret postgres_password)"
export PGPASSWORD

until pg_isready -q; do
    echo "==> db-init: waiting for ${PGHOST}:${PGPORT}"
    sleep 1
done

psql -v ON_ERROR_STOP=1 -d postgres \
    -v owner_pw="$(read_secret ai_owner_db_password)" \
    -v runtime_pw="$(read_secret ai_runtime_db_password)" \
    -v auth_pw="$(read_secret auth_db_password)" \
    -v auth_user="${AUTH_DB_USER}" \
    -v auth_db="${AUTH_DB_NAME}" <<'SQL'
SELECT format('%s ROLE ai_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L',
              CASE WHEN EXISTS (SELECT FROM pg_roles WHERE rolname = 'ai_owner')
                   THEN 'ALTER' ELSE 'CREATE' END, :'owner_pw') \gexec
SELECT format('%s ROLE ai_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L',
              CASE WHEN EXISTS (SELECT FROM pg_roles WHERE rolname = 'ai_runtime')
                   THEN 'ALTER' ELSE 'CREATE' END, :'runtime_pw') \gexec
SELECT format('%s ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L',
              CASE WHEN EXISTS (SELECT FROM pg_roles WHERE rolname = :'auth_user')
                   THEN 'ALTER' ELSE 'CREATE' END, :'auth_user', :'auth_pw') \gexec

SELECT 'CREATE DATABASE ai_db OWNER ai_owner'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ai_db') \gexec
REVOKE ALL ON DATABASE ai_db FROM PUBLIC;
GRANT CONNECT ON DATABASE ai_db TO ai_owner, ai_runtime;

SELECT format('CREATE DATABASE %I OWNER %I', :'auth_db', :'auth_user')
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'auth_db') \gexec
SQL

psql -v ON_ERROR_STOP=1 -d ai_db <<'SQL'
ALTER SCHEMA public OWNER TO ai_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ai_runtime;
SQL

echo "==> db-init: roles ai_owner, ai_runtime, ${AUTH_DB_USER}; databases ai_db, ${AUTH_DB_NAME}"
