#!/usr/bin/env bash
set -euo pipefail

# DSM Development Database Setup Script
# Creates (if absent) a development PostgreSQL database and user, then applies schema.
# Idempotent: safe to re-run.
#
# Environment overrides:
#   PGHOST (default: localhost)
#   PGPORT (default: 5432)
#   PGUSER (default: postgres)  # admin user for creating role/db
#   PGPASSWORD (optional)       # password for admin user
#   DB_NAME (default: dsm_storage)
#   DB_USER (default: dsm)
#   DB_PASS (default: dsm)
#   APPLY_EXTRA (default: true) # whether to apply setup_dsm_db.sql if exists
#
# Usage:
#   ./scripts/setup_dev_db.sh          # perform setup
#   ./scripts/setup_dev_db.sh --dry-run # show actions without executing
#   ./scripts/setup_dev_db.sh --help    # help text
#
# Requires: psql CLI available in PATH.

DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --help|-h)
      grep '^# ' "$0" | sed 's/^# //'
      exit 0
      ;;
    *) echo "Unknown arg: $arg" >&2; exit 1 ;;
  esac
done

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-postgres}"
DB_NAME="${DB_NAME:-dsm_storage}"
DB_USER="${DB_USER:-dsm}"
DB_PASS="${DB_PASS:-dsm}"
APPLY_EXTRA="${APPLY_EXTRA:-true}"

SCHEMA_FILE="$(dirname "$0")/../dsm_storage_node/setup_dsm_db.sql"

psql_base_args=("-h" "$PGHOST" "-p" "$PGPORT" "-U" "$PGUSER" "-v" "ON_ERROR_STOP=1")

run() {
  echo "> $*"
  if [ "$DRY_RUN" = true ]; then
    return 0
  fi
  eval "$@"
}

if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Skipping psql availability and connection checks"
else
  # Check psql availability
  if ! command -v psql >/dev/null 2>&1; then
    echo "ERROR: psql CLI not found in PATH." >&2
    exit 1
  fi

  # Function: test connection
  if ! PGPASSWORD="${PGPASSWORD:-}" psql "${psql_base_args[@]}" -c 'SELECT 1;' >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to Postgres at $PGHOST:$PGPORT as $PGUSER" >&2
    exit 1
  fi

  echo "[+] Connected to Postgres as $PGUSER at $PGHOST:$PGPORT"
fi

# Create role if missing
if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Would check/create role ${DB_USER}"
else
  ROLE_EXISTS=$(PGPASSWORD="${PGPASSWORD:-}" psql "${psql_base_args[@]}" -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'") || true
  if [ "$ROLE_EXISTS" != "1" ]; then
    run "PGPASSWORD='${PGPASSWORD:-}' psql ${psql_base_args[*]} -c \"CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}'\""
  else
    echo "[=] Role ${DB_USER} already exists"
  fi
fi

# Create database if missing
if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Would check/create database ${DB_NAME} owned by ${DB_USER}"
else
  DB_EXISTS=$(PGPASSWORD="${PGPASSWORD:-}" psql "${psql_base_args[@]}" -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'") || true
  if [ "$DB_EXISTS" != "1" ]; then
    run "PGPASSWORD='${PGPASSWORD:-}' psql ${psql_base_args[*]} -c \"CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}\""
  else
    echo "[=] Database ${DB_NAME} already exists"
  fi
fi

# Grant privileges (idempotent)
if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Would grant privileges on ${DB_NAME} to ${DB_USER}"
else
  run "PGPASSWORD='${PGPASSWORD:-}' psql ${psql_base_args[*]} -d '${DB_NAME}' -c \"GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER}\""
fi

# Apply schema file if present
if [ -f "$SCHEMA_FILE" ] && [ "$APPLY_EXTRA" = "true" ]; then
  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Would apply schema from $SCHEMA_FILE"
  else
    echo "[+] Applying schema from $SCHEMA_FILE"
    run "PGPASSWORD='${PGPASSWORD:-}' psql ${psql_base_args[*]} -d '${DB_NAME}' -f '$SCHEMA_FILE'"
  fi
else
  echo "[=] Skipping schema apply (file missing or APPLY_EXTRA!=true)"
fi

echo "[✓] Development database setup complete"
if [ "$DRY_RUN" = true ]; then
  echo "(Dry run mode: no changes were applied)"
fi
#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Setup development PostgreSQL database for DSM storage node

set -euo pipefail

DB_NAME="${DSM_DB_NAME:-dsm_storage}"
DB_USER="${DSM_DB_USER:-dsm}"
DB_PASS="${DSM_DB_PASS:-dsm}"
DB_HOST="${DSM_DB_HOST:-localhost}"
DB_PORT="${DSM_DB_PORT:-5432}"

echo "==> Setting up DSM storage node development database"
echo "    Database: $DB_NAME"
echo "    User: $DB_USER"
echo "    Host: $DB_HOST:$DB_PORT"
echo ""

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "ERROR: psql command not found. Please install PostgreSQL client tools."
    exit 1
fi

# Create user if doesn't exist
echo "==> Creating database user '$DB_USER' (if not exists)..."
psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -tc \
    "SELECT 1 FROM pg_user WHERE usename = '$DB_USER'" | grep -q 1 || \
    psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -c \
    "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"

# Create database if doesn't exist
echo "==> Creating database '$DB_NAME' (if not exists)..."
psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -tc \
    "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || \
    psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -c \
    "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

# Grant privileges
echo "==> Granting privileges..."
psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -c \
    "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

# Run schema setup
echo "==> Running schema setup..."
if [ -f "dsm_storage_node/setup_dsm_db.sql" ]; then
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f dsm_storage_node/setup_dsm_db.sql
elif [ -f "../dsm_storage_node/setup_dsm_db.sql" ]; then
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f ../dsm_storage_node/setup_dsm_db.sql
elif [ -f "setup_dsm_db.sql" ]; then
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f setup_dsm_db.sql
else
    echo "WARNING: setup_dsm_db.sql not found. Skipping schema initialization."
    echo "         Please run the SQL file manually from dsm_storage_node/ directory."
fi

echo ""
echo "==> Database setup complete!"
echo "    Database endpoint: $DB_HOST:$DB_PORT/$DB_NAME"
echo ""
echo "To connect manually:"
echo "  psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME"
