#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MIGRATIONS_DIR="${MIGRATIONS_DIR:-$SCRIPT_DIR/../migrations}"
PSQL_BIN="${PSQL_BIN:-psql}"

psql_exec() {
    if [[ -n "${DATABASE_URL:-}" ]]; then
        "$PSQL_BIN" "$DATABASE_URL" "$@"
        return
    fi

    "$PSQL_BIN" "$@"
}

ensure_requirements() {
    if ! command -v "$PSQL_BIN" >/dev/null 2>&1; then
        printf 'psql binary not found: %s\n' "$PSQL_BIN" >&2
        exit 1
    fi

    if [[ ! -d "$MIGRATIONS_DIR" ]]; then
        printf 'migrations directory not found: %s\n' "$MIGRATIONS_DIR" >&2
        exit 1
    fi
}

ensure_migrations_table() {
    psql_exec -v ON_ERROR_STOP=1 -c "
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version text PRIMARY KEY,
            applied_at timestamptz NOT NULL DEFAULT now()
        );
    "
}

main() {
    ensure_requirements
    ensure_migrations_table

    printf '%-45s %-10s %s\n' "VERSION" "STATUS" "APPLIED_AT"
    printf '%.0s-' {1..75}; printf '\n'

    while IFS= read -r up_file; do
        filename=$(basename "$up_file")
        version="${filename%.up.sql}"

        applied_at=$(psql_exec -At -c "SELECT applied_at FROM schema_migrations WHERE version = '$version';")
        if [[ -n "$applied_at" ]]; then
            printf '%-45s %-10s %s\n' "$version" "applied" "$applied_at"
        else
            printf '%-45s %-10s\n' "$version" "pending"
        fi
    done < <(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.up.sql' | sort)
}

main "$@"
