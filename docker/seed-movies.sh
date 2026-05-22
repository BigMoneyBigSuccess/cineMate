#!/bin/sh
set -e

SEED_FILE=/seeds/moviedb.sql

if [ ! -f "$SEED_FILE" ]; then
    echo "No seed file found, skipping."
    exit 0
fi

echo "Waiting for movie schema..."
until psql -h postgres -U "$POSTGRES_USER" -d moviedb -c "SELECT 1 FROM movies LIMIT 1;" 2>/dev/null; do
    sleep 2
done

COUNT=$(psql -h postgres -U "$POSTGRES_USER" -d moviedb -t -c "SELECT COUNT(*) FROM movies;")
COUNT=$(echo "$COUNT" | tr -d ' ')

if [ "$COUNT" -gt "0" ]; then
    echo "Movies already seeded ($COUNT rows), skipping."
    exit 0
fi

echo "Seeding movie data..."
psql -h postgres -U "$POSTGRES_USER" -d moviedb -v ON_ERROR_STOP=1 -f "$SEED_FILE"
echo "Seed complete."
