#!/usr/bin/env bash
# Seed the running service with test movies via UpsertMovie (gRPC).
# Usage: ./scripts/seed.sh [host:port]
# Default target: localhost:8080

set -euo pipefail

HOST="${1:-localhost:8080}"
GRPCURL="grpcurl -plaintext"
SVC="movieservice.v1.MovieAdminService"

upsert() {
  $GRPCURL -d "$1" "$HOST" "$SVC/UpsertMovie"
}

echo "==> Seeding $HOST ..."

# ── Movie 1: The Shawshank Redemption ────────────────────────────────────────
MOVIE1_ID="11111111-1111-1111-1111-111111111111"
upsert '{
  "movie": {
    "movie_id": "'"$MOVIE1_ID"'",
    "title": "The Shawshank Redemption",
    "description": "Two imprisoned men bond over years, finding solace and eventual redemption through acts of common decency.",
    "genres": [{"name": "Drama"}],
    "actors": [
      {"name": "Tim",    "surname": "Robbins",  "birth_year": 1958},
      {"name": "Morgan", "surname": "Freeman",  "birth_year": 1937}
    ],
    "directors": [{"name": "Frank", "surname": "Darabont", "birth_year": 1959}],
    "country": "USA",
    "release_year": 1994,
    "imdb_rating": 9.3
  }
}'
echo "  inserted: The Shawshank Redemption ($MOVIE1_ID)"

# ── Movie 2: The Dark Knight ─────────────────────────────────────────────────
MOVIE2_ID="22222222-2222-2222-2222-222222222222"
upsert '{
  "movie": {
    "movie_id": "'"$MOVIE2_ID"'",
    "title": "The Dark Knight",
    "description": "When the menace known as the Joker wreaks havoc on Gotham City, Batman must confront his greatest psychological and physical test.",
    "genres": [{"name": "Action"}, {"name": "Crime"}, {"name": "Drama"}],
    "actors": [
      {"name": "Christian", "surname": "Bale",   "birth_year": 1974},
      {"name": "Heath",     "surname": "Ledger",  "birth_year": 1979},
      {"name": "Aaron",     "surname": "Eckhart", "birth_year": 1968}
    ],
    "directors": [{"name": "Christopher", "surname": "Nolan", "birth_year": 1970}],
    "country": "USA",
    "release_year": 2008,
    "imdb_rating": 9.0
  }
}'
echo "  inserted: The Dark Knight ($MOVIE2_ID)"

# ── Movie 3: Inception ────────────────────────────────────────────────────────
MOVIE3_ID="33333333-3333-3333-3333-333333333333"
upsert '{
  "movie": {
    "movie_id": "'"$MOVIE3_ID"'",
    "title": "Inception",
    "description": "A thief who steals corporate secrets through the use of dream-sharing technology is given the inverse task of planting an idea.",
    "genres": [{"name": "Action"}, {"name": "Sci-Fi"}, {"name": "Thriller"}],
    "actors": [
      {"name": "Leonardo", "surname": "DiCaprio",        "birth_year": 1974},
      {"name": "Joseph",   "surname": "Gordon-Levitt",   "birth_year": 1981},
      {"name": "Ken",      "surname": "Watanabe",        "birth_year": 1959}
    ],
    "directors": [{"name": "Christopher", "surname": "Nolan", "birth_year": 1970}],
    "country": "USA",
    "release_year": 2010,
    "imdb_rating": 8.8
  }
}'
echo "  inserted: Inception ($MOVIE3_ID)"

# ── Movie 4 (will be archived in test.sh) ─────────────────────────────────────
MOVIE4_ID="44444444-4444-4444-4444-444444444444"
upsert '{
  "movie": {
    "movie_id": "'"$MOVIE4_ID"'",
    "title": "Interstellar",
    "description": "A team of explorers travel through a wormhole in space in an attempt to ensure humanitys survival.",
    "genres": [{"name": "Sci-Fi"}, {"name": "Drama"}],
    "actors": [
      {"name": "Matthew", "surname": "McConaughey", "birth_year": 1969},
      {"name": "Anne",    "surname": "Hathaway",    "birth_year": 1982}
    ],
    "directors": [{"name": "Christopher", "surname": "Nolan", "birth_year": 1970}],
    "country": "USA",
    "release_year": 2014,
    "imdb_rating": 8.7
  }
}'
echo "  inserted: Interstellar ($MOVIE4_ID)"

echo
echo "Done. IDs for use in test.sh:"
echo "  MOVIE1_ID=$MOVIE1_ID  (Shawshank)"
echo "  MOVIE2_ID=$MOVIE2_ID  (Dark Knight)"
echo "  MOVIE3_ID=$MOVIE3_ID  (Inception)"
echo "  MOVIE4_ID=$MOVIE4_ID  (Interstellar — will be archived)"
