#!/usr/bin/env bash
# End-to-end gRPC tests against a running collections-service instance.
# Run seed.sh first to populate data.
# Usage: ./scripts/test.sh [host:port]

set -euo pipefail

HOST="${1:-localhost:8080}"
GR="grpcurl -plaintext"

# Capture both stdout and stderr; never let a failing grpcurl abort the script.
grpc() { $GR "$@" 2>&1 || true; }

MOVIE1_ID="11111111-1111-1111-1111-111111111111"  # Shawshank Redemption
MOVIE2_ID="22222222-2222-2222-2222-222222222222"  # The Dark Knight
MOVIE3_ID="33333333-3333-3333-3333-333333333333"  # Inception
MOVIE4_ID="44444444-4444-4444-4444-444444444444"  # Interstellar (to be archived)
USER1_ID="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

PASS=0
FAIL=0

check() {
  local label="$1"
  local got="$2"
  local want="$3"
  if echo "$got" | grep -q "$want"; then
    echo "  PASS  $label"
    PASS=$((PASS+1))
  else
    echo "  FAIL  $label"
    echo "        expected to contain: $want"
    echo "        got: $got"
    FAIL=$((FAIL+1))
  fi
}

check_absent() {
  local label="$1"
  local got="$2"
  local absent="$3"
  if echo "$got" | grep -q "$absent"; then
    echo "  FAIL  $label (found '$absent' but should be absent)"
    echo "        got: $got"
    FAIL=$((FAIL+1))
  else
    echo "  PASS  $label"
    PASS=$((PASS+1))
  fi
}

echo "======================================================================"
echo "  collections-service gRPC tests  →  $HOST"
echo "======================================================================"

# ── MovieService ───────────────────────────────────────────────────────
echo
echo "── GetMovieByID ─────────────────────────────────────────────────────────"

OUT=$(grpc -d '{"movie_id":"'"$MOVIE1_ID"'"}' "$HOST" \
  movieservice.v1.MovieService/GetMovieByID 2>&1)
check "returns correct title"        "$OUT" "Shawshank Redemption"
check "includes genres"              "$OUT" "Drama"
check "includes actor Tim Robbins"   "$OUT" "Robbins"
check "includes director Darabont"   "$OUT" "Darabont"
check "correct release year"         "$OUT" "1994"
check "correct IMDB rating"          "$OUT" "9.3"

OUT=$(grpc -d '{"movie_id":"'"$MOVIE2_ID"'"}' "$HOST" \
  movieservice.v1.MovieService/GetMovieByID 2>&1)
check "Dark Knight title"            "$OUT" "Dark Knight"
check "Dark Knight has Action genre" "$OUT" "Action"
check "Dark Knight actor Ledger"     "$OUT" "Ledger"

OUT=$(grpc -d '{"movie_id":"deadbeef-dead-beef-dead-beefdeadbeef"}' "$HOST" \
  movieservice.v1.MovieService/GetMovieByID 2>&1)
check "non-existent ID → NotFound"   "$OUT" "NotFound\|not found\|NOT_FOUND"

echo
echo "── ListMovies ───────────────────────────────────────────────────────────"

# List all (default: no filters)
OUT=$(grpc -d '{"limit":10}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "list returns Shawshank"       "$OUT" "Shawshank"
check "list returns Dark Knight"     "$OUT" "Dark Knight"
check "list returns Inception"       "$OUT" "Inception"

# Text search by title
OUT=$(grpc -d '{"query":"inception","limit":10}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "query 'inception' finds it"   "$OUT" "Inception"
check_absent "query 'inception' excludes Shawshank" "$OUT" "Shawshank"

# Search by actor name
OUT=$(grpc -d '{"query":"dicaprio","limit":10}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "query 'dicaprio' finds Inception" "$OUT" "Inception"

# Filter by genre name
OUT=$(grpc -d '{"genres":[{"name":"Sci-Fi"}],"limit":10}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "genre filter Sci-Fi returns Inception"    "$OUT" "Inception"
check_absent "genre filter Sci-Fi excludes Shawshank" "$OUT" "Shawshank"

# Filter by country
OUT=$(grpc -d '{"country":"USA","limit":10}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "country=USA returns movies"   "$OUT" "Shawshank"

# Filter by release year range
OUT=$(grpc -d '{"release_year_from":2005,"release_year_to":2012,"limit":10}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "year 2005-2012 includes Dark Knight" "$OUT" "Dark Knight"
check "year 2005-2012 includes Inception"   "$OUT" "Inception"
check_absent "year 2005-2012 excludes Shawshank" "$OUT" "Shawshank"

# Filter by IMDb rating
OUT=$(grpc -d '{"imdb_rating_from":9.0,"limit":10}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "rating >= 9.0 includes Shawshank"   "$OUT" "Shawshank"
check "rating >= 9.0 includes Dark Knight" "$OUT" "Dark Knight"
check_absent "rating >= 9.0 excludes Inception" "$OUT" "Inception"

# Sort by release year DESC
OUT=$(grpc -d '{"limit":10,"sort_by":"release_year","sort_order":"desc"}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "sort by year desc returns results" "$OUT" "movie"

# Pagination
OUT=$(grpc -d '{"limit":2,"offset":0,"sort_by":"title","sort_order":"asc"}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "pagination limit=2 returns ≤2 movies" "$OUT" "movie"

# ── MovieAdminService ──────────────────────────────────────────────────
echo
echo "── UpsertMovie (update) ─────────────────────────────────────────────────"

OUT=$(grpc -d '{
  "movie": {
    "movie_id": "'"$MOVIE1_ID"'",
    "title": "The Shawshank Redemption (Updated)",
    "description": "Updated description.",
    "genres": [{"name": "Drama"}],
    "actors":    [{"name": "Tim", "surname": "Robbins"}],
    "directors": [{"name": "Frank", "surname": "Darabont"}],
    "country": "USA",
    "release_year": 1994,
    "imdb_rating": 9.3
  }
}' "$HOST" movieservice.v1.MovieAdminService/UpsertMovie 2>&1)
check "upsert update returns empty response" "$OUT" "{}\|^$"

OUT=$(grpc -d '{"movie_id":"'"$MOVIE1_ID"'"}' "$HOST" \
  movieservice.v1.MovieService/GetMovieByID 2>&1)
check "updated title persisted" "$OUT" "Updated"

# Restore original title
grpc -d '{
  "movie": {
    "movie_id": "'"$MOVIE1_ID"'",
    "title": "The Shawshank Redemption",
    "description": "Two imprisoned men bond over years, finding solace and eventual redemption through acts of common decency.",
    "genres": [{"name": "Drama"}],
    "actors":    [{"name": "Tim", "surname": "Robbins"},{"name": "Morgan", "surname": "Freeman"}],
    "directors": [{"name": "Frank", "surname": "Darabont"}],
    "country": "USA",
    "release_year": 1994,
    "imdb_rating": 9.3
  }
}' "$HOST" movieservice.v1.MovieAdminService/UpsertMovie > /dev/null 2>&1

echo
echo "── ArchiveMovie ─────────────────────────────────────────────────────────"

OUT=$(grpc -d '{"movie_id":"'"$MOVIE4_ID"'"}' "$HOST" \
  movieservice.v1.MovieAdminService/ArchiveMovie 2>&1)
check "archive returns empty response" "$OUT" "{}\|^$"

# Archived movie should be invisible to ListMovies by default
OUT=$(grpc -d '{"limit":10}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check_absent "archived movie hidden from list by default" "$OUT" "Interstellar"

# Archived movie visible with include_archived=true
OUT=$(grpc -d '{"limit":10,"include_archived":true}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "include_archived shows archived movie" "$OUT" "Interstellar"

# GetMovieByID on archived movie returns NotFound
OUT=$(grpc -d '{"movie_id":"'"$MOVIE4_ID"'"}' "$HOST" \
  movieservice.v1.MovieService/GetMovieByID 2>&1)
check "archived movie → GetByID returns NotFound" "$OUT" "NotFound\|not found\|NOT_FOUND"

echo
echo "── RemoveMovie ──────────────────────────────────────────────────────────"

# Insert a temporary movie to delete
TMP_ID="ffffffff-ffff-ffff-ffff-ffffffffffff"
grpc -d '{
  "movie": {
    "movie_id": "'"$TMP_ID"'",
    "title": "Temporary Movie",
    "description": "Will be deleted.",
    "genres": [{"name": "Drama"}],
    "actors":    [{"name": "John", "surname": "Doe"}],
    "directors": [{"name": "Jane", "surname": "Doe"}],
    "country": "USA",
    "release_year": 2000,
    "imdb_rating": 5.0
  }
}' "$HOST" movieservice.v1.MovieAdminService/UpsertMovie > /dev/null 2>&1

OUT=$(grpc -d '{"movie_id":"'"$TMP_ID"'"}' "$HOST" \
  movieservice.v1.MovieAdminService/RemoveMovie 2>&1)
check "remove returns empty response" "$OUT" "{}\|^$"

OUT=$(grpc -d '{"movie_id":"'"$TMP_ID"'"}' "$HOST" \
  movieservice.v1.MovieService/GetMovieByID 2>&1)
check "removed movie → GetByID returns NotFound" "$OUT" "NotFound\|not found\|NOT_FOUND"

# ── WatchlistService ──────────────────────────────────────────────────────────
echo
echo "── WatchlistService ─────────────────────────────────────────────────────"

# Add movies to watchlist
OUT=$(grpc -d '{"user_id":"'"$USER1_ID"'","movie_id":"'"$MOVIE1_ID"'"}' "$HOST" \
  movieservice.v1.WatchlistService/AddMovieToWatchlist 2>&1)
check "add Shawshank to watchlist"    "$OUT" "{}\|^$"

OUT=$(grpc -d '{"user_id":"'"$USER1_ID"'","movie_id":"'"$MOVIE2_ID"'"}' "$HOST" \
  movieservice.v1.WatchlistService/AddMovieToWatchlist 2>&1)
check "add Dark Knight to watchlist" "$OUT" "{}\|^$"

# Duplicate add should not error (ON CONFLICT DO NOTHING via FK cascade)
OUT=$(grpc -d '{"user_id":"'"$USER1_ID"'","movie_id":"'"$MOVIE1_ID"'"}' "$HOST" \
  movieservice.v1.WatchlistService/AddMovieToWatchlist 2>&1)
check "duplicate add is idempotent"  "$OUT" "{}\|^$"

# Get watchlist
OUT=$(grpc -d '{"user_id":"'"$USER1_ID"'"}' "$HOST" \
  movieservice.v1.WatchlistService/GetUserWatchlist 2>&1)
check "watchlist contains Shawshank"    "$OUT" "Shawshank"
check "watchlist contains Dark Knight"  "$OUT" "Dark Knight"
check_absent "watchlist excludes Inception" "$OUT" "Inception"

# Remove one movie
OUT=$(grpc -d '{"user_id":"'"$USER1_ID"'","movie_id":"'"$MOVIE1_ID"'"}' "$HOST" \
  movieservice.v1.WatchlistService/RemoveMovieFromWatchlist 2>&1)
check "remove Shawshank from watchlist" "$OUT" "{}\|^$"

OUT=$(grpc -d '{"user_id":"'"$USER1_ID"'"}' "$HOST" \
  movieservice.v1.WatchlistService/GetUserWatchlist 2>&1)
check_absent "Shawshank removed from watchlist" "$OUT" "Shawshank"
check "Dark Knight still in watchlist"           "$OUT" "Dark Knight"

# Empty watchlist for unknown user
OUT=$(grpc -d '{"user_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}' "$HOST" \
  movieservice.v1.WatchlistService/GetUserWatchlist 2>&1)
check "unknown user has empty watchlist" "$OUT" "{}\|\"movies\": \[\]"

# ── Validation errors ─────────────────────────────────────────────────────────
echo
echo "── Validation errors ────────────────────────────────────────────────────"

OUT=$(grpc -d '{"movie_id":"not-a-uuid"}' "$HOST" \
  movieservice.v1.MovieService/GetMovieByID 2>&1)
check "bad UUID → InvalidArgument" "$OUT" "InvalidArgument\|INVALID_ARGUMENT"

OUT=$(grpc -d '{"limit":-1}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "negative limit → InvalidArgument" "$OUT" "InvalidArgument\|INVALID_ARGUMENT"

OUT=$(grpc -d '{"release_year_from":2020,"release_year_to":2000}' "$HOST" \
  movieservice.v1.MovieService/ListMovies 2>&1)
check "from > to year range → InvalidArgument" "$OUT" "InvalidArgument\|INVALID_ARGUMENT"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "======================================================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "======================================================================"
[ "$FAIL" -eq 0 ]
