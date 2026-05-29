/**
 * Movie endpoints stress test.
 * Covers:
 *   GET /api/v1/movies             (list with filters & pagination)
 *   GET /api/v1/movies/{movieId}   (single movie)
 *
 * These are read-heavy public endpoints — highest expected traffic.
 *
 * Stages: smoke → load → spike → recovery
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, randomInt, randomElement } from './helpers.js';

const listDuration   = new Trend('movies_list_duration', true);
const detailDuration = new Trend('movies_detail_duration', true);
const errorRate      = new Rate('movies_error_rate');

const SORT_BY_OPTIONS    = ['title', 'release_year', 'imdb_rating'];
const SORT_ORDER_OPTIONS = ['asc', 'desc'];

// Populated at runtime via setup(); script still works without seed movies
// by falling back to a hardcoded placeholder that returns 404 gracefully.
let MOVIE_IDS = [];

export const options = {
  stages: [
    { duration: '30s', target: 10 },   // smoke
    { duration: '1m',  target: 100 },  // ramp to load
    { duration: '3m',  target: 100 },  // steady load
    { duration: '30s', target: 300 },  // spike
    { duration: '1m',  target: 300 },  // spike hold
    { duration: '1m',  target: 100 },  // recover to load
    { duration: '1m',  target: 0 },    // ramp down
  ],
  thresholds: {
    http_req_failed:    ['rate<0.01'],
    movies_list_duration:   ['p(95)<600', 'p(99)<1000'],
    movies_detail_duration: ['p(95)<400', 'p(99)<800'],
    movies_error_rate:      ['rate<0.02'],
  },
};

export function setup() {
  const res = http.get(`${BASE_URL}/api/v1/movies?limit=50`);
  if (res.status !== 200) return { movieIds: [] };

  const body = res.json();
  const ids = (body.movies || []).map((m) => m.movie_id).filter(Boolean);
  return { movieIds: ids };
}

export default function ({ movieIds }) {
  MOVIE_IDS = movieIds;

  // ~70 % list, ~30 % detail
  if (Math.random() < 0.7) {
    listMovies();
  } else {
    getMovieDetail();
  }

  sleep(randomInt(1, 3) * 0.1); // 0.1 – 0.3 s think time
}

function listMovies() {
  const params = new URLSearchParams({
    limit:  randomInt(5, 20),
    offset: randomInt(0, 3) * 10,
    sort_by:    randomElement(SORT_BY_OPTIONS),
    sort_order: randomElement(SORT_ORDER_OPTIONS),
  });

  // Randomly add optional filters
  if (Math.random() < 0.4) params.set('release_year_from', randomInt(2000, 2015));
  if (Math.random() < 0.4) params.set('release_year_to',   randomInt(2016, 2024));
  if (Math.random() < 0.3) params.set('imdb_rating_from',  (randomInt(50, 70) / 10).toFixed(1));
  if (Math.random() < 0.2) params.set('q', randomElement(['action', 'drama', 'sci', 'comedy']));

  const res = http.get(`${BASE_URL}/api/v1/movies?${params.toString()}`, {
    tags: { endpoint: 'list_movies' },
  });
  listDuration.add(res.timings.duration);
  const ok = check(res, {
    'list movies 200': (r) => r.status === 200,
    'list has movies array': (r) => Array.isArray(r.json('movies')),
  });
  errorRate.add(!ok);
}

function getMovieDetail() {
  const movieId = MOVIE_IDS.length > 0
    ? randomElement(MOVIE_IDS)
    : '00000000-0000-0000-0000-000000000000'; // graceful miss

  const res = http.get(`${BASE_URL}/api/v1/movies/${movieId}`, {
    tags: { endpoint: 'get_movie' },
  });
  detailDuration.add(res.timings.duration);
  const ok = check(res, {
    'get movie 200 or 404': (r) => r.status === 200 || r.status === 404,
  });
  errorRate.add(!ok);
}
