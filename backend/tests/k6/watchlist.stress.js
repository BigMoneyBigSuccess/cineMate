/**
 * Watchlist endpoints stress test.
 * Covers (all require auth):
 *   GET    /api/v1/watchlist
 *   POST   /api/v1/watchlist/{movieId}
 *   DELETE /api/v1/watchlist/{movieId}
 *   GET    /api/v1/users/{userId}/watchlist
 *
 * Each VU creates its own user in setup, then performs a realistic
 * add → read → delete cycle.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, JSON_HEADERS, authHeaders, createAndLoginUser, randomElement } from './helpers.js';

const addDuration    = new Trend('watchlist_add_duration', true);
const getDuration    = new Trend('watchlist_get_duration', true);
const deleteDuration = new Trend('watchlist_delete_duration', true);
const errorRate      = new Rate('watchlist_error_rate');

export const options = {
  stages: [
    { duration: '30s', target: 5 },
    { duration: '1m',  target: 40 },
    { duration: '3m',  target: 40 },
    { duration: '1m',  target: 0 },
  ],
  thresholds: {
    http_req_failed:       ['rate<0.01'],
    watchlist_add_duration:    ['p(95)<500'],
    watchlist_get_duration:    ['p(95)<400'],
    watchlist_delete_duration: ['p(95)<400'],
    watchlist_error_rate:      ['rate<0.02'],
  },
};

// Each VU gets its own account + a pool of movie IDs to work with
export function setup() {
  const res = http.get(`${BASE_URL}/api/v1/movies?limit=50`);
  const ids = res.status === 200
    ? (res.json('movies') || []).map((m) => m.movie_id).filter(Boolean)
    : [];
  return { movieIds: ids };
}

// VU-level state: one auth session per VU
let session = null;

export default function ({ movieIds }) {
  if (!session) {
    session = createAndLoginUser();
  }

  const { token, userId } = session;
  if (!token) return;

  const movieId = movieIds.length > 0
    ? randomElement(movieIds)
    : '00000000-0000-0000-0000-000000000001';

  // --- Add to watchlist ---
  const addRes = http.post(
    `${BASE_URL}/api/v1/watchlist/${movieId}`,
    null,
    { headers: authHeaders(token), tags: { endpoint: 'watchlist_add' } },
  );
  addDuration.add(addRes.timings.duration);
  errorRate.add(!check(addRes, {
    'add watchlist 204 or 409': (r) => r.status === 204 || r.status === 409,
  }));

  sleep(0.2);

  // --- Get own watchlist ---
  const getRes = http.get(
    `${BASE_URL}/api/v1/watchlist`,
    { headers: authHeaders(token), tags: { endpoint: 'watchlist_get' } },
  );
  getDuration.add(getRes.timings.duration);
  errorRate.add(!check(getRes, {
    'get watchlist 200': (r) => r.status === 200,
  }));

  sleep(0.2);

  // --- Get another user's watchlist (public) ---
  if (userId) {
    const pubRes = http.get(
      `${BASE_URL}/api/v1/users/${userId}/watchlist`,
      { tags: { endpoint: 'watchlist_public' } },
    );
    check(pubRes, { 'public watchlist 200': (r) => r.status === 200 });
  }

  sleep(0.2);

  // --- Remove from watchlist ---
  const delRes = http.del(
    `${BASE_URL}/api/v1/watchlist/${movieId}`,
    null,
    { headers: authHeaders(token), tags: { endpoint: 'watchlist_delete' } },
  );
  deleteDuration.add(delRes.timings.duration);
  errorRate.add(!check(delRes, {
    'delete watchlist 204 or 404': (r) => r.status === 204 || r.status === 404,
  }));

  sleep(randomElement([0.5, 1, 1.5]));
}
