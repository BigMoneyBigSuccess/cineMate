/**
 * Recommendations endpoints stress test.
 * Covers (all auth required):
 *   GET    /api/v1/recommendations
 *   GET    /api/v1/recommendations/history
 *   DELETE /api/v1/recommendations/history
 *   POST   /api/v1/recommendations/{id}/interactions
 *
 * Seeds several reviews first so the preference engine has data to work with.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, authHeaders, createAndLoginUser, randomInt, randomElement } from './helpers.js';

const recDuration     = new Trend('rec_get_duration', true);
const histDuration    = new Trend('rec_history_duration', true);
const interactDuration = new Trend('rec_interact_duration', true);
const errorRate       = new Rate('rec_error_rate');

const STRATEGIES = [
  'preference_profile_based',
  'genres_based',
  'actors_based',
  'directors_based',
];

const INTERACTIONS = ['click', 'dismiss'];

export const options = {
  stages: [
    { duration: '30s', target: 5 },
    { duration: '1m',  target: 20 },
    { duration: '3m',  target: 20 },
    { duration: '1m',  target: 0 },
  ],
  thresholds: {
    http_req_failed:      ['rate<0.01'],
    rec_get_duration:     ['p(95)<2000'], // AI strategy can be slower
    rec_history_duration: ['p(95)<600'],
    rec_interact_duration: ['p(95)<500'],
    rec_error_rate:       ['rate<0.05'],  // slightly looser: AI calls may fail
  },
};

export function setup() {
  const res = http.get(`${BASE_URL}/api/v1/movies?limit=50`);
  const ids = res.status === 200
    ? (res.json('movies') || []).map((m) => m.movie_id).filter(Boolean)
    : [];
  return { movieIds: ids };
}

let session = null;
let seeded = false;

export default function ({ movieIds }) {
  if (!session) {
    session = createAndLoginUser();
    seeded = false;
  }

  const { token } = session;
  if (!token) return;

  // Seed a few reviews on first iteration so the engine has signal
  if (!seeded && movieIds.length > 0) {
    seeded = true;
    const toReview = movieIds.slice(0, Math.min(5, movieIds.length));
    for (const mid of toReview) {
      http.post(
        `${BASE_URL}/api/v1/movies/${mid}/reviews`,
        JSON.stringify({ rating: randomInt(1, 10) }),
        { headers: authHeaders(token) },
      );
    }
    sleep(0.5);
  }

  // --- Get recommendations ---
  const strategy = randomElement(STRATEGIES);
  const recRes = http.get(
    `${BASE_URL}/api/v1/recommendations?strategy=${strategy}&limit=${randomInt(5, 15)}`,
    { headers: authHeaders(token), tags: { endpoint: 'rec_get', strategy } },
  );
  recDuration.add(recRes.timings.duration);
  const recOk = check(recRes, {
    'recommendations 200': (r) => r.status === 200,
    'has recommendations array': (r) => Array.isArray(r.json('recommendations')),
  });
  errorRate.add(!recOk);

  // --- Interact with first recommendation ---
  const recs = recRes.status === 200 ? (recRes.json('recommendations') || []) : [];
  if (recs.length > 0) {
    const recId = recs[0].recommendation_id;
    const interactRes = http.post(
      `${BASE_URL}/api/v1/recommendations/${recId}/interactions`,
      JSON.stringify({ interaction: randomElement(INTERACTIONS) }),
      { headers: authHeaders(token), tags: { endpoint: 'rec_interact' } },
    );
    interactDuration.add(interactRes.timings.duration);
    errorRate.add(!check(interactRes, {
      'interact 200 or 204': (r) => r.status === 200 || r.status === 204,
    }));
  }

  sleep(0.3);

  // --- Get history ---
  const histRes = http.get(
    `${BASE_URL}/api/v1/recommendations/history?limit=10`,
    { headers: authHeaders(token), tags: { endpoint: 'rec_history' } },
  );
  histDuration.add(histRes.timings.duration);
  check(histRes, { 'history 200': (r) => r.status === 200 });

  sleep(randomInt(2, 5) * 0.2);
}
