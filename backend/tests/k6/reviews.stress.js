/**
 * Reviews/feedback endpoints stress test.
 * Covers:
 *   POST   /api/v1/movies/{movieId}/reviews  (create / update)
 *   GET    /api/v1/reviews/{feedbackId}
 *   GET    /api/v1/users/{userId}/reviews
 *   DELETE /api/v1/reviews/{feedbackId}
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, authHeaders, createAndLoginUser, randomInt, randomElement } from './helpers.js';

const upsertDuration = new Trend('reviews_upsert_duration', true);
const getDuration    = new Trend('reviews_get_duration', true);
const listDuration   = new Trend('reviews_list_duration', true);
const deleteDuration = new Trend('reviews_delete_duration', true);
const errorRate      = new Rate('reviews_error_rate');

const REVIEW_TITLES   = ['Loved it', 'Pretty good', 'Meh', 'Masterpiece', 'Disappointing'];
const REVIEW_CONTENTS = [
  'One of the best films I have seen.',
  'Good acting but weak plot.',
  'Not really my genre.',
  'Absolutely stunning visuals.',
  'Could have been better.',
];

export const options = {
  stages: [
    { duration: '30s', target: 5 },
    { duration: '1m',  target: 30 },
    { duration: '3m',  target: 30 },
    { duration: '1m',  target: 0 },
  ],
  thresholds: {
    http_req_failed:       ['rate<0.01'],
    reviews_upsert_duration: ['p(95)<600'],
    reviews_get_duration:    ['p(95)<400'],
    reviews_list_duration:   ['p(95)<500'],
    reviews_delete_duration: ['p(95)<400'],
    reviews_error_rate:      ['rate<0.02'],
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

export default function ({ movieIds }) {
  if (!session) {
    session = createAndLoginUser();
  }

  const { token, userId } = session;
  if (!token) return;

  const movieId = movieIds.length > 0
    ? randomElement(movieIds)
    : '00000000-0000-0000-0000-000000000001';

  // --- Create / upsert review ---
  const upsertRes = http.post(
    `${BASE_URL}/api/v1/movies/${movieId}/reviews`,
    JSON.stringify({
      rating:  randomInt(1, 10),
      title:   randomElement(REVIEW_TITLES),
      content: randomElement(REVIEW_CONTENTS),
    }),
    { headers: authHeaders(token), tags: { endpoint: 'reviews_upsert' } },
  );
  upsertDuration.add(upsertRes.timings.duration);
  const upsertOk = check(upsertRes, {
    'upsert review 200': (r) => r.status === 200,
    'upsert has feedback_id': (r) => r.json('feedback_id') !== undefined,
  });
  errorRate.add(!upsertOk);

  const feedbackId = upsertRes.json('feedback_id');
  sleep(0.3);

  // --- Get single review ---
  if (feedbackId) {
    const getRes = http.get(
      `${BASE_URL}/api/v1/reviews/${feedbackId}`,
      { tags: { endpoint: 'reviews_get' } },
    );
    getDuration.add(getRes.timings.duration);
    errorRate.add(!check(getRes, {
      'get review 200': (r) => r.status === 200,
    }));
  }

  sleep(0.2);

  // --- List user reviews ---
  if (userId) {
    const listRes = http.get(
      `${BASE_URL}/api/v1/users/${userId}/reviews`,
      { tags: { endpoint: 'reviews_list' } },
    );
    listDuration.add(listRes.timings.duration);
    check(listRes, { 'list reviews 200': (r) => r.status === 200 });
  }

  sleep(0.2);

  // --- Delete review (cleanup) ---
  if (feedbackId) {
    const delRes = http.del(
      `${BASE_URL}/api/v1/reviews/${feedbackId}`,
      null,
      { headers: authHeaders(token), tags: { endpoint: 'reviews_delete' } },
    );
    deleteDuration.add(delRes.timings.duration);
    errorRate.add(!check(delRes, {
      'delete review 204 or 404': (r) => r.status === 204 || r.status === 404,
    }));
  }

  sleep(randomInt(1, 3) * 0.3);
}
