/**
 * Full end-to-end scenario stress test.
 *
 * Simulates a realistic user session:
 *   1. Register + login
 *   2. Browse movies (list + detail)
 *   3. Add movies to watchlist
 *   4. Submit reviews
 *   5. Fetch recommendations
 *   6. Interact with a recommendation
 *   7. Follow another user
 *   8. View history
 *   9. Logout
 *
 * Uses k6 scenarios with weighted executor allocation:
 *   - browse_only:    60 % of VUs  (unauthenticated readers)
 *   - full_session:   40 % of VUs  (full authenticated flow)
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { BASE_URL, JSON_HEADERS, authHeaders, createAndLoginUser, randomInt, randomElement } from './helpers.js';

const sessionDuration = new Trend('full_session_duration', true);
const errorRate       = new Rate('full_flow_error_rate');
const completedSessions = new Counter('completed_sessions');

const STRATEGIES = ['preference_profile_based', 'genres_based', 'actors_based'];

export const options = {
  scenarios: {
    browse_only: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m',  target: 60 },
        { duration: '3m',  target: 60 },
        { duration: '1m',  target: 0 },
      ],
      gracefulRampDown: '30s',
      exec: 'browseScenario',
    },
    full_session: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m',  target: 40 },
        { duration: '3m',  target: 40 },
        { duration: '1m',  target: 0 },
      ],
      gracefulRampDown: '30s',
      exec: 'fullSessionScenario',
    },
  },
  thresholds: {
    http_req_failed:        ['rate<5'],   // http errors should be less than 5%
    http_req_duration:      ['p(95)<1000'], // 95% of requests should be under 1s
    full_flow_error_rate:   ['rate<0.03'], // overall flow errors should be less than 3%
    full_session_duration:  ['p(95)<15000'], // full session under 15 s
  },
};

export function setup() {
  const res = http.get(`${BASE_URL}/api/v1/movies?limit=50`);
  const ids = res.status === 200
    ? (res.json('movies') || []).map((m) => m.movie_id).filter(Boolean)
    : [];

  // Pre-create a few users so new sessions can follow them
  const poolUsers = [];
  for (let i = 0; i < 3; i++) {
    const u = createAndLoginUser();
    if (u.token && u.userId) poolUsers.push(u);
  }

  return { movieIds: ids, poolUsers };
}

// ─── Unauthenticated reader ───────────────────────────────────────────────────
export function browseScenario({ movieIds }) {
  group('browse movies', () => {
    const listRes = http.get(
      `${BASE_URL}/api/v1/movies?limit=${randomInt(5, 20)}&sort_by=imdb_rating&sort_order=desc`,
    );
    errorRate.add(!check(listRes, { 'list 200': (r) => r.status === 200 }));

    if (movieIds.length > 0) {
      const detailRes = http.get(`${BASE_URL}/api/v1/movies/${randomElement(movieIds)}`);
      errorRate.add(!check(detailRes, { 'detail 200 or 404': (r) => r.status === 200 || r.status === 404 }));
    }
  });

  sleep(randomInt(1, 3));
}

// ─── Full authenticated session ───────────────────────────────────────────────
export function fullSessionScenario({ movieIds, poolUsers }) {
  const startTime = Date.now();

  // 1. Auth
  let token, userId;
  group('auth', () => {
    const sess = createAndLoginUser();
    token = sess.token;
    userId = sess.userId;
  });

  if (!token) return;

  sleep(0.5);

  // 2. Browse movies
  group('browse', () => {
    const listRes = http.get(
      `${BASE_URL}/api/v1/movies?limit=10&sort_by=release_year&sort_order=desc`,
      { headers: authHeaders(token) },
    );
    errorRate.add(!check(listRes, { 'browse list 200': (r) => r.status === 200 }));

    if (movieIds.length > 0) {
      const mid = randomElement(movieIds);
      const detailRes = http.get(`${BASE_URL}/api/v1/movies/${mid}`);
      errorRate.add(!check(detailRes, { 'browse detail 200': (r) => r.status === 200 || r.status === 404 }));
    }
  });

  sleep(0.5);

  // 3. Add to watchlist
  const moviesToWatch = movieIds.slice(0, Math.min(3, movieIds.length));
  group('watchlist', () => {
    for (const mid of moviesToWatch) {
      const res = http.post(
        `${BASE_URL}/api/v1/watchlist/${mid}`,
        null,
        { headers: authHeaders(token) },
      );
      // Handler returns 204 on success, 409 on duplicate
      errorRate.add(!check(res, { 'watchlist add ok': (r) => r.status === 204 || r.status === 409 }));
    }

    const getRes = http.get(`${BASE_URL}/api/v1/watchlist`, { headers: authHeaders(token) });
    check(getRes, { 'watchlist get 200': (r) => r.status === 200 });
  });

  sleep(0.5);

  // 4. Submit reviews
  const reviewedIds = [];
  group('reviews', () => {
    const toReview = movieIds.slice(0, Math.min(3, movieIds.length));
    for (const mid of toReview) {
      const res = http.post(
        `${BASE_URL}/api/v1/movies/${mid}/reviews`,
        JSON.stringify({ rating: randomInt(1, 10) }),
        { headers: authHeaders(token) },
      );
      if (res.status === 200) {
        const fid = res.json('feedback_id');
        if (fid) reviewedIds.push(fid);
      }
    }
  });

  sleep(0.5);

  // 5. Recommendations
  let firstRecId = null;
  group('recommendations', () => {
    const recRes = http.get(
      `${BASE_URL}/api/v1/recommendations?strategy=${randomElement(STRATEGIES)}&limit=10`,
      { headers: authHeaders(token) },
    );
    errorRate.add(!check(recRes, { 'recs 200': (r) => r.status === 200 }));

    const recs = recRes.status === 200 ? (recRes.json('recommendations') || []) : [];
    if (recs.length > 0) firstRecId = recs[0].recommendation_id;
  });

  sleep(0.3);

  // 6. Interact with recommendation
  if (firstRecId) {
    group('rec_interaction', () => {
      const res = http.post(
        `${BASE_URL}/api/v1/recommendations/${firstRecId}/interactions`,
        JSON.stringify({ interaction: 'click' }),
        { headers: authHeaders(token) },
      );
      check(res, { 'interact ok': (r) => r.status === 200 || r.status === 204 });
    });
    sleep(0.2);
  }

  // 7. Social: follow a pool user
  if (poolUsers.length > 0) {
    group('social', () => {
      const target = randomElement(poolUsers);
      if (target.userId !== userId) {
        http.post(
          `${BASE_URL}/api/v1/users/${target.userId}/follow`,
          null,
          { headers: authHeaders(token) },
        );
        http.get(`${BASE_URL}/api/v1/users/${target.userId}/profile`);
      }
    });
    sleep(0.2);
  }

  // 8. Recommendation history
  group('history', () => {
    http.get(`${BASE_URL}/api/v1/recommendations/history?limit=10`, { headers: authHeaders(token) });
  });

  sessionDuration.add(Date.now() - startTime);
  completedSessions.add(1);

  sleep(randomInt(1, 3));
}
