/**
 * Social / user-profile endpoints stress test.
 * Covers:
 *   GET  /api/v1/users/search
 *   GET  /api/v1/users/{userId}/profile
 *   PUT  /api/v1/users/{userId}/profile
 *   POST /api/v1/users/{userId}/follow
 *   DELETE /api/v1/users/{userId}/follow
 *   GET  /api/v1/users/{userId}/followers
 *   GET  /api/v1/users/{userId}/following
 *   GET  /api/v1/users/{userId}/is-following
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, JSON_HEADERS, authHeaders, createAndLoginUser, randomElement, randomInt } from './helpers.js';

const searchDuration  = new Trend('social_search_duration', true);
const profileDuration = new Trend('social_profile_duration', true);
const followDuration  = new Trend('social_follow_duration', true);
const errorRate       = new Rate('social_error_rate');

const BIOS = [
  'Movie lover and critic.',
  'Watching everything since 1999.',
  'Sci-fi nerd.',
  'Director wannabe.',
];

export const options = {
  stages: [
    { duration: '30s', target: 5 },
    { duration: '1m',  target: 40 },
    { duration: '3m',  target: 40 },
    { duration: '1m',  target: 0 },
  ],
  thresholds: {
    http_req_failed:      ['rate<0.01'],
    social_search_duration:  ['p(95)<500'],
    social_profile_duration: ['p(95)<400'],
    social_follow_duration:  ['p(95)<500'],
    social_error_rate:       ['rate<0.02'],
  },
};

// Create a small pool of users so VUs can follow each other
export function setup() {
  const users = [];
  for (let i = 0; i < 5; i++) {
    const u = createAndLoginUser();
    if (u.token && u.userId) users.push(u);
  }
  return { users };
}

let session = null;

export default function ({ users }) {
  if (!session) {
    session = createAndLoginUser();
  }

  const { token, userId } = session;
  if (!token || !userId) return;

  // --- Search users ---
  const searchTerms = ['stress', 'test', 'user'];
  const searchRes = http.get(
    `${BASE_URL}/api/v1/users/search?q=${randomElement(searchTerms)}&limit=10`,
    { tags: { endpoint: 'social_search' } },
  );
  searchDuration.add(searchRes.timings.duration);
  errorRate.add(!check(searchRes, { 'search 200': (r) => r.status === 200 }));

  sleep(0.2);

  // --- Get own profile ---
  const profileRes = http.get(
    `${BASE_URL}/api/v1/users/${userId}/profile`,
    { tags: { endpoint: 'social_profile_get' } },
  );
  profileDuration.add(profileRes.timings.duration);
  errorRate.add(!check(profileRes, { 'get profile 200': (r) => r.status === 200 }));

  sleep(0.2);

  // --- Update own profile ---
  const updateRes = http.put(
    `${BASE_URL}/api/v1/users/${userId}/profile`,
    JSON.stringify({
      username: `user_${userId.slice(0, 8)}_${randomInt(1, 999)}`,
      bio: randomElement(BIOS),
    }),
    { headers: authHeaders(token), tags: { endpoint: 'social_profile_update' } },
  );
  errorRate.add(!check(updateRes, { 'update profile 200 or 204': (r) => r.status === 200 || r.status === 204 }));

  sleep(0.2);

  // --- Follow / unfollow a pool user ---
  if (users.length > 0) {
    const target = randomElement(users);
    if (target.userId === userId) {
      sleep(0.5);
      return;
    }

    const followRes = http.post(
      `${BASE_URL}/api/v1/users/${target.userId}/follow`,
      null,
      { headers: authHeaders(token), tags: { endpoint: 'social_follow' } },
    );
    followDuration.add(followRes.timings.duration);
    errorRate.add(!check(followRes, {
      'follow 200 or 409': (r) => r.status === 200 || r.status === 409,
    }));

    sleep(0.2);

    // Check is-following
    const isFollowRes = http.get(
      `${BASE_URL}/api/v1/users/${target.userId}/is-following?follower_id=${userId}`,
      { tags: { endpoint: 'social_is_following' } },
    );
    check(isFollowRes, { 'is-following 200': (r) => r.status === 200 });

    sleep(0.3);

    // Get followers list
    const followersRes = http.get(
      `${BASE_URL}/api/v1/users/${target.userId}/followers?limit=20`,
      { tags: { endpoint: 'social_followers' } },
    );
    check(followersRes, { 'followers 200': (r) => r.status === 200 });

    sleep(0.2);

    // Unfollow
    const unfollowRes = http.del(
      `${BASE_URL}/api/v1/users/${target.userId}/follow`,
      null,
      { headers: authHeaders(token), tags: { endpoint: 'social_unfollow' } },
    );
    errorRate.add(!check(unfollowRes, {
      'unfollow 204 or 404': (r) => r.status === 204 || r.status === 404,
    }));
  }

  sleep(randomInt(1, 4) * 0.2);
}
