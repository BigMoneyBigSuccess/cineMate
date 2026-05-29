/**
 * Auth endpoint stress test.
 * Covers: POST /auth/register, POST /auth/login, POST /auth/logout
 *
 * Stages:
 *   smoke  – 5 VUs for 30 s  (quick sanity)
 *   load   – ramp to 50 VUs over 1 min, hold 3 min, ramp down
 *   stress – ramp to 150 VUs, hold 2 min, ramp down
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, JSON_HEADERS } from './helpers.js';

const registerDuration = new Trend('auth_register_duration', true);
const loginDuration = new Trend('auth_login_duration', true);
const logoutDuration = new Trend('auth_logout_duration', true);
const errorRate = new Rate('auth_error_rate');

export const options = {
  stages: [
    { duration: '30s', target: 5 },   // smoke
    { duration: '1m',  target: 50 },  // ramp up
    { duration: '3m',  target: 50 },  // steady load
    { duration: '1m',  target: 150 }, // stress ramp
    { duration: '2m',  target: 150 }, // stress hold
    { duration: '1m',  target: 0 },   // ramp down
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'],          // <1 % errors overall
    auth_register_duration: ['p(95)<500'],   // 95th pct < 500 ms
    auth_login_duration:    ['p(95)<300'],
    auth_logout_duration:   ['p(95)<300'],
    auth_error_rate:        ['rate<0.02'],
  },
};

export default function () {
  const suffix = `${__VU}_${Date.now()}`;
  const email = `stress_auth_${suffix}@test.local`;
  const password = 'Stress1234!';

  // --- Register ---
  const regRes = http.post(
    `${BASE_URL}/auth/register`,
    JSON.stringify({ email, password }),
    { headers: JSON_HEADERS, tags: { endpoint: 'register' } },
  );
  registerDuration.add(regRes.timings.duration);
  const regOk = check(regRes, {
    'register status 201': (r) => r.status === 201,
    'register has user_id': (r) => r.json('user_id') !== undefined,
  });
  errorRate.add(!regOk);

  sleep(0.5);

  // --- Login ---
  const loginRes = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify({ email, password }),
    { headers: JSON_HEADERS, tags: { endpoint: 'login' } },
  );
  loginDuration.add(loginRes.timings.duration);
  const loginOk = check(loginRes, {
    'login status 200': (r) => r.status === 200,
    'login has token':  (r) => r.json('token') !== undefined,
  });
  errorRate.add(!loginOk);

  const token = loginRes.json('token');
  if (!token) {
    sleep(1);
    return;
  }

  sleep(0.3);

  // --- Logout ---
  const logoutRes = http.post(
    `${BASE_URL}/auth/logout`,
    null,
    {
      headers: { Authorization: `Bearer ${token}` },
      tags: { endpoint: 'logout' },
    },
  );
  logoutDuration.add(logoutRes.timings.duration);
  const logoutOk = check(logoutRes, {
    'logout status 204': (r) => r.status === 204,
  });
  errorRate.add(!logoutOk);

  sleep(1);
}
