import http from 'k6/http';
import { check } from 'k6';

export const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export const JSON_HEADERS = { 'Content-Type': 'application/json' };

export function authHeaders(token) {
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
}

/**
 * Register + login a unique user, return { token, userId }.
 * Uses VU id + timestamp to avoid collisions under parallel load.
 */
export function createAndLoginUser() {
  const suffix = `${__VU}_${Date.now()}`;
  const email = `stress_${suffix}@test.local`;
  const password = 'Stress1234!';

  const regRes = http.post(
    `${BASE_URL}/auth/register`,
    JSON.stringify({ email, password }),
    { headers: JSON_HEADERS },
  );
  check(regRes, { 'register 201': (r) => r.status === 201 });

  const loginRes = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify({ email, password }),
    { headers: JSON_HEADERS },
  );
  check(loginRes, { 'login 200': (r) => r.status === 200 });

  const body = loginRes.json();
  return { token: body.token, userId: body.user_id || extractUserIdFromJWT(body.token) };
}

function extractUserIdFromJWT(token) {
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.user_id || null;
  } catch {
    return null;
  }
}

export function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function randomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}
