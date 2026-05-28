import { apiClient } from './client';

export interface AuthRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
}

export interface RegisterResponse {
  user_id: string;
}

export async function login(payload: AuthRequest): Promise<LoginResponse> {
  const response = await apiClient.post<LoginResponse>('/auth/login', payload);
  return response.data;
}

export async function register(payload: AuthRequest): Promise<RegisterResponse> {
  const response = await apiClient.post<RegisterResponse>('/auth/register', payload);
  return response.data;
}

export async function logout(): Promise<void> {
  await apiClient.post('/auth/logout');
}
