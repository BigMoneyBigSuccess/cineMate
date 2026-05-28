import axios, { AxiosError } from 'axios';
import { getToken, removeToken } from '../auth/tokenStorage';

type ErrorContext = 'default' | 'login' | 'register';

export const apiClient = axios.create({
  baseURL: '',
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use((config) => {
  const token = getToken();

  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      removeToken();
    }
    return Promise.reject(error);
  },
);

export function getApiErrorMessage(error: unknown, context: ErrorContext = 'default'): string {
  if (!axios.isAxiosError(error)) {
    return 'Что-то пошло не так. Попробуйте еще раз.';
  }

  const axiosError = error as AxiosError<{ error?: string; message?: string } | string>;

  if (axiosError.response) {
    return translateApiError(axiosError.response.status, getResponseMessage(axiosError.response.data), context);
  }

  if (axiosError.request) {
    return 'Не удалось связаться с сервером. Попробуйте позже.';
  }

  return 'Что-то пошло не так. Попробуйте еще раз.';
}

function getResponseMessage(data: { error?: string; message?: string } | string | undefined): string {
  if (!data) {
    return '';
  }

  if (typeof data === 'string') {
    return data;
  }

  return data.error || data.message || '';
}

function translateApiError(status: number, message: string, context: ErrorContext): string {
  const normalized = message.trim().toLowerCase();

  if (context === 'login') {
    if (status === 400) {
      return 'Проверьте email и пароль.';
    }
    if (status === 401 || status === 404 || normalized.includes('user not found')) {
      return 'Неверный email или пароль.';
    }
  }

  if (context === 'register') {
    if (status === 409 || normalized.includes('already exists') || normalized.includes('duplicate')) {
      return 'Аккаунт с таким email уже существует.';
    }
    if (status === 400) {
      return 'Проверьте email и пароль.';
    }
  }

  if (
    status === 401 ||
    normalized.includes('authorization header') ||
    normalized.includes('missing user') ||
    normalized.includes('invalid token') ||
    normalized.includes('unauthenticated')
  ) {
    return 'Войдите в аккаунт и повторите действие.';
  }

  if (status === 404 || normalized.includes('not found')) {
    return 'Ничего не найдено.';
  }

  if (status === 409 || normalized.includes('already exists') || normalized.includes('duplicate')) {
    return 'Такая запись уже существует.';
  }

  if (status === 400 || normalized.includes('invalid') || normalized.includes('required')) {
    return 'Проверьте введенные данные.';
  }

  if (status >= 500) {
    return 'Сервис временно недоступен. Попробуйте позже.';
  }

  return 'Запрос не выполнен. Попробуйте еще раз.';
}
