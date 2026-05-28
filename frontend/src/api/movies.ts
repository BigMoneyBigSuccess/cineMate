import type { Movie } from '../types/domain';
import { normalizeMovie } from '../utils/movie';
import { apiClient } from './client';

export interface MovieListParams {
  q?: string;
  limit?: number;
  offset?: number;
  sort_by?: string;
  sort_order?: string;
  release_year_from?: number;
  release_year_to?: number;
  imdb_rating_from?: number;
  imdb_rating_to?: number;
}

export interface MovieListResult {
  movies: Movie[];
  total: number;
}

interface MovieListResponse {
  movies?: Partial<Movie>[];
  total?: number;
}

export async function listMovies(params: MovieListParams = {}): Promise<MovieListResult> {
  const response = await apiClient.get<MovieListResponse>('/api/v1/movies', { params });
  const movies = (response.data.movies || []).map((movie) => normalizeMovie(movie));
  return {
    movies,
    total: response.data.total || movies.length,
  };
}

export async function getWatchlist(): Promise<Movie[]> {
  const response = await apiClient.get<MovieListResponse>('/api/v1/watchlist');
  return (response.data.movies || []).map((movie) => normalizeMovie(movie));
}

export async function getUserWatchlist(userId: string): Promise<Movie[]> {
  const response = await apiClient.get<MovieListResponse>(`/api/v1/users/${userId}/watchlist`);
  return (response.data.movies || []).map((movie) => normalizeMovie(movie));
}

export async function addToWatchlist(movie: Movie): Promise<void> {
  await apiClient.post(`/api/v1/watchlist/${movie.movie_id}`);
}

export async function removeFromWatchlist(movie: Movie): Promise<void> {
  await apiClient.delete(`/api/v1/watchlist/${movie.movie_id}`);
}
