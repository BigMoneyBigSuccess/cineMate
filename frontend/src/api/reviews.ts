import type { Review } from '../types/domain';
import { apiClient } from './client';

interface ReviewsResponse {
  reviews?: Review[];
  total?: number;
}

interface UpsertReviewResponse {
  feedback_id: string;
}

export async function listUserReviews(userId: string): Promise<Review[]> {
  const response = await apiClient.get<ReviewsResponse>(`/api/v1/users/${userId}/reviews`);
  return response.data.reviews || [];
}

export async function upsertMovieReview(movieId: string, rating: number): Promise<string> {
  const response = await apiClient.post<UpsertReviewResponse>(`/api/v1/movies/${movieId}/reviews`, {
    rating,
  });
  return response.data.feedback_id;
}
