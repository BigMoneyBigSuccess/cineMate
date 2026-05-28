import type { Recommendation } from '../types/domain';
import { normalizeMovie } from '../utils/movie';
import { apiClient } from './client';

interface RecommendationsResponse {
  recommendations?: Array<Omit<Recommendation, 'movie'> & { movie?: unknown }>;
  total?: number;
}

export async function generateRecommendations(limit = 8): Promise<Recommendation[]> {
  const response = await apiClient.get<RecommendationsResponse>('/api/v1/recommendations', {
    params: {
      strategy: 'preference_profile_based',
      limit,
    },
  });

  return (response.data.recommendations || [])
    .filter((recommendation) => recommendation.movie)
    .map((recommendation) => ({
      recommendation_id: recommendation.recommendation_id,
      strategy: recommendation.strategy,
      ai_response: recommendation.ai_response,
      rank: recommendation.rank,
      generated_at: recommendation.generated_at,
      movie: normalizeMovie(recommendation.movie as object),
    }));
}

export async function getRecommendationHistory(limit = 8): Promise<Recommendation[]> {
  const response = await apiClient.get<RecommendationsResponse>('/api/v1/recommendations/history', {
    params: {
      strategy: 'preference_profile_based',
      limit,
    },
  });

  return (response.data.recommendations || [])
    .filter((recommendation) => recommendation.movie)
    .map((recommendation) => ({
      recommendation_id: recommendation.recommendation_id,
      strategy: recommendation.strategy,
      ai_response: recommendation.ai_response,
      rank: recommendation.rank,
      generated_at: recommendation.generated_at,
      movie: normalizeMovie(recommendation.movie as object),
    }));
}
