import type { UserProfile } from '../types/domain';
import { apiClient } from './client';

interface SearchUsersResponse {
  profiles?: UserProfile[];
  total?: number;
}

interface IdListResponse {
  follower_ids?: string[];
  following_ids?: string[];
  total?: number;
}

interface IsFollowingResponse {
  is_following?: boolean;
}

export async function getProfile(userId: string): Promise<UserProfile> {
  const response = await apiClient.get<UserProfile>(`/api/v1/users/${userId}/profile`);
  return response.data;
}

export async function updateProfile(userId: string, payload: Pick<UserProfile, 'username' | 'bio'>) {
  await apiClient.put(`/api/v1/users/${userId}/profile`, payload);
}

export async function searchUsers(query: string, limit = 12, offset = 0) {
  const response = await apiClient.get<SearchUsersResponse>('/api/v1/users/search', {
    params: { q: query, limit, offset },
  });
  return {
    profiles: response.data.profiles || [],
    total: response.data.total || response.data.profiles?.length || 0,
  };
}

export async function getFollowers(userId: string, limit = 50, offset = 0) {
  const response = await apiClient.get<IdListResponse>(`/api/v1/users/${userId}/followers`, {
    params: { limit, offset },
  });
  return response.data.follower_ids || [];
}

export async function getFollowing(userId: string, limit = 50, offset = 0) {
  const response = await apiClient.get<IdListResponse>(`/api/v1/users/${userId}/following`, {
    params: { limit, offset },
  });
  return response.data.following_ids || [];
}

export async function isFollowing(currentUserId: string, userId: string) {
  const response = await apiClient.get<IsFollowingResponse>(`/api/v1/users/${userId}/is-following`, {
    params: { follower_id: currentUserId },
  });
  return Boolean(response.data.is_following);
}

export async function followUser(userId: string) {
  await apiClient.post(`/api/v1/users/${userId}/follow`);
}

export async function unfollowUser(userId: string) {
  await apiClient.delete(`/api/v1/users/${userId}/follow`);
}
