export interface Genre {
  id?: string;
  name: string;
}

export interface Person {
  id?: string;
  name: string;
  surname?: string;
  birth_year?: number;
}

export interface Movie {
  movie_id: string;
  title: string;
  description: string;
  genres: Genre[];
  actors: Person[];
  directors: Person[];
  country: string;
  release_year: number;
  imdb_rating: number;
  poster_tone?: string;
}

export interface UserProfile {
  user_id: string;
  username: string;
  bio: string;
  created_at?: unknown;
  updated_at?: unknown;
}

export interface LibraryState {
  watchlistIds: string[];
  ratings: Record<string, number>;
}

export interface Review {
  feedback_id: string;
  user_id: string;
  movie_id: string;
  rating: number;
  title?: string;
  content?: string;
}

export interface Recommendation {
  recommendation_id: string;
  movie: Movie;
  strategy: string;
  ai_response?: string;
  rank: number;
  generated_at: number;
}
