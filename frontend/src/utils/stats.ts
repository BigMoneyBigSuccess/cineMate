import type { LibraryState, Movie } from '../types/domain';
import { personName } from './movie';

export interface CountItem {
  label: string;
  value: number;
}

export function ratedMovies(movies: Movie[], library: LibraryState): Movie[] {
  const ids = new Set(Object.keys(library.ratings));
  return movies.filter((movie) => ids.has(movie.movie_id));
}

export function countGenres(movies: Movie[]): CountItem[] {
  const counts = new Map<string, number>();
  movies.forEach((movie) => {
    movie.genres.forEach((genre) => counts.set(genre.name, (counts.get(genre.name) || 0) + 1));
  });
  return sortCounts(counts);
}

export function countActors(movies: Movie[]): CountItem[] {
  const counts = new Map<string, number>();
  movies.forEach((movie) => {
    movie.actors.forEach((actor) => {
      const name = personName(actor);
      if (name) {
        counts.set(name, (counts.get(name) || 0) + 1);
      }
    });
  });
  return sortCounts(counts);
}

export function averageRating(library: LibraryState): number {
  const values = Object.values(library.ratings);
  if (values.length === 0) {
    return 0;
  }
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function sortCounts(counts: Map<string, number>): CountItem[] {
  return Array.from(counts.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label));
}
