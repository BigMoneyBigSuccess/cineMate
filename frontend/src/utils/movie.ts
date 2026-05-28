import type { Movie, Person } from '../types/domain';

export function personName(person: Person): string {
  return [person.name, person.surname].filter(Boolean).join(' ').trim();
}

export function movieGenres(movie: Movie): string {
  return movie.genres.map((genre) => genre.name).filter(Boolean).join(', ');
}

export function moviePeople(people: Person[], limit = 2): string {
  const names = people.map(personName).filter(Boolean);
  return names.slice(0, limit).join(', ');
}

export function normalizeMovie(raw: Partial<Movie>): Movie {
  return {
    movie_id: String(raw.movie_id || ''),
    title: String(raw.title || ''),
    description: String(raw.description || ''),
    genres: Array.isArray(raw.genres) ? raw.genres : [],
    actors: Array.isArray(raw.actors) ? raw.actors : [],
    directors: Array.isArray(raw.directors) ? raw.directors : [],
    country: String(raw.country || ''),
    release_year: Number(raw.release_year || 0),
    imdb_rating: Number(raw.imdb_rating || 0),
    poster_tone: raw.poster_tone,
  };
}

export function initials(value: string): string {
  const parts = value.trim().split(/[\s._-]+/).filter(Boolean);
  return parts
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('');
}
