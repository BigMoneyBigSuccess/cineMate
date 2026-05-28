import { useEffect, useState } from 'react';
import { BookmarkPlus, Info, Star, X } from 'lucide-react';
import type { Movie } from '../types/domain';
import { movieGenres, moviePeople, personName } from '../utils/movie';
import RatingControl from './RatingControl';

interface MovieCardProps {
  movie: Movie;
  inWatchlist?: boolean;
  rating?: number;
  onToggleWatchlist?: (movie: Movie) => void;
  onRate?: (movie: Movie, rating: number) => void;
}

export default function MovieCard({
  movie,
  inWatchlist,
  rating,
  onToggleWatchlist,
  onRate,
}: MovieCardProps) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const userRating = rating ? ((movie.imdb_rating + rating) / 2).toFixed(1) : null;
  const genres = movieGenres(movie);
  const actors = movie.actors.map(personName).filter(Boolean).join(', ');
  const directors = movie.directors.map(personName).filter(Boolean).join(', ');

  useEffect(() => {
    if (!detailsOpen) {
      return;
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setDetailsOpen(false);
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [detailsOpen]);

  return (
    <>
      <article className="movie-card">
        <div className={`movie-poster tone-${movie.poster_tone || 'default'}`}>
          <span className="poster-year">{movie.release_year || 'N/A'}</span>
          <strong>{movie.title}</strong>
        </div>
        <div className="movie-card-body">
          <div className="movie-title-row">
            <h3>{movie.title}</h3>
            <span className="rating-pill">
              <Star size={14} fill="currentColor" />
              {movie.imdb_rating ? movie.imdb_rating.toFixed(1) : 'N/A'}
            </span>
          </div>
          <p className="movie-meta">{genres || movie.country}</p>
          <p className="movie-description">{movie.description}</p>
          <p className="movie-people">{moviePeople(movie.actors) || moviePeople(movie.directors)}</p>

          <div className="movie-actions">
            <button
              className={inWatchlist ? 'action-button action-button-active' : 'action-button'}
              type="button"
              onClick={() => onToggleWatchlist?.(movie)}
              title="Буду смотреть"
            >
              <BookmarkPlus size={16} />
              <span>Интересно</span>
            </button>
            <button className="action-button" type="button" onClick={() => setDetailsOpen(true)}>
              <Info size={16} />
              <span>Подробнее</span>
            </button>
          </div>

          <div className="movie-rating-row">
            <RatingControl compact value={rating} onChange={(next) => onRate?.(movie, next)} />
            <span>{userRating ? `Польз. ${userRating}` : 'Нет оценки'}</span>
          </div>
        </div>
      </article>

      {detailsOpen ? (
        <div className="movie-modal-backdrop" role="presentation" onMouseDown={() => setDetailsOpen(false)}>
          <section
            className="movie-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby={`movie-title-${movie.movie_id}`}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <button className="icon-button movie-modal-close" type="button" onClick={() => setDetailsOpen(false)}>
              <X size={18} />
            </button>
            <div className={`movie-modal-poster tone-${movie.poster_tone || 'default'}`}>
              <span>{movie.release_year || 'N/A'}</span>
              <strong>{movie.title}</strong>
            </div>
            <div className="movie-modal-content">
              <div className="movie-title-row">
                <h2 id={`movie-title-${movie.movie_id}`}>{movie.title}</h2>
              </div>
              <div className="movie-detail-grid">
                <span>
                  <strong>Рейтинг</strong>
                  <em>
                    <Star size={15} fill="currentColor" />
                    {movie.imdb_rating ? movie.imdb_rating.toFixed(1) : 'Нет данных'}
                  </em>
                </span>
                <span>
                  <strong>Год</strong>
                  {movie.release_year || 'Нет данных'}
                </span>
                <span>
                  <strong>Страна</strong>
                  {movie.country || 'Нет данных'}
                </span>
                <span>
                  <strong>Жанры</strong>
                  {genres || 'Нет данных'}
                </span>
                <span>
                  <strong>Режиссеры</strong>
                  {directors || 'Нет данных'}
                </span>
              </div>
              <p className="movie-modal-description">{movie.description || 'Описание не добавлено.'}</p>
              <div className="movie-detail-list">
                <strong>Актеры</strong>
                <span>{actors || 'Нет данных'}</span>
              </div>
              <div className="movie-modal-actions">
                <button
                  className={inWatchlist ? 'action-button action-button-active' : 'action-button'}
                  type="button"
                  onClick={() => onToggleWatchlist?.(movie)}
                >
                  <BookmarkPlus size={16} />
                  <span>Интересно</span>
                </button>
                <div className="movie-modal-rating">
                  <span>Ваша оценка</span>
                  <RatingControl value={rating} onChange={(next) => onRate?.(movie, next)} />
                </div>
              </div>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}
