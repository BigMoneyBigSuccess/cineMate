import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Film, RefreshCw, Sparkles } from 'lucide-react';
import { generateRecommendations, getRecommendationHistory } from '../api/recommendations';
import AppLayout from '../components/AppLayout';
import EmptyState from '../components/EmptyState';
import MovieCard from '../components/MovieCard';
import { useMovieLibrary } from '../hooks/useMovieLibrary';
import { useSession } from '../hooks/useSession';
import type { Movie } from '../types/domain';
import { averageRating } from '../utils/stats';

export default function HomePage() {
  const { userId } = useSession();
  const { library, syncError, toggleWatchlist, rateMovie } = useMovieLibrary(userId);
  const [serverRecommendations, setServerRecommendations] = useState<Movie[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [recommendationNote, setRecommendationNote] = useState('');
  const visibleRecommendations = useMemo(
    () => serverRecommendations.filter((movie) => !library.ratings[movie.movie_id]),
    [library.ratings, serverRecommendations],
  );

  useEffect(() => {
    if (!userId) {
      setServerRecommendations([]);
      setLoading(false);
      setRecommendationNote('');
      return;
    }

    let cancelled = false;
    setLoading(true);

    getRecommendationHistory(8)
      .then((recommendations) => {
        if (recommendations.length) {
          return recommendations;
        }
        return generateRecommendations(8);
      })
      .then((recommendations) => {
        if (!cancelled) {
          setServerRecommendations(recommendations.map((recommendation) => recommendation.movie));
          setRecommendationNote('');
        }
      })
      .catch(() => {
        if (!cancelled) {
          setServerRecommendations([]);
          setRecommendationNote('Не удалось загрузить рекомендации.');
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [userId]);

  async function refreshRecommendations() {
    if (!userId) {
      setRecommendationNote('Войдите, чтобы обновить рекомендации.');
      return;
    }

    setRefreshing(true);
    setRecommendationNote('');
    try {
      const recommendations = await generateRecommendations(8);
      const movies = recommendations.map((recommendation) => recommendation.movie);
      const freshMovies = movies.filter((movie) => !library.ratings[movie.movie_id]);
      setServerRecommendations(movies);
      setRecommendationNote(freshMovies.length ? 'Рекомендации обновлены.' : 'Новых рекомендаций пока нет.');
    } catch {
      setRecommendationNote('Не удалось обновить рекомендации. Попробуйте позже.');
    } finally {
      setRefreshing(false);
    }
  }

  const plannedCount = library.watchlistIds.length;
  const ratedCount = Object.keys(library.ratings).length;
  const avg = averageRating(library);

  return (
    <AppLayout>
      <section className="page-head">
        <div>
          <p className="eyebrow">Cinemate</p>
          <h1>Рекомендации</h1>
          <p>Возможно, вам понравится.</p>
        </div>
        <Link className="primary-link" to="/catalog">
          <span>Открыть каталог</span>
          <ArrowRight size={18} />
        </Link>
      </section>

      <section className="metric-row">
        <div className="metric">
          <Film size={20} />
          <span>Оценок</span>
          <strong>{ratedCount}</strong>
        </div>
        <div className="metric">
          <Sparkles size={20} />
          <span>Буду смотреть</span>
          <strong>{plannedCount}</strong>
        </div>
        <div className="metric">
          <span className="metric-dot" />
          <span>Средняя оценка</span>
          <strong>{avg ? avg.toFixed(1) : '—'}</strong>
        </div>
      </section>

      {syncError ? <p className="system-note">{syncError}</p> : null}

      <section className="content-section">
        <div className="section-title-row">
          <h2>Для вас</h2>
          <div className="section-actions">
            <button className="secondary-button small-button" type="button" onClick={refreshRecommendations} disabled={refreshing}>
              <RefreshCw size={16} />
              {refreshing ? 'Обновляем...' : 'Обновить'}
            </button>
            <Link to="/analytics">Ваши предпочтения</Link>
          </div>
        </div>

        {recommendationNote ? <p className="system-note">{recommendationNote}</p> : null}

        {loading && visibleRecommendations.length === 0 ? (
          <div className="movie-grid skeleton-grid">
            {Array.from({ length: 4 }, (_, index) => (
              <span className="movie-skeleton" key={index} />
            ))}
          </div>
        ) : visibleRecommendations.length ? (
          <div className="movie-grid">
            {visibleRecommendations.slice(0, 4).map((movie) => (
              <MovieCard
                key={movie.movie_id}
                movie={movie}
                inWatchlist={library.watchlistIds.includes(movie.movie_id)}
                rating={library.ratings[movie.movie_id]}
                onToggleWatchlist={toggleWatchlist}
                onRate={rateMovie}
              />
            ))}
          </div>
        ) : (
          <EmptyState
            title="Пока нет рекомендаций"
            text="Оценивайте фильмы, чтобы получать персональную подборку."
            action={
              <Link className="secondary-button small-button" to="/catalog">
                Перейти в каталог
              </Link>
            }
          />
        )}
      </section>
    </AppLayout>
  );
}
