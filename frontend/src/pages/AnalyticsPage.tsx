import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { listMovies } from '../api/movies';
import AppLayout from '../components/AppLayout';
import EmptyState from '../components/EmptyState';
import { useMovieLibrary } from '../hooks/useMovieLibrary';
import { useSession } from '../hooks/useSession';
import type { Movie } from '../types/domain';
import { averageRating, countActors, countGenres, ratedMovies } from '../utils/stats';

const chartColors = ['#8db8ff', '#f3b45d', '#78d8a2', '#f3776f', '#c7a4ff', '#72d6df'];

export default function AnalyticsPage() {
  const { userId } = useSession();
  const { library } = useMovieLibrary(userId);
  const [movies, setMovies] = useState<Movie[]>([]);

  useEffect(() => {
    listMovies({ limit: 100, sort_by: 'imdb_rating', sort_order: 'desc' })
      .then((result) => {
        setMovies(result.movies);
      })
      .catch(() => {
        setMovies([]);
      });
  }, []);

  const rated = useMemo(() => ratedMovies(movies, library), [movies, library]);
  const genres = useMemo(() => countGenres(rated).slice(0, 6), [rated]);
  const actors = useMemo(() => countActors(rated).slice(0, 6), [rated]);
  const avg = averageRating(library);
  const totalGenreCount = genres.reduce((sum, item) => sum + item.value, 0);
  const pieSegments = genres.reduce(
    (state, item, index) => {
      const next = state.offset + (item.value / Math.max(totalGenreCount, 1)) * 100;
      state.parts.push(`${chartColors[index % chartColors.length]} ${state.offset}% ${next}%`);
      state.offset = next;
      return state;
    },
    { offset: 0, parts: [] as string[] },
  );

  return (
    <AppLayout>
      <section className="page-head">
        <div>
          <p className="eyebrow">Аналитика</p>
          <h1>Статистика оценок</h1>
          <p>Здесь собрана аналитика по вашим оценкам и кинопредпочтениям.</p>
        </div>
      </section>

      <section className="metric-row">
        <div className="metric">
          <span className="metric-dot" />
          <span>Фильмов</span>
          <strong>{rated.length}</strong>
        </div>
        <div className="metric">
          <span className="metric-dot metric-dot-green" />
          <span>Оценок</span>
          <strong>{Object.keys(library.ratings).length}</strong>
        </div>
        <div className="metric">
          <span className="metric-dot metric-dot-orange" />
          <span>Средняя</span>
          <strong>{avg ? avg.toFixed(1) : '—'}</strong>
        </div>
      </section>

      {rated.length === 0 ? (
        <EmptyState
          title="Пока нет данных"
          text="Оценивайте фильмы, чтобы увидеть статистику по своим оценкам."
          action={
            <Link className="primary-link" to="/catalog">
              Открыть каталог
            </Link>
          }
        />
      ) : (
        <>
          <section className="analytics-grid">
            <div className="analytics-panel">
              <div className="section-title-row">
                <h2>Любимые жанры</h2>
                <span>{genres.length}</span>
              </div>
              <div
                className="pie-chart"
                style={{
                  background: pieSegments.parts.length
                    ? `conic-gradient(${pieSegments.parts.join(', ')})`
                    : 'rgba(255, 255, 255, 0.06)',
                }}
              />
              <div className="legend-list">
                {genres.map((item, index) => (
                  <span key={item.label}>
                    <i style={{ backgroundColor: chartColors[index % chartColors.length] }} />
                    {item.label} · {item.value}
                  </span>
                ))}
              </div>
            </div>

            <div className="analytics-panel">
              <div className="section-title-row">
                <h2>Топ актеров</h2>
                <span>{actors.length}</span>
              </div>
              <div className="bar-list">
                {actors.map((item) => (
                  <div className="bar-row" key={item.label}>
                    <span>{item.label}</span>
                    <strong>{item.value}</strong>
                    <i style={{ width: `${(item.value / Math.max(actors[0]?.value || 1, 1)) * 100}%` }} />
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section className="content-section">
            <div className="section-title-row">
              <h2>Последние оценки</h2>
              <Link to="/profile">Коллекция</Link>
            </div>
            <div className="rating-table">
              {rated.slice(0, 8).map((movie) => (
                <div key={movie.movie_id}>
                  <span>{movie.title}</span>
                  <strong>{library.ratings[movie.movie_id] || '—'}/10</strong>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </AppLayout>
  );
}
