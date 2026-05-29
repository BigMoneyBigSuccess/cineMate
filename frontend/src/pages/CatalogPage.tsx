import { FormEvent, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Search } from 'lucide-react';
import { listMovies, type MovieListParams } from '../api/movies';
import AppLayout from '../components/AppLayout';
import MovieCard from '../components/MovieCard';
import { useMovieLibrary } from '../hooks/useMovieLibrary';
import { useSession } from '../hooks/useSession';
import type { Movie } from '../types/domain';

const pageSize = 12;

const presets = [
  { id: 'all', label: 'Все', params: {} },
  { id: 'new', label: 'Новые', params: { release_year_from: 2020, sort_by: 'release_year' } },
  { id: 'classic', label: 'Старые', params: { release_year_to: 2005, sort_by: 'release_year' } },
  { id: 'hidden', label: 'Малоизвестные', params: { imdb_rating_to: 7.5, sort_by: 'imdb_rating' } },
] as const;

type PresetId = (typeof presets)[number]['id'];

export default function CatalogPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQuery = searchParams.get('q') || '';
  const [query, setQuery] = useState(initialQuery);
  const [preset, setPreset] = useState<PresetId>('all');
  const [page, setPage] = useState(0);
  const [movies, setMovies] = useState<Movie[]>([]);
  const [hasNextPage, setHasNextPage] = useState(false);
  const [loading, setLoading] = useState(true);
  const { userId } = useSession();
  const { library, syncError, toggleWatchlist, rateMovie } = useMovieLibrary(userId);

  const activePreset = useMemo(() => presets.find((item) => item.id === preset) || presets[0], [preset]);
  const orderedMovies = useMemo(() => {
    const unrated: Movie[] = [];
    const rated: Movie[] = [];

    movies.forEach((movie) => {
      if (library.ratings[movie.movie_id]) {
        rated.push(movie);
      } else {
        unrated.push(movie);
      }
    });

    return [...unrated, ...rated];
  }, [library.ratings, movies]);

  useEffect(() => {
    setQuery(initialQuery);
  }, [initialQuery]);

  useEffect(() => {
    const params: MovieListParams = {
      q: query || undefined,
      limit: pageSize + 1,
      offset: page * pageSize,
      sort_by: 'imdb_rating',
      sort_order: 'desc',
      ...activePreset.params,
    };

    let cancelled = false;
    setLoading(true);
    listMovies(params)
      .then((result) => {
        if (!cancelled) {
          setMovies(result.movies.slice(0, pageSize));
          setHasNextPage(result.movies.length > pageSize);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setMovies([]);
          setHasNextPage(false);
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
  }, [activePreset, page, query]);

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPage(0);
    setSearchParams(query ? { q: query } : {});
  }

  return (
    <AppLayout>
      <section className="page-head">
        <div>
          <p className="eyebrow">Каталог</p>
          <h1>Коллекция фильмов</h1>
          <p>Новинки, культовая классика и глубокое искусство.</p>
        </div>
      </section>

      <section className="catalog-toolbar">
        <form className="catalog-search" onSubmit={submitSearch}>
          <Search size={18} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Поиск по названию, актеру, режиссеру"
          />
          <button type="submit">Найти</button>
        </form>
        <div className="segmented-control">
          {presets.map((item) => (
            <button
              key={item.id}
              className={item.id === preset ? 'segment-active' : ''}
              type="button"
              onClick={() => {
                setPreset(item.id);
                setPage(0);
              }}
            >
              {item.label}
            </button>
          ))}
        </div>
      </section>

      {syncError ? <p className="system-note">{syncError}</p> : null}

      <section className="catalog-results" aria-busy={loading}>
        <div className="section-title-row">
          <h2>{query ? `Результаты: ${query}` : activePreset.label}</h2>
          <span>{loading ? 'Загрузка' : `${movies.length} на странице`}</span>
        </div>
        <div className="movie-grid">
          {loading
            ? Array.from({ length: pageSize }, (_, index) => (
                <span className="movie-skeleton" key={index} />
              ))
            : orderedMovies.map((movie) => (
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
      </section>

      <footer className="pagination">
        <button type="button" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>
          <ChevronLeft size={18} />
          Назад
        </button>
        <span>
          Страница {page + 1}
        </span>
        <button
          type="button"
          disabled={!hasNextPage}
          onClick={() => setPage((value) => value + 1)}
        >
          Вперед
          <ChevronRight size={18} />
        </button>
      </footer>
    </AppLayout>
  );
}
