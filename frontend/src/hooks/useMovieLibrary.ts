import { useCallback, useEffect, useState } from 'react';
import { addToWatchlist, getWatchlist, removeFromWatchlist } from '../api/movies';
import { listUserReviews, upsertMovieReview } from '../api/reviews';
import type { LibraryState, Movie } from '../types/domain';

const emptyLibrary: LibraryState = {
  watchlistIds: [],
  ratings: {},
};

export function useMovieLibrary(userId: string | null) {
  const [library, setLibrary] = useState<LibraryState>(emptyLibrary);
  const [syncError, setSyncError] = useState('');

  useEffect(() => {
    if (!userId) {
      setLibrary(emptyLibrary);
      return;
    }

    let cancelled = false;

    Promise.all([getWatchlist(), listUserReviews(userId)])
      .then(([watchlist, reviews]) => {
        if (cancelled) {
          return;
        }

        const ratings: Record<string, number> = {};
        reviews.forEach((review) => {
          ratings[review.movie_id] = review.rating;
        });

        setLibrary({
          watchlistIds: watchlist.map((movie) => movie.movie_id),
          ratings,
        });
        setSyncError('');
      })
      .catch(() => {
        if (!cancelled) {
          setLibrary(emptyLibrary);
          setSyncError('Не удалось загрузить список и оценки. Обновите страницу.');
        }
      });

    return () => {
      cancelled = true;
    };
  }, [userId]);

  const toggleWatchlist = useCallback(
    async (movie: Movie) => {
      if (!userId) {
        setSyncError('Войдите, чтобы добавить фильм в список.');
        return;
      }

      const wasAdded = library.watchlistIds.includes(movie.movie_id);
      setLibrary((current) => ({
        ...current,
        watchlistIds: wasAdded
          ? current.watchlistIds.filter((id) => id !== movie.movie_id)
          : [...current.watchlistIds, movie.movie_id],
      }));

      try {
        if (wasAdded) {
          await removeFromWatchlist(movie);
        } else {
          await addToWatchlist(movie);
        }
        setSyncError('');
      } catch {
        setLibrary((current) => ({
          ...current,
          watchlistIds: wasAdded
            ? [...current.watchlistIds, movie.movie_id]
            : current.watchlistIds.filter((id) => id !== movie.movie_id),
        }));
        setSyncError('Не удалось изменить список. Попробуйте еще раз.');
      }
    },
    [library.watchlistIds, userId],
  );

  const rateMovie = useCallback(
    async (movie: Movie, rating: number) => {
      if (!userId) {
        setSyncError('Войдите, чтобы поставить оценку.');
        return;
      }

      const previousRating = library.ratings[movie.movie_id];
      setLibrary((current) => ({
        ...current,
        ratings: {
          ...current.ratings,
          [movie.movie_id]: rating,
        },
      }));

      try {
        await upsertMovieReview(movie.movie_id, rating);
        setSyncError('');
      } catch {
        setLibrary((current) => {
          const ratings = { ...current.ratings };
          if (previousRating === undefined) {
            delete ratings[movie.movie_id];
          } else {
            ratings[movie.movie_id] = previousRating;
          }
          return {
            ...current,
            ratings,
          };
        });
        setSyncError('Не удалось сохранить оценку. Попробуйте еще раз.');
      }
    },
    [library.ratings, userId],
  );

  return {
    library,
    syncError,
    toggleWatchlist,
    rateMovie,
  };
}
