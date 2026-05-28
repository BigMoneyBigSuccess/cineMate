import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { UserMinus, UserPlus } from 'lucide-react';
import { getUserWatchlist, listMovies } from '../api/movies';
import { listUserReviews } from '../api/reviews';
import {
  followUser,
  getFollowers,
  getFollowing,
  getProfile,
  isFollowing,
  unfollowUser,
} from '../api/social';
import AppLayout from '../components/AppLayout';
import EmptyState from '../components/EmptyState';
import MovieCard from '../components/MovieCard';
import { useMovieLibrary } from '../hooks/useMovieLibrary';
import { useSession } from '../hooks/useSession';
import type { Movie, UserProfile } from '../types/domain';
import { initials } from '../utils/movie';
import { averageRating, countActors, countGenres, ratedMovies } from '../utils/stats';

export default function FriendProfilePage() {
  const { userId: routeUserId = '' } = useParams();
  const { userId: currentUserId, authenticated } = useSession();
  const { library, toggleWatchlist, rateMovie } = useMovieLibrary(currentUserId);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [watchlist, setWatchlist] = useState<Movie[]>([]);
  const [movies, setMovies] = useState<Movie[]>([]);
  const [ratings, setRatings] = useState<Record<string, number>>({});
  const [followers, setFollowers] = useState<string[]>([]);
  const [following, setFollowing] = useState<string[]>([]);
  const [followingProfile, setFollowingProfile] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (!routeUserId) {
      return;
    }

    getProfile(routeUserId)
      .then(setProfile)
      .catch(() => setProfile(null));

    getUserWatchlist(routeUserId)
      .then(setWatchlist)
      .catch(() => setWatchlist([]));

    getFollowers(routeUserId)
      .then(setFollowers)
      .catch(() => setFollowers([]));
    getFollowing(routeUserId)
      .then(setFollowing)
      .catch(() => setFollowing([]));

    Promise.all([
      listMovies({ limit: 200, sort_by: 'imdb_rating', sort_order: 'desc' }),
      listUserReviews(routeUserId),
    ])
      .then(([movieResult, reviews]) => {
        const nextRatings: Record<string, number> = {};
        reviews.forEach((review) => {
          nextRatings[review.movie_id] = review.rating;
        });
        setMovies(movieResult.movies);
        setRatings(nextRatings);
      })
      .catch(() => {
        setMovies([]);
        setRatings({});
      });
  }, [routeUserId]);

  useEffect(() => {
    if (!currentUserId || !routeUserId || currentUserId === routeUserId) {
      return;
    }
    isFollowing(currentUserId, routeUserId)
      .then(setFollowingProfile)
      .catch(() => setFollowingProfile(false));
  }, [currentUserId, routeUserId]);

  const canFollow = authenticated && currentUserId && currentUserId !== routeUserId;
  const profileName = profile?.username || `user_${routeUserId.slice(0, 6)}`;
  const publicLibrary = useMemo(() => ({ watchlistIds: [], ratings }), [ratings]);
  const rated = useMemo(() => ratedMovies(movies, publicLibrary), [movies, publicLibrary]);
  const topGenres = useMemo(() => countGenres(rated).slice(0, 5), [rated]);
  const topActors = useMemo(() => countActors(rated).slice(0, 5), [rated]);
  const avgRating = averageRating(publicLibrary);

  async function handleFollow() {
    if (!routeUserId) {
      return;
    }
    try {
      if (followingProfile) {
        await unfollowUser(routeUserId);
      } else {
        await followUser(routeUserId);
      }
      setFollowingProfile((value) => !value);
      setMessage(followingProfile ? 'Подписка отменена.' : 'Подписка оформлена.');
    } catch {
      setMessage('Не удалось изменить подписку. Попробуйте еще раз.');
    }
  }

  if (!routeUserId) {
    return (
      <AppLayout>
        <EmptyState title="Профиль не найден" text="В ссылке нет ID пользователя." />
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <section className="profile-hero">
        <div className="profile-initials profile-initials-large">
          <span>{initials(profileName)}</span>
        </div>
        <div>
          <p className="eyebrow">Профиль друга</p>
          <h1>{profileName}</h1>
          <p>{profile?.bio || 'Пользователь пока не заполнил описание.'}</p>
          <div className="profile-stats">
            <span>{followers.length} подписчиков</span>
            <span>{following.length} подписок</span>
            <span>{watchlist.length} в списке</span>
            <span>{rated.length} оценок</span>
            <span>{avgRating ? avgRating.toFixed(1) : '—'} средняя</span>
          </div>
        </div>
        {canFollow ? (
          <button className="primary-link" type="button" onClick={handleFollow}>
            {followingProfile ? <UserMinus size={18} /> : <UserPlus size={18} />}
            <span>{followingProfile ? 'Отписаться' : 'Подписаться'}</span>
          </button>
        ) : null}
      </section>

      {message ? <p className="system-note">{message}</p> : null}

      <section className="content-section">
        <div className="section-title-row">
          <h2>Предпочтения</h2>
          <Link to="/friends">К друзьям</Link>
        </div>
        <div className="tag-row">
          {topGenres.length ? (
            topGenres.map((genre) => <span key={genre.label}>{genre.label}</span>)
          ) : (
            <span>Нет данных</span>
          )}
        </div>
        <div className="tag-row tag-row-spaced">
          {topActors.length ? (
            topActors.map((actor) => <span key={actor.label}>{actor.label}</span>)
          ) : (
            <span>Актеры появятся после оценок</span>
          )}
        </div>
      </section>

      <section className="content-section">
        <div className="section-title-row">
          <h2>Последние оценки</h2>
          <span>{rated.length} фильмов</span>
        </div>
        {rated.length ? (
          <div className="rating-table">
            {rated.slice(0, 8).map((movie) => (
              <div key={movie.movie_id}>
                <span>{movie.title}</span>
                <strong>{ratings[movie.movie_id] || '—'}/10</strong>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState title="Оценок пока нет" text="Пользователь еще не оценивал фильмы." />
        )}
      </section>

      <section className="content-section">
        <div className="section-title-row">
          <h2>Будет смотреть</h2>
          <span>{watchlist.length} фильмов</span>
        </div>
        <div className="movie-grid">
          {watchlist.map((movie) => (
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
    </AppLayout>
  );
}
