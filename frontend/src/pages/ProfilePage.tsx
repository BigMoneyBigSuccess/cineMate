import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Save } from 'lucide-react';
import { getFollowers, getFollowing, getProfile, updateProfile } from '../api/social';
import { listMovies } from '../api/movies';
import AppLayout from '../components/AppLayout';
import EmptyState from '../components/EmptyState';
import MovieCard from '../components/MovieCard';
import { useMovieLibrary } from '../hooks/useMovieLibrary';
import { useSession } from '../hooks/useSession';
import type { Movie, UserProfile } from '../types/domain';
import { initials } from '../utils/movie';
import { averageRating, ratedMovies } from '../utils/stats';

export default function ProfilePage() {
  const { authenticated, userId } = useSession();
  const { library, toggleWatchlist, rateMovie } = useMovieLibrary(userId);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [username, setUsername] = useState('');
  const [bio, setBio] = useState('');
  const [movies, setMovies] = useState<Movie[]>([]);
  const [followers, setFollowers] = useState<UserProfile[]>([]);
  const [following, setFollowing] = useState<UserProfile[]>([]);
  const [friends, setFriends] = useState<UserProfile[]>([]);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (!userId) {
      return;
    }

    getProfile(userId)
      .then((remoteProfile) => {
        setProfile(remoteProfile);
        setUsername(remoteProfile.username || `user_${userId.slice(0, 6)}`);
        setBio(remoteProfile.bio || '');
      })
      .catch(() => {
        setProfile(null);
        setUsername(`user_${userId.slice(0, 6)}`);
        setBio('');
      });
  }, [userId]);

  useEffect(() => {
    listMovies({ limit: 100, sort_by: 'imdb_rating', sort_order: 'desc' })
      .then((result) => setMovies(result.movies))
      .catch(() => setMovies([]));
  }, []);

  useEffect(() => {
    if (!userId) {
      setFollowers([]);
      setFollowing([]);
      setFriends([]);
      return;
    }

    let cancelled = false;

    Promise.all([getFollowers(userId), getFollowing(userId)])
      .then(async ([followerIds, followingIds]) => {
        const uniqueIds = Array.from(new Set([...followerIds, ...followingIds]));
        const profiles = await loadProfiles(uniqueIds);
        if (cancelled) {
          return;
        }

        const profilesById = new Map(profiles.map((item) => [item.user_id, item]));
        const followerProfiles = followerIds
          .map((id) => profilesById.get(id))
          .filter((item): item is UserProfile => Boolean(item));
        const followingProfiles = followingIds
          .map((id) => profilesById.get(id))
          .filter((item): item is UserProfile => Boolean(item));
        const followerSet = new Set(followerIds);
        const friendProfiles = followingProfiles.filter((item) => followerSet.has(item.user_id));

        setFollowers(followerProfiles);
        setFollowing(followingProfiles);
        setFriends(friendProfiles);
      })
      .catch(() => {
        if (!cancelled) {
          setFollowers([]);
          setFollowing([]);
          setFriends([]);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [userId]);

  const selected = useMemo(() => {
    const watchlist = movies.filter((movie) => library.watchlistIds.includes(movie.movie_id));
    const rated = ratedMovies(movies, library);
    return { watchlist, rated };
  }, [movies, library]);

  if (!authenticated || !userId) {
    return (
      <AppLayout>
        <EmptyState
          title="Требуется авторизация"
          text="Открывайте для себя новые фильмы и делитесь мнением с друзьями."
          action={
            <Link className="primary-link" to="/login">
              Войти
            </Link>
          }
        />
      </AppLayout>
    );
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!userId) {
      return;
    }

    setSaving(true);
    setMessage('');
    try {
      await updateProfile(userId, { username: username.trim(), bio: bio.trim() });
      setProfile({ user_id: userId, username: username.trim(), bio: bio.trim() });
      setMessage('Профиль сохранен.');
    } catch {
      setMessage('Не удалось сохранить профиль. Попробуйте еще раз.');
    } finally {
      setSaving(false);
    }
  }

  const displayName = username || profile?.username || 'Профиль';

  return (
    <AppLayout>
      <section className="profile-hero">
        <div className="profile-initials profile-initials-large">
          <span>{initials(displayName) || 'П'}</span>
        </div>
        <div>
          <p className="eyebrow">Мой профиль</p>
          <h1>{displayName}</h1>
          <p>{bio || 'Описание профиля пока не заполнено.'}</p>
          <div className="profile-stats">
            <span>{selected.rated.length} оценок</span>
            <span>{selected.watchlist.length} буду смотреть</span>
            <span>{averageRating(library) ? averageRating(library).toFixed(1) : '—'} средняя</span>
            <span>{friends.length} друзей</span>
            <span>{followers.length} подписчиков</span>
            <span>{following.length} подписок</span>
          </div>
        </div>
      </section>

      <section className="profile-grid">
        <form className="profile-form" onSubmit={handleSubmit}>
          <h2>Редактирование</h2>
          <label className="form-field" htmlFor="username">
            <span>Имя пользователя</span>
            <input
              id="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="username"
            />
          </label>
          <label className="form-field" htmlFor="bio">
            <span>О себе</span>
            <textarea
              id="bio"
              value={bio}
              onChange={(event) => setBio(event.target.value)}
              placeholder="Опишите свой уникальный тонкий вкус"
              rows={5}
            />
          </label>
          {message ? <p className="system-note">{message}</p> : null}
          <button className="primary-button" type="submit" disabled={saving}>
            <Save size={18} />
            {saving ? 'Сохраняем...' : 'Сохранить'}
          </button>
        </form>

        <section className="profile-lists">
          <div className="section-title-row">
            <h2>Буду смотреть</h2>
          </div>
          <div className="compact-movie-list">
            {selected.watchlist.length ? (
              selected.watchlist.slice(0, 4).map((movie) => (
                <MovieCard
                  key={movie.movie_id}
                  movie={movie}
                  inWatchlist
                  rating={library.ratings[movie.movie_id]}
                  onToggleWatchlist={toggleWatchlist}
                  onRate={rateMovie}
                />
              ))
            ) : (
              <EmptyState
                title="Список пуст"
                text="Добавляйте сюда фильмы из каталога, чтобы всегда было что посмотреть вечером."
                action={
                  <Link className="secondary-button small-button" to="/catalog">
                    В каталог
                  </Link>
                }
              />
            )}
          </div>
        </section>
      </section>

      <section className="content-section">
        <div className="section-title-row">
          <h2>Связи</h2>
          <Link to="/friends">Найти профиль</Link>
        </div>
        <div className="social-columns">
          <ProfileLinkList title="Друзья" profiles={friends} emptyText="Взаимных подписок пока нет." />
          <ProfileLinkList title="Подписчики" profiles={followers} emptyText="Подписчиков пока нет." />
          <ProfileLinkList title="Подписки" profiles={following} emptyText="Вы пока ни на кого не подписаны." />
        </div>
      </section>

      <section className="content-section">
        <div className="section-title-row">
          <h2>Мои оценки</h2>
          <Link to="/analytics">Статистика</Link>
        </div>
        <div className="movie-grid">
          {selected.rated.length ? (
            selected.rated.map((movie) => (
              <MovieCard
                key={movie.movie_id}
                movie={movie}
                inWatchlist={library.watchlistIds.includes(movie.movie_id)}
                rating={library.ratings[movie.movie_id]}
                onToggleWatchlist={toggleWatchlist}
                onRate={rateMovie}
              />
            ))
          ) : (
            <EmptyState
              title="Оценок пока нет"
              text="Поставьте оценки фильмам в каталоге."
              action={
                <Link className="secondary-button small-button" to="/catalog">
                  В каталог
                </Link>
              }
            />
          )}
        </div>
      </section>
    </AppLayout>
  );
}

async function loadProfiles(ids: string[]): Promise<UserProfile[]> {
  const result = await Promise.allSettled(ids.map((id) => getProfile(id)));
  return result
    .filter((item): item is PromiseFulfilledResult<UserProfile> => item.status === 'fulfilled')
    .map((item) => item.value);
}

function ProfileLinkList({
  title,
  profiles,
  emptyText,
}: {
  title: string;
  profiles: UserProfile[];
  emptyText: string;
}) {
  return (
    <div className="profile-link-list">
      <div className="section-title-row">
        <h3>{title}</h3>
        <span>{profiles.length}</span>
      </div>
      {profiles.length ? (
        profiles.slice(0, 6).map((profile) => (
          <Link className="profile-link-item" key={profile.user_id} to={`/users/${profile.user_id}`}>
            <span className="profile-initials">{initials(profile.username)}</span>
            <strong>{profile.username}</strong>
          </Link>
        ))
      ) : (
        <p>{emptyText}</p>
      )}
    </div>
  );
}
