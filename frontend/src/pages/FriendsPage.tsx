import { FormEvent, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Search, UsersRound } from 'lucide-react';
import { getFollowing, searchUsers } from '../api/social';
import AppLayout from '../components/AppLayout';
import EmptyState from '../components/EmptyState';
import { useSession } from '../hooks/useSession';
import type { UserProfile } from '../types/domain';
import { initials } from '../utils/movie';

export default function FriendsPage() {
  const { userId, authenticated } = useSession();
  const [query, setQuery] = useState('');
  const [profiles, setProfiles] = useState<UserProfile[]>([]);
  const [followingIds, setFollowingIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!userId) {
      return;
    }

    getFollowing(userId)
      .then(setFollowingIds)
      .catch(() => setFollowingIds([]));
  }, [userId]);

  async function handleSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalized = query.trim();
    if (!normalized) {
      setProfiles([]);
      return;
    }

    setLoading(true);
    try {
      const result = await searchUsers(normalized);
      setProfiles(result.profiles);
    } catch {
      setProfiles([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <AppLayout>
      <section className="page-head">
        <div>
          <p className="eyebrow">Социальное</p>
          <h1>Поиск профиля</h1>
          <p>Подпишитесь на своих друзей и посмотрите, что они оценили недавно.</p>
        </div>
      </section>

      <section className="catalog-toolbar">
        <form className="catalog-search" onSubmit={handleSearch}>
          <Search size={18} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Имя пользователя"
          />
          <button type="submit">{loading ? 'Ищем...' : 'Найти'}</button>
        </form>
      </section>

      {!authenticated ? (
        <p className="system-note">Подписки доступны только после входа, но вы можете смотреть чужие профили.</p>
      ) : null}
      <section className="friend-grid">
        {profiles.map((profile) => (
          <Link className="friend-card" key={profile.user_id} to={`/users/${profile.user_id}`}>
            <div className="profile-initials">
              <span>{initials(profile.username)}</span>
            </div>
            <div>
              <strong>{profile.username}</strong>
              <p>{profile.bio || 'Описание не заполнено.'}</p>
              <span>
                {followingIds.includes(profile.user_id) ? 'Вы подписаны' : 'Открыть профиль'}
              </span>
            </div>
          </Link>
        ))}
      </section>

      {profiles.length === 0 ? (
        <EmptyState
          title="Никого не нашли"
          text="Попробуйте другой запрос."
          action={<UsersRound size={24} />}
        />
      ) : null}
    </AppLayout>
  );
}
