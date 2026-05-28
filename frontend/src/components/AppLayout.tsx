import {
  BarChart3,
  Bookmark,
  Compass,
  LogIn,
  LogOut,
  Search,
  Sparkles,
  UserRound,
  UsersRound,
} from 'lucide-react';
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { getProfile } from '../api/social';
import { initials } from '../utils/movie';
import Brand from './Brand';
import { useSession } from '../hooks/useSession';

interface AppLayoutProps {
  children: ReactNode;
}

const navItems = [
  { to: '/', label: 'Рекомендации', icon: Sparkles },
  { to: '/catalog', label: 'Каталог', icon: Compass },
  { to: '/profile', label: 'Профиль', icon: UserRound },
  { to: '/friends', label: 'Друзья', icon: UsersRound },
  { to: '/analytics', label: 'Аналитика', icon: BarChart3 },
];

export default function AppLayout({ children }: AppLayoutProps) {
  const navigate = useNavigate();
  const { authenticated, userId, signOut } = useSession();
  const [username, setUsername] = useState('Профиль');

  useEffect(() => {
    if (!userId) {
      setUsername('Профиль');
      return;
    }

    let cancelled = false;
    getProfile(userId)
      .then((profile) => {
        if (!cancelled) {
          setUsername(profile.username || 'Профиль');
        }
      })
      .catch(() => {
        if (!cancelled) {
          setUsername('Профиль');
        }
      });

    return () => {
      cancelled = true;
    };
  }, [userId]);

  function handleSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const query = String(form.get('q') || '').trim();
    navigate(query ? `/catalog?q=${encodeURIComponent(query)}` : '/catalog');
  }

  async function handleSignOut() {
    await signOut();
    navigate('/login');
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <Brand />
        <nav className="sidebar-nav" aria-label="Главная навигация">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-link${isActive ? ' nav-link-active' : ''}`}
            >
              <Icon size={18} strokeWidth={2.2} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <form className="global-search" onSubmit={handleSearch}>
            <Search size={18} />
            <input name="q" type="search" placeholder="Фильм, актер или режиссер" />
          </form>

          <div className="topbar-actions">
            <NavLink className="icon-button" to="/catalog" title="Каталог">
              <Bookmark size={18} />
            </NavLink>
            {authenticated ? (
              <>
                <NavLink className="profile-chip" to="/profile" title="Профиль">
                  <span>{initials(username) || 'П'}</span>
                  <strong>{username}</strong>
                </NavLink>
                <button className="icon-button" type="button" onClick={handleSignOut} title="Выйти">
                  <LogOut size={18} />
                </button>
              </>
            ) : (
              <NavLink className="login-link" to="/login">
                <LogIn size={18} />
                <span>Войти</span>
              </NavLink>
            )}
          </div>
        </header>
        {children}
      </section>
    </main>
  );
}
