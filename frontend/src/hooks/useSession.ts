import { useCallback, useMemo, useState } from 'react';
import { logout } from '../api/auth';
import { getCurrentUserId, getToken, removeToken } from '../auth/tokenStorage';

export function useSession() {
  const [token, setToken] = useState<string | null>(() => getToken());
  const userId = useMemo(() => getCurrentUserId(), [token]);

  const refresh = useCallback(() => {
    setToken(getToken());
  }, []);

  const signOut = useCallback(async () => {
    try {
      if (getToken()) {
        await logout();
      }
    } catch {
    } finally {
      removeToken();
      setToken(null);
    }
  }, []);

  return {
    token,
    userId,
    authenticated: Boolean(token && userId),
    refresh,
    signOut,
  };
}
