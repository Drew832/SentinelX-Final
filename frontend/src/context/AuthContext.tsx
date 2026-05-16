import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { authApi } from "@/api/endpoints";
import { setOnUnauthorized } from "@/api/client";
import type { AppUser, AuthToken, RegisterPending } from "@/types";

interface AuthState {
  user: AppUser | null;
  token: string | null;
  isGuest: boolean;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (email: string, username: string, password: string) => Promise<RegisterPending>;
  verifyEmail: (email: string, code: string) => Promise<void>;
  resendOtp: (email: string) => Promise<RegisterPending>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  logout: () => void;
  enterGuest: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

const TOKEN_KEY = "sentinelx_token";
const USER_KEY = "sentinelx_user";
const GUEST_KEY = "sentinelx_guest";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AppUser | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isGuest, setGuest] = useState<boolean>(false);
  const [loading, setLoading] = useState(true);

  const persist = useCallback((auth: AuthToken | null) => {
    if (!auth) {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      setUser(null);
      setToken(null);
      return;
    }
    localStorage.setItem(TOKEN_KEY, auth.access_token);
    localStorage.setItem(USER_KEY, JSON.stringify(auth.user));
    localStorage.removeItem(GUEST_KEY);
    setUser(auth.user);
    setToken(auth.access_token);
    setGuest(false);
  }, []);

  const logout = useCallback(() => {
    persist(null);
    setGuest(false);
    localStorage.removeItem(GUEST_KEY);
  }, [persist]);

  useEffect(() => {
    setOnUnauthorized(() => {
      logout();
    });
  }, [logout]);

  useEffect(() => {
    const storedToken = localStorage.getItem(TOKEN_KEY);
    const storedUser = localStorage.getItem(USER_KEY);
    const guest = localStorage.getItem(GUEST_KEY) === "1";

    if (storedToken && storedUser) {
      try {
        setUser(JSON.parse(storedUser));
        setToken(storedToken);
      } catch {
        logout();
      }
    } else if (guest) {
      setGuest(true);
    }
    setLoading(false);
  }, [logout]);

  const login = useCallback(
    async (username: string, password: string) => {
      const data = await authApi.login(username, password);
      persist(data);
    },
    [persist],
  );

  const register = useCallback(async (email: string, username: string, password: string) => {
    return authApi.register({ email, username, password });
  }, []);

  const verifyEmail = useCallback(
    async (email: string, code: string) => {
      const data = await authApi.verifyEmail({ email, code });
      persist(data);
    },
    [persist],
  );

  const resendOtp = useCallback(async (email: string) => {
    return authApi.resendOtp({ email });
  }, []);

  const changePassword = useCallback(async (currentPassword: string, newPassword: string) => {
    await authApi.changePassword({ current_password: currentPassword, new_password: newPassword });
  }, []);

  const enterGuest = useCallback(() => {
    localStorage.setItem(GUEST_KEY, "1");
    persist(null);
    setGuest(true);
  }, [persist]);

  const value = useMemo<AuthState>(
    () => ({
      user,
      token,
      isGuest,
      loading,
      login,
      register,
      verifyEmail,
      resendOtp,
      changePassword,
      logout,
      enterGuest,
    }),
    [
      user,
      token,
      isGuest,
      loading,
      login,
      register,
      verifyEmail,
      resendOtp,
      changePassword,
      logout,
      enterGuest,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
