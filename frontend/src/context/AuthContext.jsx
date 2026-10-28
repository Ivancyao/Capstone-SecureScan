import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../services/index.js";

const AuthCtx = createContext(null);
export const useAuth = () => useContext(AuthCtx);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [cargando, setCargando] = useState(true);
  const salidaManual = useRef(false); // si la persona cerró sesión a propósito, el login no recuerda la página anterior

  useEffect(() => {
    if (!api.hayToken()) {
      setCargando(false);
      return;
    }
    api
      .me()
      .then(setUser)
      .catch(() => api.logout())
      .finally(() => setCargando(false));
  }, []);

  const login = useCallback(async (email, password) => {
    await api.login(email, password);
    salidaManual.current = false;
    const u = await api.me();
    setUser(u);
    return u;
  }, []);
  const registrar = useCallback((datos) => api.register(datos), []);
  const salir = useCallback(() => {
    salidaManual.current = true;
    api.logout();
    setUser(null);
  }, []);

  const value = useMemo(() => ({ user, setUser, cargando, login, registrar, salir, salidaManual: () => salidaManual.current }), [user, cargando, login, registrar, salir]);
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}
