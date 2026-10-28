import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

const ThemeCtx = createContext(null);
export const useTheme = () => useContext(ThemeCtx);

const leer = () => {
  try {
    return localStorage.getItem("securescan-tema") || "sistema";
  } catch {
    return "sistema";
  }
};

export function ThemeProvider({ children }) {
  const [preferencia, setPreferencia] = useState(leer);
  const [sistemaOscuro, setSistemaOscuro] = useState(() => matchMedia("(prefers-color-scheme: dark)").matches);

  useEffect(() => {
    const mq = matchMedia("(prefers-color-scheme: dark)");
    const fn = (e) => setSistemaOscuro(e.matches);
    mq.addEventListener("change", fn);
    return () => mq.removeEventListener("change", fn);
  }, []);

  const oscuro = preferencia === "oscuro" || (preferencia === "sistema" && sistemaOscuro);
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", oscuro ? "dark" : "light");
  }, [oscuro]);

  const elegir = useCallback((p) => {
    setPreferencia(p);
    try {
      localStorage.setItem("securescan-tema", p);
    } catch {
      /* ignorar */
    }
  }, []);
  const alternar = useCallback(() => elegir(oscuro ? "claro" : "oscuro"), [oscuro, elegir]);

  const value = useMemo(() => ({ preferencia, oscuro, elegir, alternar }), [preferencia, oscuro, elegir, alternar]);
  return <ThemeCtx.Provider value={value}>{children}</ThemeCtx.Provider>;
}
