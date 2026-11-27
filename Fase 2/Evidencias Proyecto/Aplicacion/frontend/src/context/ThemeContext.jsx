import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

// Tema claro/oscuro. Puede ser "claro", "oscuro" o "sistema" (sigue la preferencia del computador). Se guarda en localStorage.
const ThemeCtx = createContext(null);
export const useTheme = () => useContext(ThemeCtx);

const leer = () => {
  try {
    return localStorage.getItem("securescan-tema") || "oscuro";
  } catch {
    return "oscuro";
  }
};

export function ThemeProvider({ children }) {
  const [preferencia, setPreferencia] = useState(leer);
  const [sistemaOscuro, setSistemaOscuro] = useState(() => matchMedia("(prefers-color-scheme: dark)").matches);

  useEffect(() => {
    const consultaOscuro = matchMedia("(prefers-color-scheme: dark)");
    const alCambiar = (evento) => setSistemaOscuro(evento.matches);
    consultaOscuro.addEventListener("change", alCambiar);
    return () => consultaOscuro.removeEventListener("change", alCambiar);
  }, []);

  const oscuro = preferencia === "oscuro" || (preferencia === "sistema" && sistemaOscuro);
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", oscuro ? "dark" : "light");
  }, [oscuro]);

  const elegir = useCallback((nuevaPreferencia) => {
    setPreferencia(nuevaPreferencia);
    try {
      localStorage.setItem("securescan-tema", nuevaPreferencia);
    } catch {
      /* ignorar */
    }
  }, []);
  const alternar = useCallback(() => elegir(oscuro ? "claro" : "oscuro"), [oscuro, elegir]);

  const value = useMemo(() => ({ preferencia, oscuro, elegir, alternar }), [preferencia, oscuro, elegir, alternar]);
  return <ThemeCtx.Provider value={value}>{children}</ThemeCtx.Provider>;
}
