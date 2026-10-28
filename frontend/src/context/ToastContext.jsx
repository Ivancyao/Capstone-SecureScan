import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";
import { Icon } from "../components/Icon.jsx";

const ToastCtx = createContext(null);
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const n = useRef(0);

  const cerrar = useCallback((id) => setItems((xs) => xs.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (tipo, titulo, texto) => {
      const id = ++n.current;
      setItems((xs) => [...xs.slice(-3), { id, tipo, titulo, texto }]);
      setTimeout(() => cerrar(id), tipo === "error" ? 7000 : 4500);
    },
    [cerrar]
  );
  const api = useMemo(
    () => ({
      ok: (t, x) => toast("ok", t, x),
      error: (t, x) => toast("error", t, x),
      info: (t, x) => toast("info", t, x),
    }),
    [toast]
  );

  return (
    <ToastCtx.Provider value={api}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast toast-${t.tipo}`}>
            <Icon name={t.tipo === "error" ? "alert" : t.tipo === "ok" ? "check-circle" : "info"} size={18} />
            <div>
              <strong>{t.titulo}</strong>
              {t.texto && <p>{t.texto}</p>}
            </div>
            <button className="toast-x" onClick={() => cerrar(t.id)} aria-label="Cerrar aviso">
              <Icon name="x" size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
