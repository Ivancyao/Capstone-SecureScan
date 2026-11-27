import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";
import { Icon } from "../components/Icon.jsx";

// Avisos emergentes (toast) para confirmar acciones o mostrar errores. Máximo 4 a la vez; desaparecen solos (los errores tardan más).
const ToastCtx = createContext(null);
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const contador = useRef(0);

  const cerrar = useCallback((id) => setItems((itemsActuales) => itemsActuales.filter((item) => item.id !== id)), []);
  const toast = useCallback(
    (tipo, titulo, texto) => {
      const id = ++contador.current;
      setItems((itemsActuales) => [...itemsActuales.slice(-3), { id, tipo, titulo, texto }]);
      setTimeout(() => cerrar(id), tipo === "error" ? 7000 : 4500);
    },
    [cerrar]
  );
  const api = useMemo(
    () => ({
      ok: (titulo, texto) => toast("ok", titulo, texto),
      error: (titulo, texto) => toast("error", titulo, texto),
      info: (titulo, texto) => toast("info", titulo, texto),
    }),
    [toast]
  );

  return (
    <ToastCtx.Provider value={api}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((item) => (
          <div key={item.id} className={`toast toast-${item.tipo}`}>
            <Icon name={item.tipo === "error" ? "alert" : item.tipo === "ok" ? "check-circle" : "info"} size={18} />
            <div>
              <strong>{item.titulo}</strong>
              {item.texto && <p>{item.texto}</p>}
            </div>
            <button className="toast-x" onClick={() => cerrar(item.id)} aria-label="Cerrar aviso">
              <Icon name="x" size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
