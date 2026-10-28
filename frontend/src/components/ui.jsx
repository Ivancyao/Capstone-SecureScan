import { useEffect, useId, useRef } from "react";
import { Link } from "react-router-dom";
import { Icon } from "./Icon.jsx";
import { ESTADOS, ROLES, SEV } from "../lib/risk.js";
import { iniciales } from "../lib/format.js";

export function useTitulo(titulo) {
  useEffect(() => {
    document.title = titulo ? `${titulo} · SecureScan` : "SecureScan";
  }, [titulo]);
}

// ---------- Marca ----------
export function Logo({ size = 30, texto = true, claro = false }) {
  return (
    <span className={`logo ${claro ? "logo-claro" : ""}`}>
      <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
        <rect width="32" height="32" rx="7" fill="#0B2038" />
        <rect x="6" y="6" width="9" height="9" rx="2" fill="#2BB6D6" />
        <rect x="17" y="6" width="9" height="9" rx="2" fill="#3A5370" />
        <rect x="6" y="17" width="9" height="9" rx="2" fill="#3A5370" />
        <rect x="17" y="17" width="9" height="9" rx="2" fill="#E06A1B" />
      </svg>
      {texto && <span className="logo-texto">SecureScan</span>}
    </span>
  );
}

// ---------- Severidad: color + forma + texto (nunca solo color) ----------
export function SevMark({ sev, size = 12 }) {
  const c = `var(--sev-${sev})`;
  const s = size;
  let forma;
  if (sev === "critica") forma = <rect x="2.2" y="2.2" width="7.6" height="7.6" rx="1" transform="rotate(45 6 6)" fill={c} />;
  else if (sev === "alta") forma = <path d="M6 1.3 11 10.2H1z" fill={c} strokeLinejoin="round" stroke={c} strokeWidth="1" />;
  else if (sev === "media") forma = <rect x="1.5" y="1.5" width="9" height="9" rx="2" fill={c} />;
  else if (sev === "baja") forma = <circle cx="6" cy="6" r="4.6" fill={c} />;
  else forma = <circle cx="6" cy="6" r="4" fill="none" stroke={c} strokeWidth="1.8" />;
  return (
    <svg width={s} height={s} viewBox="0 0 12 12" aria-hidden="true" className="sevmark">
      {forma}
    </svg>
  );
}

export function SevBadge({ sev, compacto = false }) {
  if (!sev) return <span className="muted">—</span>;
  return (
    <span className={`badge sevbg-${sev}`}>
      <SevMark sev={sev} />
      {compacto ? SEV[sev].label.slice(0, 4) + "." : SEV[sev].label}
    </span>
  );
}

export function EstadoBadge({ estado }) {
  return (
    <span className={`estado estado-${estado}`}>
      <i aria-hidden="true" />
      {ESTADOS[estado] || estado}
    </span>
  );
}

export function RolBadge({ rol }) {
  return <span className={`tag tag-${rol}`}>{ROLES[rol] || rol}</span>;
}

export function Tag({ children, tono }) {
  return <span className={`tag ${tono ? `tag-${tono}` : ""}`}>{children}</span>;
}

export function Avatar({ nombre, size = 32 }) {
  return (
    <span className="avatar" style={{ width: size, height: size, fontSize: size * 0.38 }} aria-hidden="true">
      {iniciales(nombre)}
    </span>
  );
}

// ---------- Estructura de página ----------
export function PageHeader({ titulo, descripcion, acciones, migas = [] }) {
  return (
    <header className="ph">
      {migas.length > 0 && (
        <nav className="crumbs" aria-label="Ruta de navegación">
          {migas.map((m, i) => (
            <span key={i}>
              {m.to ? <Link to={m.to}>{m.texto}</Link> : <span aria-current="page">{m.texto}</span>}
              {i < migas.length - 1 && <Icon name="chevron-right" size={13} />}
            </span>
          ))}
        </nav>
      )}
      <div className="ph-row">
        <div className="ph-text">
          <h1 className="h-title">{titulo}</h1>
          {descripcion && <p className="ph-sub">{descripcion}</p>}
        </div>
        {acciones && <div className="ph-actions">{acciones}</div>}
      </div>
    </header>
  );
}

export function Panel({ titulo, descripcion, acciones, children, flush = false, className = "", id }) {
  return (
    <section className={`panel ${className}`} id={id}>
      {(titulo || acciones) && (
        <div className="panel-head">
          <div>
            {titulo && <h2 className="h-section">{titulo}</h2>}
            {descripcion && <p className="small muted panel-desc">{descripcion}</p>}
          </div>
          {acciones && <div className="panel-actions">{acciones}</div>}
        </div>
      )}
      <div className={flush ? "panel-body flush" : "panel-body"}>{children}</div>
    </section>
  );
}

export function Seccion({ titulo, descripcion, acciones, children }) {
  return (
    <section className="seccion">
      <div className="seccion-head">
        <div>
          <h2 className="h-section">{titulo}</h2>
          {descripcion && <p className="small muted">{descripcion}</p>}
        </div>
        {acciones}
      </div>
      {children}
    </section>
  );
}

export function EmptyState({ icono = "folder", titulo, texto, accion }) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name={icono} size={22} />
      </span>
      <h3 className="h-sub">{titulo}</h3>
      {texto && <p className="small muted">{texto}</p>}
      {accion}
    </div>
  );
}

export function Spinner({ texto }) {
  return (
    <div className="spinner-wrap" role="status">
      <span className="spinner" aria-hidden="true" />
      {texto && <span className="small muted">{texto}</span>}
    </div>
  );
}

export function ErrorNote({ children, accion }) {
  return (
    <div className="notice notice-error" role="alert">
      <Icon name="alert" size={18} />
      <div>{children}</div>
      {accion}
    </div>
  );
}

export function Aviso({ tipo = "info", children, icono }) {
  return (
    <div className={`notice notice-${tipo}`}>
      <Icon name={icono || (tipo === "warn" ? "alert" : "info")} size={18} />
      <div>{children}</div>
    </div>
  );
}

export function Progress({ valor, indeterminado = false, etiqueta }) {
  return (
    <div className="progress" role="progressbar" aria-label={etiqueta || "Progreso"} aria-valuemin={0} aria-valuemax={100} aria-valuenow={indeterminado ? undefined : valor}>
      <i className={indeterminado ? "indeterminado" : ""} style={indeterminado ? undefined : { width: `${valor}%` }} />
    </div>
  );
}

// ---------- Controles ----------
export function Segmented({ opciones, valor, onChange, etiqueta }) {
  return (
    <div className="segmented" role="group" aria-label={etiqueta}>
      {opciones.map((o) => (
        <button key={o.valor} type="button" className={valor === o.valor ? "on" : ""} aria-pressed={valor === o.valor} onClick={() => onChange(o.valor)}>
          {o.etiqueta}
          {o.n != null && <span className="seg-n num">{o.n}</span>}
        </button>
      ))}
    </div>
  );
}

export function Tabs({ tabs, valor, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.valor} role="tab" aria-selected={valor === t.valor} className={valor === t.valor ? "on" : ""} onClick={() => onChange(t.valor)}>
          {t.etiqueta}
          {t.n != null && <span className="seg-n num">{t.n}</span>}
        </button>
      ))}
    </div>
  );
}

export function Campo({ etiqueta, ayuda, error, children, id }) {
  const auto = useId();
  const fid = id || auto;
  return (
    <div className="field">
      <label htmlFor={fid}>{etiqueta}</label>
      {typeof children === "function" ? children(fid) : children}
      {ayuda && !error && <span className="hint">{ayuda}</span>}
      {error && <span className="field-error">{error}</span>}
    </div>
  );
}

// ---------- Diálogo ----------
export function Modal({ abierto, onClose, titulo, descripcion, children, pie, ancho = 520 }) {
  const ref = useRef(null);
  const tid = useId();
  useEffect(() => {
    if (!abierto) return;
    const previo = document.activeElement;
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab" && ref.current) {
        const f = ref.current.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])');
        if (!f.length) return;
        const first = f[0];
        const last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    const t = setTimeout(() => ref.current?.querySelector("input,select,textarea,button.btn-primary")?.focus(), 30);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      clearTimeout(t);
      previo?.focus?.();
    };
  }, [abierto, onClose]);
  if (!abierto) return null;
  return (
    <div className="modal-overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={tid} style={{ maxWidth: ancho }} ref={ref}>
        <div className="modal-head">
          <div>
            <h2 id={tid} className="h-section">
              {titulo}
            </h2>
            {descripcion && <p className="small muted">{descripcion}</p>}
          </div>
          <button className="btn btn-quiet btn-icon btn-sm" onClick={onClose} aria-label="Cerrar">
            <Icon name="x" size={16} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {pie && <div className="modal-foot">{pie}</div>}
      </div>
    </div>
  );
}
