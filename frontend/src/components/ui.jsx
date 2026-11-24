import { useEffect, useId, useRef, useState } from "react";
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
        <rect width="32" height="32" rx="8" fill="#0B0F1E" />
        <rect x="0.5" y="0.5" width="31" height="31" rx="7.5" fill="none" stroke="#2B3552" />
        <rect x="6" y="6" width="9" height="9" rx="2" fill="#7B92FF" />
        <rect x="17" y="6" width="9" height="9" rx="2" fill="#2B3552" />
        <rect x="6" y="17" width="9" height="9" rx="2" fill="#2B3552" />
        <rect x="17" y="17" width="9" height="9" rx="2" fill="#FF8A3D" />
      </svg>
      {texto && <span className="logo-texto">SecureScan</span>}
    </span>
  );
}

// ---------- Severidad: color + forma + texto (nunca solo color) ----------
export function SevMark({ sev, size = 12 }) {
  const color = `var(--sev-${sev})`;
  const tamano = size;
  let forma;
  if (sev === "critica") forma = <rect x="2.2" y="2.2" width="7.6" height="7.6" rx="1" transform="rotate(45 6 6)" fill={color} />;
  else if (sev === "alta") forma = <path d="M6 1.3 11 10.2H1z" fill={color} strokeLinejoin="round" stroke={color} strokeWidth="1" />;
  else if (sev === "media") forma = <rect x="1.5" y="1.5" width="9" height="9" rx="2" fill={color} />;
  else if (sev === "baja") forma = <circle cx="6" cy="6" r="4.6" fill={color} />;
  else forma = <circle cx="6" cy="6" r="4" fill="none" stroke={color} strokeWidth="1.8" />;
  return (
    <svg width={tamano} height={tamano} viewBox="0 0 12 12" aria-hidden="true" className="sevmark">
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
          {migas.map((miga, indice) => (
            <span key={indice}>
              {miga.to ? <Link to={miga.to}>{miga.texto}</Link> : <span aria-current="page">{miga.texto}</span>}
              {indice < migas.length - 1 && <Icon name="chevron-right" size={13} />}
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
      {opciones.map((opcion) => (
        <button key={opcion.valor} type="button" className={valor === opcion.valor ? "on" : ""} aria-pressed={valor === opcion.valor} onClick={() => onChange(opcion.valor)}>
          {opcion.etiqueta}
          {opcion.n != null && <span className="seg-n num">{opcion.n}</span>}
        </button>
      ))}
    </div>
  );
}

export function Tabs({ tabs, valor, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((pestana) => (
        <button key={pestana.valor} role="tab" aria-selected={valor === pestana.valor} className={valor === pestana.valor ? "on" : ""} onClick={() => onChange(pestana.valor)}>
          {pestana.etiqueta}
          {pestana.n != null && <span className="seg-n num">{pestana.n}</span>}
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
    const onKey = (evento) => {
      if (evento.key === "Escape") onClose();
      if (evento.key === "Tab" && ref.current) {
        const enfocables = ref.current.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])');
        if (!enfocables.length) return;
        const first = enfocables[0];
        const last = enfocables[enfocables.length - 1];
        if (evento.shiftKey && document.activeElement === first) {
          evento.preventDefault();
          last.focus();
        } else if (!evento.shiftKey && document.activeElement === last) {
          evento.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    const temporizador = setTimeout(() => ref.current?.querySelector("input,select,textarea,button.btn-primary")?.focus(), 30);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      clearTimeout(temporizador);
      previo?.focus?.();
    };
  }, [abierto, onClose]);
  if (!abierto) return null;
  return (
    <div className="modal-overlay" onMouseDown={(evento) => evento.target === evento.currentTarget && onClose()}>
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

// ---------- Cifra que sube hasta su valor (una sola vez al montar; sin animación si se prefiere menos movimiento) ----------
export function Contador({ valor, duracion = 700 }) {
  const [valorMostrado, setValorMostrado] = useState(0);
  useEffect(() => {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches || !valor) {
      setValorMostrado(valor);
      return undefined;
    }
    let raf;
    const inicio = performance.now();
    const paso = (marcaDeTiempo) => {
      const avance = Math.min(1, (marcaDeTiempo - inicio) / duracion);
      setValorMostrado(Math.round(valor * (1 - Math.pow(1 - avance, 3))));
      if (avance < 1) raf = requestAnimationFrame(paso);
    };
    raf = requestAnimationFrame(paso);
    return () => cancelAnimationFrame(raf);
  }, [valor, duracion]);
  return <span className="num">{valorMostrado}</span>;
}

// ---------- Tarjeta de cifra clave: toda ella es un enlace ----------
export function TarjetaKpi({ to, icono, etiqueta, valor, pie, tono = "var(--accent)" }) {
  return (
    <Link to={to} className="kpi" style={{ "--kpi-c": tono }}>
      <span className="kpi-top">
        <span className="kpi-ic"><Icon name={icono} size={18} /></span>
        <Icon name="chevron-right" size={16} className="kpi-go" />
      </span>
      <span className="kpi-n"><Contador valor={valor} /></span>
      <span className="kpi-et">{etiqueta}</span>
      {pie && <span className="kpi-pie">{pie}</span>}
    </Link>
  );
}
