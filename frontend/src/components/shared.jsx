import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "./Icon.jsx";
import { Campo, EmptyState, Modal, SevBadge } from "./ui.jsx";
import { SeverityBar } from "./charts.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useData } from "../context/DataContext.jsx";
import { useToast } from "../context/ToastContext.jsx";
import { HERRAMIENTAS, SEV, SEVERIDADES, ordenSev, owaspCodigo } from "../lib/risk.js";
import { fmtCvss, fmtFecha } from "../lib/format.js";

// ---------- Recurso inexistente (o ajeno): se responde igual que el backend, con "no encontrado" ----------
export function NoEncontrado({ que = "El recurso", volver = "/panel", etiqueta = "Volver al panel" }) {
  return (
    <div className="panel">
      <EmptyState icono="search" titulo={`${que} no existe`} texto="Puede que se haya eliminado o que pertenezca a otro usuario." accion={<Link to={volver} className="btn">{etiqueta}</Link>} />
    </div>
  );
}

export function SoloAdmin({ children }) {
  const { user } = useAuth();
  if (user?.rol !== "admin") {
    return (
      <div className="panel">
        <EmptyState icono="lock" titulo="Acceso restringido" texto="Esta sección es solo para administradores. Si necesitas acceso, pídeselo a quien administra la plataforma." accion={<Link to="/panel" className="btn">Volver al panel</Link>} />
      </div>
    );
  }
  return children;
}

export function CopiarBoton({ texto, etiqueta = "Copiar" }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-quiet btn-sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(texto);
          setOk(true);
          setTimeout(() => setOk(false), 1600);
        } catch {
          /* sin portapapeles */
        }
      }}
    >
      <Icon name={ok ? "check" : "copy"} size={14} />
      {ok ? "Copiado" : etiqueta}
    </button>
  );
}

// ---------- Resumen por severidad: barra + filas con conteo ----------
export function ResumenSeveridad({ conteo }) {
  return (
    <div className="stack-sm">
      <SeverityBar conteo={conteo} alto={16} />
      <ul className="sevlist">
        {SEVERIDADES.map((s) => (
          <li key={s} className={conteo[s] === 0 ? "cero" : ""}>
            <SevBadge sev={s} />
            <span className="sevlist-rango xs muted">CVSS {SEV[s].rango}</span>
            <strong className="num">{conteo[s]}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------- Tabla de hallazgos (usada en panel, activo, evaluación y hallazgos) ----------
export function TablaHallazgos({ hallazgos, mostrarActivo = false, mostrarFecha = false, vacio = "Sin hallazgos." }) {
  const nav = useNavigate();
  const orden = [...hallazgos].sort((a, b) => ordenSev(a.severidad) - ordenSev(b.severidad) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0));
  if (!orden.length) return <p className="small muted tabla-vacia">{vacio}</p>;
  return (
    <div className="table-wrap">
      <table className="tabla tabla-clic">
        <thead>
          <tr>
            <th>Severidad</th>
            <th>Hallazgo</th>
            {mostrarActivo && <th>Activo</th>}
            <th className="right">CVSS*</th>
            <th>OWASP</th>
            <th>Estado</th>
            {mostrarFecha && <th>Detectado</th>}
          </tr>
        </thead>
        <tbody>
          {orden.map((h) => (
            <tr key={h.id} onClick={() => nav(`/hallazgos/${h.id}`)}>
              <td><SevBadge sev={h.severidad} /></td>
              <td className="celda-titulo">
                <Link to={`/hallazgos/${h.id}`} onClick={(e) => e.stopPropagation()}>{h.nombre_vulnerabilidad}</Link>
                <span className="sub mono">{h.evidencia}</span>
              </td>
              {mostrarActivo && (
                <td>
                  {h.activo?.nombre}
                  <span className="sub">{h.proyecto?.nombre}</span>
                </td>
              )}
              <td className="right num">{fmtCvss(h.cvss_score)}</td>
              <td className="nowrap"><span title={h.categoria_owasp}>{owaspCodigo(h.categoria_owasp)}</span></td>
              <td>{h.corregido === "si" ? <span className="tag tag-ok">Corregido</span> : <span className="tag">Abierto</span>}</td>
              {mostrarFecha && <td className="nowrap">{fmtFecha(h.fecha)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="xs muted tabla-nota">*CVSS estimado por reglas según el servicio expuesto.</p>
    </div>
  );
}

export const nombreHerramienta = (h) => HERRAMIENTAS[h] || h || "—";

// ---------- Botón para iniciar una evaluación y seguirla en vivo ----------
export function EvaluarBoton({ activo, grande = false, pequeno = false, texto = "Evaluar ahora" }) {
  const { iniciarEvaluacion } = useData();
  const nav = useNavigate();
  const [cargando, setCargando] = useState(false);
  const enCurso = activo.enCurso;
  const ir = async () => {
    setCargando(true);
    try {
      const ev = await iniciarEvaluacion(activo.id);
      nav(`/evaluaciones/${ev.id}`);
    } catch {
      /* el aviso de error ya se mostró */
    } finally {
      setCargando(false);
    }
  };
  if (enCurso && activo.ultima) {
    return (
      <Link to={`/evaluaciones/${activo.ultima.id}`} className={`btn ${pequeno ? "btn-sm" : ""} ${grande ? "btn-lg" : ""}`}>
        <span className="estado estado-en_progreso"><i aria-hidden="true" /></span> Ver evaluación en curso
      </Link>
    );
  }
  return (
    <button className={`btn btn-primary ${pequeno ? "btn-sm" : ""} ${grande ? "btn-lg" : ""}`} onClick={ir} disabled={cargando}>
      <Icon name="play" size={pequeno ? 13 : 15} />
      {cargando ? "Iniciando…" : texto}
    </button>
  );
}

// ---------- Formularios en diálogo ----------
export function ProyectoModal({ abierto, onClose }) {
  const { crearProyecto } = useData();
  const nav = useNavigate();
  const [f, setF] = useState({ nombre: "", descripcion: "" });
  const [cargando, setCargando] = useState(false);
  const enviar = async (e) => {
    e.preventDefault();
    setCargando(true);
    try {
      const p = await crearProyecto(f);
      setF({ nombre: "", descripcion: "" });
      onClose();
      nav(`/proyectos/${p.id}`);
    } catch {
      /* aviso mostrado */
    } finally {
      setCargando(false);
    }
  };
  return (
    <Modal
      abierto={abierto}
      onClose={onClose}
      titulo="Nuevo proyecto"
      descripcion="Un proyecto agrupa los activos de una organización o de un contexto de trabajo."
      pie={
        <>
          <button className="btn" type="button" onClick={onClose}>Cancelar</button>
          <button className="btn btn-primary" form="form-proyecto" disabled={cargando}>{cargando ? "Creando…" : "Crear proyecto"}</button>
        </>
      }
    >
      <form id="form-proyecto" className="form-grid" onSubmit={enviar}>
        <Campo etiqueta="Nombre del proyecto">
          {(id) => <input id={id} className="input" value={f.nombre} onChange={(e) => setF({ ...f, nombre: e.target.value })} minLength={2} maxLength={150} placeholder="Ej.: Sitio institucional" required />}
        </Campo>
        <Campo etiqueta="Descripción" ayuda="Opcional. Ayuda a otras personas a entender el alcance.">
          {(id) => <textarea id={id} className="textarea" value={f.descripcion} onChange={(e) => setF({ ...f, descripcion: e.target.value })} />}
        </Campo>
      </form>
    </Modal>
  );
}

export function ActivoModal({ abierto, onClose, proyectoId }) {
  const { data, crearActivo } = useData();
  const toast = useToast();
  const [f, setF] = useState({ proyecto_id: proyectoId || "", nombre: "", url_objetivo: "", descripcion: "" });
  const [cargando, setCargando] = useState(false);
  const pid = proyectoId || f.proyecto_id;
  const enviar = async (e) => {
    e.preventDefault();
    if (!pid) return toast.error("Elige un proyecto");
    setCargando(true);
    try {
      await crearActivo(pid, { nombre: f.nombre, url_objetivo: f.url_objetivo, descripcion: f.descripcion });
      setF({ proyecto_id: proyectoId || "", nombre: "", url_objetivo: "", descripcion: "" });
      onClose();
    } catch {
      /* aviso mostrado */
    } finally {
      setCargando(false);
    }
  };
  return (
    <Modal
      abierto={abierto}
      onClose={onClose}
      titulo="Registrar activo"
      descripcion="Un activo es la aplicación o el servidor que quieres evaluar."
      pie={
        <>
          <button className="btn" type="button" onClick={onClose}>Cancelar</button>
          <button className="btn btn-primary" form="form-activo" disabled={cargando}>{cargando ? "Registrando…" : "Registrar activo"}</button>
        </>
      }
    >
      <form id="form-activo" className="form-grid" onSubmit={enviar}>
        {!proyectoId && (
          <Campo etiqueta="Proyecto">
            {(id) => (
              <select id={id} className="select" value={f.proyecto_id} onChange={(e) => setF({ ...f, proyecto_id: e.target.value })} required>
                <option value="">Elige un proyecto</option>
                {data.proyectos.map((p) => <option key={p.id} value={p.id}>{p.nombre}</option>)}
              </select>
            )}
          </Campo>
        )}
        <Campo etiqueta="Nombre del activo">
          {(id) => <input id={id} className="input" value={f.nombre} onChange={(e) => setF({ ...f, nombre: e.target.value })} minLength={2} placeholder="Ej.: Portal de matrículas" required />}
        </Campo>
        <Campo etiqueta="URL o dirección del objetivo" ayuda="Debe estar en un entorno propio o autorizado. Ej.: http://10.0.0.5 o app.lab.local">
          {(id) => <input id={id} className="input mono" value={f.url_objetivo} onChange={(e) => setF({ ...f, url_objetivo: e.target.value })} minLength={4} placeholder="http://juiceshop:3000" required />}
        </Campo>
        <Campo etiqueta="Descripción">
          {(id) => <textarea id={id} className="textarea" value={f.descripcion} onChange={(e) => setF({ ...f, descripcion: e.target.value })} />}
        </Campo>
      </form>
    </Modal>
  );
}
