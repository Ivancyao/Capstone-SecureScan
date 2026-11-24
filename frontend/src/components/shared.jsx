import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "./Icon.jsx";
import { Campo, EmptyState, Modal, SevBadge } from "./ui.jsx";
import { SeverityBar, Sparkline } from "./charts.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useData } from "../context/DataContext.jsx";
import { useToast } from "../context/ToastContext.jsx";
import { HERRAMIENTAS, SEV, SEVERIDADES, ordenSev, owaspCodigo } from "../lib/risk.js";
import { fmtCvss, fmtFecha, hace, plural } from "../lib/format.js";

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
        {SEVERIDADES.map((severidad) => (
          <li key={severidad} className={conteo[severidad] === 0 ? "cero" : ""}>
            <SevBadge sev={severidad} />
            <span className="sevlist-rango xs muted">CVSS {SEV[severidad].rango}</span>
            <strong className="num">{conteo[severidad]}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------- Tabla de hallazgos (usada en panel, activo, evaluación y hallazgos) ----------
export function TablaHallazgos({ hallazgos, mostrarActivo = false, mostrarFecha = false, vacio = "Sin hallazgos." }) {
  const navegar = useNavigate();
  const orden = [...hallazgos].sort((primero, segundo) => ordenSev(primero.severidad) - ordenSev(segundo.severidad) || (segundo.cvss_score ?? 0) - (primero.cvss_score ?? 0));
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
          {orden.map((hallazgo) => (
            <tr key={hallazgo.id} onClick={() => navegar(`/hallazgos/${hallazgo.id}`)}>
              <td><SevBadge sev={hallazgo.severidad} /></td>
              <td className="celda-titulo">
                <Link to={`/hallazgos/${hallazgo.id}`} onClick={(evento) => evento.stopPropagation()}>{hallazgo.nombre_vulnerabilidad}</Link>
                <span className="sub mono">{hallazgo.evidencia}</span>
              </td>
              {mostrarActivo && (
                <td>
                  {hallazgo.activo?.nombre}
                  <span className="sub">{hallazgo.proyecto?.nombre}</span>
                </td>
              )}
              <td className="right num">{fmtCvss(hallazgo.cvss_score)}</td>
              <td className="nowrap"><span title={hallazgo.categoria_owasp}>{owaspCodigo(hallazgo.categoria_owasp)}</span></td>
              <td>{hallazgo.corregido === "si" ? <span className="tag tag-ok">Corregido</span> : <span className="tag">Abierto</span>}</td>
              {mostrarFecha && <td className="nowrap">{fmtFecha(hallazgo.fecha)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="xs muted tabla-nota">*CVSS estimado por reglas según el servicio expuesto.</p>
    </div>
  );
}

export const nombreHerramienta = (herramienta) => HERRAMIENTAS[herramienta] || herramienta || "—";

// ---------- Botón para iniciar una evaluación y seguirla en vivo ----------
export function EvaluarBoton({ activo, grande = false, pequeno = false, texto = "Evaluar ahora" }) {
  const { iniciarEvaluacion } = useData();
  const navegar = useNavigate();
  const [cargando, setCargando] = useState(false);
  const enCurso = activo.enCurso;
  const iniciar = async () => {
    setCargando(true);
    try {
      const evaluacion = await iniciarEvaluacion(activo.id);
      navegar(`/evaluaciones/${evaluacion.id}`);
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
    <button className={`btn btn-primary ${pequeno ? "btn-sm" : ""} ${grande ? "btn-lg" : ""}`} onClick={iniciar} disabled={cargando}>
      <Icon name="play" size={pequeno ? 13 : 15} />
      {cargando ? "Iniciando…" : texto}
    </button>
  );
}

// ---------- Formularios en diálogo ----------
export function ProyectoModal({ abierto, onClose }) {
  const { crearProyecto } = useData();
  const navegar = useNavigate();
  const [formulario, setFormulario] = useState({ nombre: "", descripcion: "" });
  const [cargando, setCargando] = useState(false);
  const enviar = async (evento) => {
    evento.preventDefault();
    setCargando(true);
    try {
      const proyecto = await crearProyecto(formulario);
      setFormulario({ nombre: "", descripcion: "" });
      onClose();
      navegar(`/proyectos/${proyecto.id}`);
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
          {(id) => <input id={id} className="input" value={formulario.nombre} onChange={(evento) => setFormulario({ ...formulario, nombre: evento.target.value })} minLength={2} maxLength={150} placeholder="Ej.: Sitio institucional" required />}
        </Campo>
        <Campo etiqueta="Descripción" ayuda="Opcional. Ayuda a otras personas a entender el alcance.">
          {(id) => <textarea id={id} className="textarea" value={formulario.descripcion} onChange={(evento) => setFormulario({ ...formulario, descripcion: evento.target.value })} />}
        </Campo>
      </form>
    </Modal>
  );
}

export function ActivoModal({ abierto, onClose, proyectoId }) {
  const { data, crearActivo } = useData();
  const toast = useToast();
  const [formulario, setFormulario] = useState({ proyecto_id: proyectoId || "", nombre: "", url_objetivo: "", descripcion: "" });
  const [cargando, setCargando] = useState(false);
  const idDelProyecto = proyectoId || formulario.proyecto_id;
  const enviar = async (evento) => {
    evento.preventDefault();
    if (!idDelProyecto) return toast.error("Elige un proyecto");
    setCargando(true);
    try {
      await crearActivo(idDelProyecto, { nombre: formulario.nombre, url_objetivo: formulario.url_objetivo, descripcion: formulario.descripcion });
      setFormulario({ proyecto_id: proyectoId || "", nombre: "", url_objetivo: "", descripcion: "" });
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
              <select id={id} className="select" value={formulario.proyecto_id} onChange={(evento) => setFormulario({ ...formulario, proyecto_id: evento.target.value })} required>
                <option value="">Elige un proyecto</option>
                {data.proyectos.map((proyecto) => <option key={proyecto.id} value={proyecto.id}>{proyecto.nombre}</option>)}
              </select>
            )}
          </Campo>
        )}
        <Campo etiqueta="Nombre del activo">
          {(id) => <input id={id} className="input" value={formulario.nombre} onChange={(evento) => setFormulario({ ...formulario, nombre: evento.target.value })} minLength={2} placeholder="Ej.: Portal de matrículas" required />}
        </Campo>
        <Campo etiqueta="URL o dirección del objetivo" ayuda="Debe estar en un entorno propio o autorizado. Ej.: http://10.0.0.5 o app.lab.local">
          {(id) => <input id={id} className="input mono" value={formulario.url_objetivo} onChange={(evento) => setFormulario({ ...formulario, url_objetivo: evento.target.value })} minLength={4} placeholder="http://juiceshop:3000" required />}
        </Campo>
        <Campo etiqueta="Descripción">
          {(id) => <textarea id={id} className="textarea" value={formulario.descripcion} onChange={(evento) => setFormulario({ ...formulario, descripcion: evento.target.value })} />}
        </Campo>
      </form>
    </Modal>
  );
}

// ---------- Tarjetas (toda la tarjeta lleva al detalle; el botón de evaluar queda por encima) ----------
export function TarjetaActivo({ activo, mostrarProyecto = true }) {
  const navegar = useNavigate();
  return (
    <article className="card-i" style={{ "--tone": activo.ultimaOk ? `var(--sev-${activo.maxSev || "informativa"})` : "var(--line-strong)" }} onClick={() => navegar(`/activos/${activo.id}`)}>
      <header className="card-i-head">
        <div className="grow">
          <Link to={`/activos/${activo.id}`} className="titulo card-i-titulo" onClick={(evento) => evento.stopPropagation()}>{activo.nombre}</Link>
          <span className="sub mono">{activo.url_objetivo}</span>
        </div>
        {activo.ultimaOk ? <SevBadge sev={activo.maxSev} /> : <span className="tag">Sin evaluar</span>}
      </header>
      {activo.ultimaOk ? (
        <div className="card-i-datos">
          <SeverityBar conteo={activo.conteo} alto={8} />
          <div className="card-i-fila">
            <span className="small soft"><strong className="num">{activo.conteo.total}</strong> {activo.conteo.total === 1 ? "hallazgo abierto" : "hallazgos abiertos"}</span>
            <Sparkline valores={activo.serie} ancho={72} alto={22} />
          </div>
        </div>
      ) : (
        <p className="small muted">Lanza la primera evaluación para ver su exposición.</p>
      )}
      <footer className="card-i-pie">
        <span className="xs muted">
          {mostrarProyecto && activo.proyecto?.nombre ? `${activo.proyecto.nombre} · ` : ""}
          {activo.ultima ? `evaluado ${hace(activo.ultima.iniciada_en)}` : "sin evaluaciones"}
        </span>
        <span className="card-i-accion" onClick={(evento) => evento.stopPropagation()}>
          <EvaluarBoton activo={activo} pequeno texto="Evaluar" />
        </span>
      </footer>
    </article>
  );
}

export function TarjetaProyecto({ proyecto, dueno }) {
  const navegar = useNavigate();
  return (
    <article className="card-i" style={{ "--tone": proyecto.conteo.total > 0 ? `var(--sev-${proyecto.maxSev || "informativa"})` : "var(--line-strong)" }} onClick={() => navegar(`/proyectos/${proyecto.id}`)}>
      <header className="card-i-head">
        <span className="icono-caja"><Icon name="folder" size={20} /></span>
        <div className="grow">
          <Link to={`/proyectos/${proyecto.id}`} className="titulo card-i-titulo" onClick={(evento) => evento.stopPropagation()}>{proyecto.nombre}</Link>
          <span className="sub">{proyecto.descripcion || "Sin descripción"}</span>
        </div>
      </header>
      <div className="card-i-datos">
        {proyecto.conteo.total > 0 ? <SeverityBar conteo={proyecto.conteo} alto={8} /> : <span className="xs muted">{proyecto.activos.some((activo) => activo.ultimaOk) ? "Sin hallazgos abiertos" : "Sin datos de evaluación"}</span>}
        <div className="card-i-fila">
          <span className="small soft">{plural(proyecto.activos.length, "activo", "activos")}</span>
          {proyecto.conteo.total > 0 && <SevBadge sev={proyecto.maxSev} />}
        </div>
      </div>
      <footer className="card-i-pie">
        <span className="xs muted">{proyecto.ultima ? `última evaluación ${hace(proyecto.ultima.iniciada_en)}` : "sin evaluaciones"}{dueno ? ` · de ${dueno}` : ""}</span>
        <Icon name="chevron-right" size={16} className="card-i-go" />
      </footer>
    </article>
  );
}
