import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Aviso, Campo, EmptyState, Modal, PageHeader, SevBadge, useTitulo } from "../components/ui.jsx";
import { SeverityBar } from "../components/charts.jsx";
import { NoEncontrado } from "../components/shared.jsx";
import { useData } from "../context/DataContext.jsx";
import { useToast } from "../context/ToastContext.jsx";
import { contar, SEV, SEVERIDADES, ordenSev } from "../lib/risk.js";
import { fmtCvss, fmtFecha, fmtFechaHora, fmtKb, plural } from "../lib/format.js";
import { api, USE_MOCK } from "../services/index.js";

// Con la API real el PDF lo genera el servidor; en el modo de ejemplo se imprime desde el navegador.
async function bajarPdf(reporte, toast) {
  if (USE_MOCK) {
    toast.info("Descarga de PDF", "En el modo de ejemplo no hay servidor que genere el PDF. Usa Imprimir y elige “Guardar como PDF”.");
    return;
  }
  try {
    await api.descargarReporte(reporte);
  } catch (error) {
    toast.error("No se pudo descargar el PDF", error.message);
  }
}

function GenerarModal({ abierto, onClose, proyectoInicial }) {
  const { data, crearReporte } = useData();
  const navegar = useNavigate();
  const [proyectoId, setProyectoId] = useState(proyectoInicial || "");
  const [titulo, setTitulo] = useState("");
  const [seleccionadas, setSeleccionadas] = useState([]);
  const [cargando, setCargando] = useState(false);

  useEffect(() => {
    if (abierto) setProyectoId(proyectoInicial || data.proyectos[0]?.id || "");
  }, [abierto, proyectoInicial, data.proyectos]);

  const evaluacionesDelProyecto = useMemo(() => data.evaluaciones.filter((evaluacion) => evaluacion.proyecto?.id === proyectoId && evaluacion.estado === "completada"), [data.evaluaciones, proyectoId]);
  // Por defecto, la evaluación más reciente de cada activo.
  useEffect(() => {
    const vistos = new Set();
    setSeleccionadas(evaluacionesDelProyecto.filter((evaluacion) => (vistos.has(evaluacion.activo_id) ? false : vistos.add(evaluacion.activo_id))).map((evaluacion) => evaluacion.id));
  }, [evaluacionesDelProyecto]);

  const alternar = (id) => setSeleccionadas((actuales) => (actuales.includes(id) ? actuales.filter((otra) => otra !== id) : [...actuales, id]));
  const enviar = async (evento) => {
    evento.preventDefault();
    setCargando(true);
    try {
      const reporte = await crearReporte({ proyecto_id: proyectoId, titulo: titulo.trim(), evaluacion_ids: seleccionadas });
      onClose();
      navegar(`/reportes/${reporte.id}`);
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
      titulo="Generar reporte"
      descripcion="Reúne los resultados de un proyecto en un informe legible para equipos técnicos y de gestión."
      ancho={600}
      pie={
        <>
          <button className="btn" type="button" onClick={onClose}>Cancelar</button>
          <button className="btn btn-primary" form="form-reporte" disabled={!proyectoId || seleccionadas.length === 0 || cargando}>
            <Icon name="file" size={15} /> {cargando ? "Generando…" : "Generar reporte"}
          </button>
        </>
      }
    >
      <form id="form-reporte" className="form-grid" onSubmit={enviar}>
        <Campo etiqueta="Proyecto">
          {(id) => (
            <select id={id} className="select" value={proyectoId} onChange={(evento) => setProyectoId(evento.target.value)} required>
              {data.proyectos.map((proyecto) => <option key={proyecto.id} value={proyecto.id}>{proyecto.nombre}</option>)}
            </select>
          )}
        </Campo>
        <Campo etiqueta="Título" ayuda="Si lo dejas vacío se usa “Informe de seguridad” con el nombre del proyecto.">
          {(id) => <input id={id} className="input" value={titulo} onChange={(evento) => setTitulo(evento.target.value)} />}
        </Campo>
        <fieldset className="motores">
          <legend className="label">Evaluaciones incluidas</legend>
          {evaluacionesDelProyecto.length === 0 ? (
            <p className="small muted">Este proyecto no tiene evaluaciones completadas.</p>
          ) : (
            evaluacionesDelProyecto.map((evaluacion) => (
              <label key={evaluacion.id} className="check">
                <input type="checkbox" checked={seleccionadas.includes(evaluacion.id)} onChange={() => alternar(evaluacion.id)} />
                <span>
                  <strong>{evaluacion.activo?.nombre}</strong> <span className="muted">· {fmtFecha(evaluacion.iniciada_en)} · {plural(evaluacion.conteo.total, "hallazgo", "hallazgos")}</span>
                </span>
              </label>
            ))
          )}
        </fieldset>
      </form>
    </Modal>
  );
}

export function Reportes() {
  useTitulo("Reportes");
  const { data, eliminarReporte } = useData();
  const toast = useToast();
  const navegar = useNavigate();
  const [params, setParams] = useSearchParams();
  const [modal, setModal] = useState(!!params.get("proyecto"));
  const proyectoInicial = params.get("proyecto") || "";

  useEffect(() => {
    if (params.get("proyecto")) setModal(true);
  }, [params]);
  const cerrar = () => {
    setModal(false);
    if (params.get("proyecto")) setParams({}, { replace: true });
  };

  const proyectos = data.proyectosPorId;
  return (
    <>
      <PageHeader
        titulo="Reportes"
        descripcion="Informes generados a partir de las evaluaciones de un proyecto. Cada uno resume el riesgo y qué corregir primero."
        acciones={<button className="btn btn-primary" onClick={() => setModal(true)} disabled={data.proyectos.length === 0}><Icon name="plus" size={16} /> Generar reporte</button>}
      />
      {!data.capacidades.reportes && (
        <div className="panel-gap">
          <Aviso tipo="warn">La generación de reportes aún no está disponible en el backend. Esta pantalla ya está lista para conectarse.</Aviso>
        </div>
      )}
      {data.reportes.length === 0 ? (
        <div className="panel">
          <EmptyState icono="file" titulo="Aún no hay reportes" texto="Genera el primero a partir de las evaluaciones de un proyecto." accion={<button className="btn btn-primary" onClick={() => setModal(true)} disabled={data.proyectos.length === 0}>Generar reporte</button>} />
        </div>
      ) : (
        <div className="panel">
          <div className="table-wrap">
            <table className="tabla tabla-clic">
              <thead><tr><th>Reporte</th><th>Proyecto</th><th>Evaluaciones</th><th>Generado</th><th className="right">Tamaño</th><th /></tr></thead>
              <tbody>
                {data.reportes.map((reporte) => (
                  <tr key={reporte.id} onClick={() => navegar(`/reportes/${reporte.id}`)}>
                    <td className="celda-titulo">
                      <Link to={`/reportes/${reporte.id}`} onClick={(evento) => evento.stopPropagation()}>{reporte.titulo}</Link>
                      <span className="sub mono">{reporte.nombre_archivo}</span>
                    </td>
                    <td>{proyectos[reporte.proyecto_id]?.nombre}</td>
                    <td className="num">{reporte.evaluacion_ids.length}</td>
                    <td className="nowrap">{fmtFecha(reporte.generado_en)}<span className="sub">{reporte.generado_por}</span></td>
                    <td className="right num">{fmtKb(reporte.tamano_kb)}</td>
                    <td className="right nowrap" onClick={(evento) => evento.stopPropagation()}>
                      <Link to={`/reportes/${reporte.id}`} className="btn btn-sm">Ver</Link>{" "}
                      <button className="btn btn-quiet btn-icon btn-sm" aria-label={`Descargar ${reporte.titulo}`} onClick={() => bajarPdf(reporte, toast)}>
                        <Icon name="download" size={15} />
                      </button>{" "}
                      <button
                        className="btn btn-quiet btn-icon btn-sm"
                        aria-label={`Eliminar ${reporte.titulo}`}
                        onClick={async () => {
                          if (window.confirm(`¿Eliminar “${reporte.titulo}”? Esta acción no se puede deshacer.`)) {
                            try { await eliminarReporte(reporte.id); } catch { /* aviso mostrado */ }
                          }
                        }}
                      >
                        <Icon name="trash" size={15} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <GenerarModal abierto={modal} onClose={cerrar} proyectoInicial={proyectoInicial} />
    </>
  );
}

// ---------- Vista del reporte (la misma maquetación que tendrá el PDF) ----------
export function ReporteVista() {
  const { id } = useParams();
  const { data } = useData();
  const toast = useToast();
  const reporte = data.reportes.find((otro) => otro.id === id);
  useTitulo(reporte?.titulo || "Reporte");
  if (!reporte) return <NoEncontrado que="El reporte" volver="/reportes" etiqueta="Ver reportes" />;

  const proyecto = data.proyectosPorId[reporte.proyecto_id];
  const evaluaciones = reporte.evaluacion_ids.map((evaluacionId) => data.evaluacionPorId[evaluacionId]).filter(Boolean);
  const hallazgos = evaluaciones.flatMap((evaluacion) => evaluacion.hallazgos.filter((hallazgo) => hallazgo.corregido !== "si").map((hallazgo) => ({ ...hallazgo, activo: evaluacion.activo })));
  const conteo = contar(hallazgos);
  const prioridad = [...hallazgos].sort((primero, segundo) => ordenSev(primero.severidad) - ordenSev(segundo.severidad) || (segundo.cvss_score ?? 0) - (primero.cvss_score ?? 0));
  const recomendaciones = [];
  prioridad.forEach((hallazgo) => {
    if (!recomendaciones.some((existente) => existente.rec === hallazgo.recomendacion)) recomendaciones.push({ rec: hallazgo.recomendacion, h: hallazgo });
  });
  const graves = conteo.critica + conteo.alta;

  return (
    <>
      <div className="no-print">
        <PageHeader
          migas={[{ texto: "Reportes", to: "/reportes" }, { texto: reporte.titulo }]}
          titulo={reporte.titulo}
          descripcion={USE_MOCK ? "Vista previa del informe. Imprímelo o guárdalo como PDF desde el navegador." : "Vista previa del informe. El PDF descargable lo genera el servidor."}
          acciones={
            <>
              <button className="btn btn-primary" onClick={() => bajarPdf(reporte, toast)}>
                <Icon name="download" size={16} /> Descargar PDF
              </button>
              <button className="btn" onClick={() => window.print()}><Icon name="printer" size={16} /> Imprimir</button>
            </>
          }
        />
      </div>

      <article className="doc">
        <header className="doc-portada">
          <p className="doc-marca">SecureScan · Informe de evaluación de vulnerabilidades</p>
          <h1 className="doc-titulo">{reporte.titulo}</h1>
          <dl className="kv doc-meta">
            <dt>Proyecto</dt><dd>{proyecto?.nombre}</dd>
            <dt>Generado</dt><dd>{fmtFechaHora(reporte.generado_en)} por {reporte.generado_por}</dd>
            <dt>Evaluaciones</dt><dd>{evaluaciones.length}</dd>
          </dl>
        </header>

        <section>
          <h2 className="doc-h2">Resumen ejecutivo</h2>
          <p>
            Se evaluaron {plural(new Set(evaluaciones.map((evaluacion) => evaluacion.activo_id)).size, "activo", "activos")} del proyecto <strong>{proyecto?.nombre}</strong>. Quedan {plural(conteo.total, "hallazgo abierto", "hallazgos abiertos")}
            {graves > 0 ? <>, de los cuales <strong>{plural(graves, "es de severidad crítica o alta", "son de severidad crítica o alta")}</strong> y deberían atenderse primero.</> : ", ninguno de severidad crítica o alta."}
          </p>
          <div className="doc-resumen">
            <SeverityBar conteo={conteo} alto={16} />
            <table className="tabla tabla-compacta">
              <thead><tr><th>Severidad</th><th className="right">Hallazgos</th><th>Qué hacer</th></tr></thead>
              <tbody>
                {SEVERIDADES.map((severidad) => (
                  <tr key={severidad}>
                    <td><SevBadge sev={severidad} /></td>
                    <td className="right num">{conteo[severidad]}</td>
                    <td>{SEV[severidad].accion}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section>
          <h2 className="doc-h2">Activos evaluados</h2>
          <table className="tabla tabla-compacta">
            <thead><tr><th>Activo</th><th>Objetivo</th><th>Fecha</th><th className="right">Hallazgos</th></tr></thead>
            <tbody>
              {evaluaciones.map((evaluacion) => (
                <tr key={evaluacion.id}>
                  <td>{evaluacion.activo?.nombre}</td>
                  <td className="mono">{evaluacion.activo?.url_objetivo}</td>
                  <td className="nowrap">{fmtFecha(evaluacion.iniciada_en)}</td>
                  <td className="right num">{evaluacion.conteo.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section>
          <h2 className="doc-h2">Hallazgos priorizados</h2>
          {prioridad.length === 0 ? (
            <p className="muted">No hay hallazgos abiertos.</p>
          ) : (
            <table className="tabla tabla-compacta">
              <thead><tr><th>Severidad</th><th>Hallazgo</th><th>Activo</th><th className="right">CVSS*</th></tr></thead>
              <tbody>
                {prioridad.map((hallazgo) => (
                  <tr key={hallazgo.id}>
                    <td><SevBadge sev={hallazgo.severidad} /></td>
                    <td>{hallazgo.nombre_vulnerabilidad}<span className="sub mono">{hallazgo.evidencia}</span></td>
                    <td>{hallazgo.activo?.nombre}</td>
                    <td className="right num">{fmtCvss(hallazgo.cvss_score)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section>
          <h2 className="doc-h2">Recomendaciones, en orden de prioridad</h2>
          <ol className="doc-recs">
            {recomendaciones.slice(0, 8).map(({ rec, h: hallazgo }) => (
              <li key={rec}>
                <SevBadge sev={hallazgo.severidad} /> <span><strong>{hallazgo.nombre_vulnerabilidad}.</strong> {rec}</span>
              </li>
            ))}
            {recomendaciones.length === 0 && <li className="muted">Sin acciones pendientes.</li>}
          </ol>
        </section>

        <section>
          <h2 className="doc-h2">Alcance y limitaciones</h2>
          <div className="prose small soft">
            <p>La evaluación se ejecutó solo sobre activos propios o autorizados, dentro de redes privadas, con las herramientas indicadas en cada hallazgo.</p>
            <p>*El puntaje CVSS es una estimación basada en reglas según el tipo de servicio expuesto. No corresponde a un cálculo vectorial completo de CVSS v3.1 y sirve para priorizar, no para certificar el riesgo.</p>
            <p>Una evaluación solo refleja el estado del activo en la fecha indicada. Se recomienda repetirla después de corregir.</p>
          </div>
        </section>
      </article>
    </>
  );
}
