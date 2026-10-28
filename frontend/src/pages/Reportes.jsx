import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Aviso, Campo, EmptyState, Modal, PageHeader, Panel, SevBadge, Tag, useTitulo } from "../components/ui.jsx";
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
  } catch (e) {
    toast.error("No se pudo descargar el PDF", e.message);
  }
}

function GenerarModal({ abierto, onClose, proyectoInicial }) {
  const { data, crearReporte } = useData();
  const nav = useNavigate();
  const [pid, setPid] = useState(proyectoInicial || "");
  const [titulo, setTitulo] = useState("");
  const [sel, setSel] = useState([]);
  const [cargando, setCargando] = useState(false);

  useEffect(() => {
    if (abierto) setPid(proyectoInicial || data.proyectos[0]?.id || "");
  }, [abierto, proyectoInicial, data.proyectos]);

  const evals = useMemo(() => data.evaluaciones.filter((e) => e.proyecto?.id === pid && e.estado === "completada"), [data.evaluaciones, pid]);
  // Por defecto, la evaluación más reciente de cada activo.
  useEffect(() => {
    const vistos = new Set();
    setSel(evals.filter((e) => (vistos.has(e.activo_id) ? false : vistos.add(e.activo_id))).map((e) => e.id));
  }, [evals]);

  const alternar = (id) => setSel((x) => (x.includes(id) ? x.filter((y) => y !== id) : [...x, id]));
  const enviar = async (e) => {
    e.preventDefault();
    setCargando(true);
    try {
      const r = await crearReporte({ proyecto_id: pid, titulo: titulo.trim(), evaluacion_ids: sel });
      onClose();
      nav(`/reportes/${r.id}`);
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
          <button className="btn btn-primary" form="form-reporte" disabled={!pid || sel.length === 0 || cargando}>
            <Icon name="file" size={15} /> {cargando ? "Generando…" : "Generar reporte"}
          </button>
        </>
      }
    >
      <form id="form-reporte" className="form-grid" onSubmit={enviar}>
        <Campo etiqueta="Proyecto">
          {(id) => (
            <select id={id} className="select" value={pid} onChange={(e) => setPid(e.target.value)} required>
              {data.proyectos.map((p) => <option key={p.id} value={p.id}>{p.nombre}</option>)}
            </select>
          )}
        </Campo>
        <Campo etiqueta="Título" ayuda="Si lo dejas vacío se usa “Informe de seguridad” con el nombre del proyecto.">
          {(id) => <input id={id} className="input" value={titulo} onChange={(e) => setTitulo(e.target.value)} />}
        </Campo>
        <fieldset className="motores">
          <legend className="label">Evaluaciones incluidas</legend>
          {evals.length === 0 ? (
            <p className="small muted">Este proyecto no tiene evaluaciones completadas.</p>
          ) : (
            evals.map((e) => (
              <label key={e.id} className="check">
                <input type="checkbox" checked={sel.includes(e.id)} onChange={() => alternar(e.id)} />
                <span>
                  <strong>{e.activo?.nombre}</strong> <span className="muted">· {fmtFecha(e.iniciada_en)} · {plural(e.conteo.total, "hallazgo", "hallazgos")}</span>
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
  const nav = useNavigate();
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
                {data.reportes.map((r) => (
                  <tr key={r.id} onClick={() => nav(`/reportes/${r.id}`)}>
                    <td className="celda-titulo">
                      <Link to={`/reportes/${r.id}`} onClick={(e) => e.stopPropagation()}>{r.titulo}</Link>
                      <span className="sub mono">{r.nombre_archivo}</span>
                    </td>
                    <td>{proyectos[r.proyecto_id]?.nombre}</td>
                    <td className="num">{r.evaluacion_ids.length}</td>
                    <td className="nowrap">{fmtFecha(r.generado_en)}<span className="sub">{r.generado_por}</span></td>
                    <td className="right num">{fmtKb(r.tamano_kb)}</td>
                    <td className="right nowrap" onClick={(e) => e.stopPropagation()}>
                      <Link to={`/reportes/${r.id}`} className="btn btn-sm">Ver</Link>{" "}
                      <button className="btn btn-quiet btn-icon btn-sm" aria-label={`Descargar ${r.titulo}`} onClick={() => bajarPdf(r, toast)}>
                        <Icon name="download" size={15} />
                      </button>{" "}
                      <button
                        className="btn btn-quiet btn-icon btn-sm"
                        aria-label={`Eliminar ${r.titulo}`}
                        onClick={async () => {
                          if (window.confirm(`¿Eliminar “${r.titulo}”? Esta acción no se puede deshacer.`)) {
                            try { await eliminarReporte(r.id); } catch { /* aviso mostrado */ }
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
  const r = data.reportes.find((x) => x.id === id);
  useTitulo(r?.titulo || "Reporte");
  if (!r) return <NoEncontrado que="El reporte" volver="/reportes" etiqueta="Ver reportes" />;

  const p = data.proyectosPorId[r.proyecto_id];
  const evals = r.evaluacion_ids.map((x) => data.evaluacionPorId[x]).filter(Boolean);
  const hs = evals.flatMap((e) => e.hallazgos.filter((h) => h.corregido !== "si").map((h) => ({ ...h, activo: e.activo })));
  const conteo = contar(hs);
  const prioridad = [...hs].sort((a, b) => ordenSev(a.severidad) - ordenSev(b.severidad) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0));
  const recomendaciones = [];
  prioridad.forEach((h) => {
    if (!recomendaciones.some((x) => x.rec === h.recomendacion)) recomendaciones.push({ rec: h.recomendacion, h });
  });
  const graves = conteo.critica + conteo.alta;

  return (
    <>
      <div className="no-print">
        <PageHeader
          migas={[{ texto: "Reportes", to: "/reportes" }, { texto: r.titulo }]}
          titulo={r.titulo}
          descripcion={USE_MOCK ? "Vista previa del informe. Imprímelo o guárdalo como PDF desde el navegador." : "Vista previa del informe. El PDF descargable lo genera el servidor."}
          acciones={
            <>
              <button className="btn btn-primary" onClick={() => bajarPdf(r, toast)}>
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
          <h1 className="doc-titulo">{r.titulo}</h1>
          <dl className="kv doc-meta">
            <dt>Proyecto</dt><dd>{p?.nombre}</dd>
            <dt>Generado</dt><dd>{fmtFechaHora(r.generado_en)} por {r.generado_por}</dd>
            <dt>Evaluaciones</dt><dd>{evals.length}</dd>
          </dl>
        </header>

        <section>
          <h2 className="doc-h2">Resumen ejecutivo</h2>
          <p>
            Se evaluaron {plural(new Set(evals.map((e) => e.activo_id)).size, "activo", "activos")} del proyecto <strong>{p?.nombre}</strong>. Quedan {plural(conteo.total, "hallazgo abierto", "hallazgos abiertos")}
            {graves > 0 ? <>, de los cuales <strong>{plural(graves, "es de severidad crítica o alta", "son de severidad crítica o alta")}</strong> y deberían atenderse primero.</> : ", ninguno de severidad crítica o alta."}
          </p>
          <div className="doc-resumen">
            <SeverityBar conteo={conteo} alto={16} />
            <table className="tabla tabla-compacta">
              <thead><tr><th>Severidad</th><th className="right">Hallazgos</th><th>Qué hacer</th></tr></thead>
              <tbody>
                {SEVERIDADES.map((s) => (
                  <tr key={s}>
                    <td><SevBadge sev={s} /></td>
                    <td className="right num">{conteo[s]}</td>
                    <td>{SEV[s].accion}</td>
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
              {evals.map((e) => (
                <tr key={e.id}>
                  <td>{e.activo?.nombre}</td>
                  <td className="mono">{e.activo?.url_objetivo}</td>
                  <td className="nowrap">{fmtFecha(e.iniciada_en)}</td>
                  <td className="right num">{e.conteo.total}</td>
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
                {prioridad.map((h) => (
                  <tr key={h.id}>
                    <td><SevBadge sev={h.severidad} /></td>
                    <td>{h.nombre_vulnerabilidad}<span className="sub mono">{h.evidencia}</span></td>
                    <td>{h.activo?.nombre}</td>
                    <td className="right num">{fmtCvss(h.cvss_score)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section>
          <h2 className="doc-h2">Recomendaciones, en orden de prioridad</h2>
          <ol className="doc-recs">
            {recomendaciones.slice(0, 8).map(({ rec, h }) => (
              <li key={rec}>
                <SevBadge sev={h.severidad} /> <span><strong>{h.nombre_vulnerabilidad}.</strong> {rec}</span>
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
