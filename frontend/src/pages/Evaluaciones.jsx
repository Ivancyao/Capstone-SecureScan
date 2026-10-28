import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Aviso, Campo, EmptyState, ErrorNote, EstadoBadge, PageHeader, Panel, Progress, Segmented, Tag, useTitulo } from "../components/ui.jsx";
import { LeyendaSev, SeverityBar } from "../components/charts.jsx";
import { PortMap, construirPuertos } from "../components/PortMap.jsx";
import { EvaluarBoton, NoEncontrado, ResumenSeveridad, TablaHallazgos } from "../components/shared.jsx";
import { useData } from "../context/DataContext.jsx";
import { fmtDuracion, fmtFecha, fmtFechaHora, esHostPrivado, hace, hostDe, plural } from "../lib/format.js";
import { ordenSev } from "../lib/risk.js";

export function Evaluaciones() {
  useTitulo("Evaluaciones");
  const { data } = useData();
  const nav = useNavigate();
  const [filtro, setFiltro] = useState("todas");
  const ev = data.evaluaciones;
  const cuenta = {
    todas: ev.length,
    curso: ev.filter((e) => e.enCurso).length,
    completada: ev.filter((e) => e.estado === "completada").length,
    fallida: ev.filter((e) => e.estado === "fallida").length,
  };
  const lista = ev.filter((e) => filtro === "todas" || (filtro === "curso" ? e.enCurso : e.estado === filtro));

  return (
    <>
      <PageHeader
        titulo="Evaluaciones"
        descripcion="Cada evaluación es una ejecución del escáner sobre un activo. Corren en segundo plano, así que puedes seguir usando la plataforma."
        acciones={<Link to="/evaluaciones/nueva" className="btn btn-primary"><Icon name="play" size={15} /> Nueva evaluación</Link>}
      />
      {ev.length === 0 ? (
        <div className="panel">
          <EmptyState icono="radar" titulo="Aún no hay evaluaciones" texto="Elige un activo y lánzale la primera evaluación para ver sus puertos y hallazgos." accion={<Link to="/evaluaciones/nueva" className="btn btn-primary">Iniciar evaluación</Link>} />
        </div>
      ) : (
        <>
          <div className="filtros">
            <Segmented
              etiqueta="Filtrar por estado"
              valor={filtro}
              onChange={setFiltro}
              opciones={[
                { valor: "todas", etiqueta: "Todas", n: cuenta.todas },
                { valor: "curso", etiqueta: "En curso", n: cuenta.curso },
                { valor: "completada", etiqueta: "Completadas", n: cuenta.completada },
                { valor: "fallida", etiqueta: "Fallidas", n: cuenta.fallida },
              ]}
            />
          </div>
          <div className="panel">
            <div className="table-wrap">
              <table className="tabla tabla-clic">
                <thead><tr><th>Activo</th><th>Estado</th><th>Hallazgos</th><th>Inicio</th><th className="right">Duración</th></tr></thead>
                <tbody>
                  {lista.map((e) => (
                    <tr key={e.id} onClick={() => nav(`/evaluaciones/${e.id}`)}>
                      <td className="celda-titulo">
                        <Link to={`/evaluaciones/${e.id}`} onClick={(x) => x.stopPropagation()}>{e.activo?.nombre}</Link>
                        <span className="sub">{e.proyecto?.nombre}</span>
                      </td>
                      <td>
                        <EstadoBadge estado={e.estado} />
                        {e.enCurso && <div className="mini-prog"><Progress valor={e.progreso || 0} indeterminado={e.progreso == null} /></div>}
                      </td>
                      <td>
                        {e.estado === "completada" ? (
                          <div className="expo"><SeverityBar conteo={e.conteo} alto={10} /><span className="num small">{e.conteo.total}</span></div>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className="nowrap">{fmtFechaHora(e.iniciada_en)}<span className="sub">{hace(e.iniciada_en)}</span></td>
                      <td className="right num">{fmtDuracion(e.iniciada_en, e.finalizada_en)}</td>
                    </tr>
                  ))}
                  {lista.length === 0 && <tr><td colSpan={5} className="muted small">No hay evaluaciones con ese estado.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}

// ---------- Nueva evaluación ----------
export function NuevaEvaluacion() {
  useTitulo("Nueva evaluación");
  const { data, iniciarEvaluacion } = useData();
  const nav = useNavigate();
  const [params] = useSearchParams();
  const previo = data.activoPorId[params.get("activo")];
  const [proyectoId, setProyectoId] = useState(previo?.proyecto_id || "");
  const [activoId, setActivoId] = useState(previo?.id || "");
  const [autorizo, setAutorizo] = useState(false);
  const [cargando, setCargando] = useState(false);
  const [error, setError] = useState("");

  const activos = useMemo(() => data.activos.filter((a) => !proyectoId || a.proyecto_id === proyectoId), [data.activos, proyectoId]);
  const activo = data.activoPorId[activoId];
  const host = activo ? hostDe(activo.url_objetivo) : "";
  const permitido = activo ? esHostPrivado(host) || data.config?.alcance?.permitir_publicas : null;

  const enviar = async (e) => {
    e.preventDefault();
    setError("");
    setCargando(true);
    try {
      const ev = await iniciarEvaluacion(activoId);
      nav(`/evaluaciones/${ev.id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setCargando(false);
    }
  };

  const zapActivo = data.config?.motores?.zap?.activo === true;

  if (data.activos.length === 0)
    return (
      <>
        <PageHeader migas={[{ texto: "Evaluaciones", to: "/evaluaciones" }, { texto: "Nueva" }]} titulo="Nueva evaluación" />
        <div className="panel">
          <EmptyState icono="server" titulo="Primero registra un activo" texto="Una evaluación se lanza sobre un activo: la aplicación o el servidor que quieres revisar." accion={<Link to="/activos" className="btn btn-primary">Ir a activos</Link>} />
        </div>
      </>
    );

  return (
    <>
      <PageHeader migas={[{ texto: "Evaluaciones", to: "/evaluaciones" }, { texto: "Nueva" }]} titulo="Nueva evaluación" descripcion="Elige el activo y confirma que tienes autorización. El escaneo corre en segundo plano y podrás seguirlo en vivo." />
      <div className="grid-main">
        <form className="panel" onSubmit={enviar}>
          <div className="panel-body form-grid">
            <div className="form-2">
              <Campo etiqueta="Proyecto">
                {(id) => (
                  <select id={id} className="select" value={proyectoId} onChange={(e) => { setProyectoId(e.target.value); setActivoId(""); }}>
                    <option value="">Todos los proyectos</option>
                    {data.proyectos.map((p) => <option key={p.id} value={p.id}>{p.nombre}</option>)}
                  </select>
                )}
              </Campo>
              <Campo etiqueta="Activo a evaluar">
                {(id) => (
                  <select id={id} className="select" value={activoId} onChange={(e) => setActivoId(e.target.value)} required>
                    <option value="">Elige un activo</option>
                    {activos.map((a) => <option key={a.id} value={a.id}>{a.nombre}</option>)}
                  </select>
                )}
              </Campo>
            </div>

            {activo && (
              <div className="objetivo">
                <dl className="kv">
                  <dt>Objetivo</dt><dd><code>{activo.url_objetivo}</code></dd>
                  <dt>Dirección</dt><dd><code>{host}</code></dd>
                  <dt>Última evaluación</dt><dd>{activo.ultima ? hace(activo.ultima.iniciada_en) : "Nunca"}</dd>
                </dl>
                {permitido ? (
                  <Aviso tipo="ok" icono="check-circle">La dirección está dentro de los rangos permitidos.</Aviso>
                ) : (
                  <Aviso tipo="warn">
                    <strong>{host} parece una dirección pública.</strong> Por política, SecureScan solo evalúa redes privadas, loopback o link-local; la evaluación será rechazada.
                  </Aviso>
                )}
                {activo.enCurso && <Aviso tipo="info">Este activo ya tiene una evaluación en curso. <Link to={`/evaluaciones/${activo.ultima.id}`}>Ver evaluación</Link></Aviso>}
              </div>
            )}

            <fieldset className="motores">
              <legend className="label">Motores de escaneo</legend>
              <label className="check"><input type="checkbox" checked readOnly disabled /> <span><strong>Nmap</strong><span className="hint block">Puertos abiertos y versiones de servicio.</span></span></label>
              <label className="check"><input type="checkbox" disabled checked={!!zapActivo} readOnly /> <span><strong>OWASP ZAP</strong> {zapActivo ? <Tag tono="ok">Activo</Tag> : <Tag>Desactivado</Tag>}<span className="hint block">{zapActivo ? "Se analizará también la aplicación web (si el objetivo tiene una)." : "Vulnerabilidades de la aplicación web. Un administrador puede activarlo en Configuración."}</span></span></label>
            </fieldset>

            <label className="check check-caja">
              <input type="checkbox" checked={autorizo} onChange={(e) => setAutorizo(e.target.checked)} required />
              <span>Confirmo que soy responsable de este activo o que cuento con autorización escrita para evaluarlo.</span>
            </label>

            {error && <ErrorNote>{error}</ErrorNote>}
          </div>
          <div className="panel-foot">
            <Link to="/evaluaciones" className="btn">Cancelar</Link>
            <button className="btn btn-primary" disabled={!activoId || !autorizo || cargando || activo?.enCurso}>
              <Icon name="play" size={15} /> {cargando ? "Iniciando…" : "Iniciar evaluación"}
            </button>
          </div>
        </form>

        <Panel titulo="Qué va a pasar">
          <ol className="pasos">
            {[
              ["Validar el objetivo", "Se resuelve la dirección una sola vez y se comprueba que esté en un rango permitido."],
              ["Escanear puertos y servicios", "Nmap revisa los puertos y detecta qué servicio y versión responde en cada uno."],
              ["Clasificar el riesgo", "Cada puerto abierto se traduce a un hallazgo con severidad, CVSS estimado y categoría OWASP."],
              ["Guardar los resultados", "Queda un historial para comparar con evaluaciones futuras."],
            ].map(([t, d], i) => (
              <li key={t} className="paso">
                <span className="paso-dot">{i + 1}</span>
                <div><strong>{t}</strong><p className="small muted">{d}</p></div>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
    </>
  );
}

// ---------- Detalle ----------
const ETAPAS = [
  ["Validar el objetivo", 0, 12],
  ["Escanear puertos y servicios", 12, 80],
  ["Clasificar el riesgo", 80, 95],
  ["Guardar los resultados", 95, 101],
];

export function EvaluacionDetalle() {
  const { id } = useParams();
  const { data } = useData();
  const nav = useNavigate();
  const [filtro, setFiltro] = useState("todos");
  const e = data.evaluacionPorId[id];
  useTitulo(e ? `Evaluación de ${e.activo?.nombre}` : "Evaluación");
  if (!e) return <NoEncontrado que="La evaluación" volver="/evaluaciones" etiqueta="Ver evaluaciones" />;

  const a = data.activoPorId[e.activo_id];
  const completada = e.estado === "completada";
  const progreso = e.estado === "pendiente" ? 0 : e.progreso ?? 0;
  const hs = e.hallazgos.map((h) => ({ ...h, activo: a, proyecto: e.proyecto, fecha: e.iniciada_en }));
  const puertosAbiertos = construirPuertos(hs).filter((x) => x.severidad).length;
  const hallazgosWeb = hs.length - hs.filter((h) => /Puerto \d+\/(tcp|udp) abierto/.test(h.evidencia || "")).length;
  const filtrados = hs.filter((h) => filtro === "todos" || (filtro === "abiertos" ? h.corregido !== "si" : h.corregido === "si"));
  const corregidos = hs.filter((h) => h.corregido === "si").length;
  const principal = [...hs].filter((h) => h.corregido !== "si").sort((x, y) => ordenSev(x.severidad) - ordenSev(y.severidad) || (y.cvss_score ?? 0) - (x.cvss_score ?? 0))[0];

  return (
    <>
      <PageHeader
        migas={[{ texto: "Evaluaciones", to: "/evaluaciones" }, { texto: a?.nombre || "Evaluación" }]}
        titulo={`Evaluación de ${a?.nombre}`}
        descripcion={`Iniciada el ${fmtFechaHora(e.iniciada_en)} · ${e.proyecto?.nombre}`}
        acciones={
          <>
            {completada && <Link to={`/reportes?proyecto=${e.proyecto?.id}`} className="btn"><Icon name="file" size={16} /> Generar reporte</Link>}
            {a && !e.enCurso && <EvaluarBoton activo={a} texto="Volver a evaluar" />}
          </>
        }
      />

      {e.enCurso && (
        <div className="grid-main-r">
          <Panel titulo="Escaneo en curso" descripcion="Esta página se actualiza sola">
            <div className="stack-sm">
              <div className="row-between">
                <strong>{e.etapa || "En cola"}</strong>
                <span className="num muted small">{e.progreso != null ? `${progreso}%` : ""}</span>
              </div>
              <Progress valor={progreso} indeterminado={e.estado === "pendiente"} etiqueta="Progreso de la evaluación" />
              <ol className="pasos pasos-sep">
                {ETAPAS.map(([t, desde, hasta], i) => {
                  const hecho = e.estado === "en_progreso" && progreso >= hasta;
                  const actual = e.estado === "en_progreso" && progreso >= desde && progreso < hasta;
                  return (
                    <li key={t} className={`paso ${hecho ? "hecho" : actual ? "actual" : "espera"}`}>
                      <span className="paso-dot">{hecho ? <Icon name="check" size={13} /> : i + 1}</span>
                      <div><strong>{t}</strong></div>
                    </li>
                  );
                })}
              </ol>
            </div>
          </Panel>
          <Panel titulo="Puertos revisados" descripcion="Se van resolviendo a medida que avanza el escaneo">
            <PortMap puertos={ETAPA_VACIA} progreso={progreso} />
          </Panel>
        </div>
      )}

      {e.estado === "fallida" && (
        <div className="stack">
          <ErrorNote accion={a && <EvaluarBoton activo={a} texto="Reintentar" pequeno />}>
            <strong>La evaluación no pudo completarse.</strong>
            <p className="small">{e.detalle_error || "Sin detalle del error."}</p>
          </ErrorNote>
          <Panel titulo="Qué puedes revisar">
            <ul className="lista-simple">
              <li>Que el activo esté encendido y responda desde la red donde corre SecureScan.</li>
              <li>Que la dirección <code>{a?.url_objetivo}</code> esté en un rango permitido (redes privadas, loopback o link-local).</li>
              <li>Que no haya un cortafuegos bloqueando el escaneo de puertos.</li>
            </ul>
          </Panel>
        </div>
      )}

      {completada && e.detalle_error && (
        <div className="panel-gap"><Aviso tipo="warn"><strong>La evaluación terminó con una advertencia.</strong> {e.detalle_error}</Aviso></div>
      )}

      {completada && (
        <div className="grid-main">
          <div className="stack">
            <Panel titulo="Mapa de puertos" descripcion={`${plural(puertosAbiertos, "puerto abierto", "puertos abiertos")}${hallazgosWeb ? ` y ${plural(hallazgosWeb, "hallazgo web", "hallazgos web")} (no asociados a un puerto)` : ""} · toca un puerto para ver el detalle`}>
              <div className="stack-sm">
                <PortMap hallazgos={hs} alSeleccionar={(h) => nav(`/hallazgos/${h.id}`)} />
                <LeyendaSev />
              </div>
            </Panel>
            <Panel
              titulo="Hallazgos"
              acciones={<Segmented etiqueta="Estado" valor={filtro} onChange={setFiltro} opciones={[{ valor: "todos", etiqueta: "Todos", n: hs.length }, { valor: "abiertos", etiqueta: "Abiertos", n: hs.length - corregidos }, { valor: "corregidos", etiqueta: "Corregidos", n: corregidos }]} />}
              flush
            >
              <TablaHallazgos hallazgos={filtrados} vacio={hs.length === 0 ? "Esta evaluación no encontró puertos abiertos." : "No hay hallazgos con ese estado."} />
            </Panel>
          </div>
          <div className="stack">
            <Panel titulo="Resumen">
              <ResumenSeveridad conteo={e.conteo} />
            </Panel>
            {principal && (
              <Panel titulo="Empieza por aquí">
                <div className="stack-sm">
                  <div className="row"><span className={`badge sevbg-${principal.severidad}`}>{principal.nombre_vulnerabilidad}</span></div>
                  <p className="small soft">{principal.recomendacion}</p>
                  <Link className="btn btn-sm" to={`/hallazgos/${principal.id}`}>Ver detalle</Link>
                </div>
              </Panel>
            )}
            <Panel titulo="Detalles">
              <dl className="kv">
                <dt>Activo</dt><dd><Link to={`/activos/${e.activo_id}`}>{a?.nombre}</Link></dd>
                <dt>Objetivo</dt><dd><code>{a?.url_objetivo}</code></dd>
                <dt>Inicio</dt><dd>{fmtFechaHora(e.iniciada_en)}</dd>
                <dt>Fin</dt><dd>{fmtFechaHora(e.finalizada_en)}</dd>
                <dt>Duración</dt><dd className="num">{fmtDuracion(e.iniciada_en, e.finalizada_en)}</dd>
                <dt>Corregidos</dt><dd className="num">{corregidos} de {hs.length}</dd>
              </dl>
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}

// Mientras corre el escaneo todavía no se conocen los resultados: se muestran los puertos de interés sin abrir.
import { PUERTOS_INTERES } from "../lib/risk.js";
const ETAPA_VACIA = PUERTOS_INTERES.map(([puerto, servicio]) => ({ puerto, servicio, severidad: null }));
