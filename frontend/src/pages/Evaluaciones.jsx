import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Aviso, Campo, EmptyState, ErrorNote, EstadoBadge, PageHeader, Panel, Progress, Segmented, Tag, useTitulo } from "../components/ui.jsx";
import { LeyendaSev, SeverityBar } from "../components/charts.jsx";
import { PortMap, construirPuertos } from "../components/PortMap.jsx";
import { EvaluarBoton, NoEncontrado, ResumenSeveridad, TablaHallazgos } from "../components/shared.jsx";
import { useData } from "../context/DataContext.jsx";
import { fmtDuracion, fmtFechaHora, esHostPrivado, hace, hostDe, plural } from "../lib/format.js";
import { ordenSev } from "../lib/risk.js";
import { evaluacionAnterior } from "../lib/comparar.js";

// Cantidad de evaluaciones por página en la tabla.
const POR_PAGINA = 15;

// Lista de evaluaciones con filtros por estado (todas, en curso, completadas, fallidas, canceladas) y paginación.
export function Evaluaciones() {
  useTitulo("Evaluaciones");
  const { data, cancelarEvaluacion, eliminarEvaluacion } = useData();
  const navegar = useNavigate();
  const [filtro, setFiltro] = useState("todas");
  const [pagina, setPagina] = useState(1);
  const todas = data.evaluaciones;
  // Cuántas hay en cada estado, para los contadores de las pestañas.
  const cuenta = {
    todas: todas.length,
    curso: todas.filter((evaluacion) => evaluacion.enCurso).length,
    completada: todas.filter((evaluacion) => evaluacion.estado === "completada").length,
    fallida: todas.filter((evaluacion) => evaluacion.estado === "fallida").length,
    cancelada: todas.filter((evaluacion) => evaluacion.estado === "cancelada").length,
  };
  const filtradas = todas.filter((evaluacion) => filtro === "todas" || (filtro === "curso" ? evaluacion.enCurso : evaluacion.estado === filtro));
  const paginas = Math.max(1, Math.ceil(filtradas.length / POR_PAGINA));
  const actual = Math.min(pagina, paginas); // si el filtro deja menos páginas, se vuelve a la última
  const lista = filtradas.slice((actual - 1) * POR_PAGINA, actual * POR_PAGINA);
  // Antes de cancelar o eliminar pido confirmación, porque son acciones que no se pueden deshacer.
  const pedirCancelar = async (evaluacion) => {
    if (window.confirm(`¿Cancelar la evaluación de “${evaluacion.activo?.nombre}”? Se detiene el escaneo y se descartan los resultados parciales.`)) {
      try { await cancelarEvaluacion(evaluacion.id); } catch { /* aviso mostrado */ }
    }
  };
  const pedirEliminar = async (evaluacion) => {
    if (window.confirm(`¿Eliminar la evaluación de “${evaluacion.activo?.nombre}” del ${fmtFechaHora(evaluacion.iniciada_en)}? Se borran también sus hallazgos y no se puede deshacer.`)) {
      try { await eliminarEvaluacion(evaluacion.id); } catch { /* aviso mostrado */ }
    }
  };

  return (
    <>
      <PageHeader
        titulo="Evaluaciones"
        descripcion="Cada evaluación es una ejecución del escáner sobre un activo. Corren en segundo plano, así que puedes seguir usando la plataforma."
        acciones={<Link to="/evaluaciones/nueva" className="btn btn-primary"><Icon name="play" size={15} /> Nueva evaluación</Link>}
      />
      {todas.length === 0 ? (
        <div className="panel">
          <EmptyState icono="radar" titulo="Aún no hay evaluaciones" texto="Elige un activo y lánzale la primera evaluación para ver sus puertos y hallazgos." accion={<Link to="/evaluaciones/nueva" className="btn btn-primary">Iniciar evaluación</Link>} />
        </div>
      ) : (
        <>
          <div className="filtros">
            <Segmented
              etiqueta="Filtrar por estado"
              valor={filtro}
              onChange={(nuevoFiltro) => { setFiltro(nuevoFiltro); setPagina(1); }}
              opciones={[
                { valor: "todas", etiqueta: "Todas", n: cuenta.todas },
                { valor: "curso", etiqueta: "En curso", n: cuenta.curso },
                { valor: "completada", etiqueta: "Completadas", n: cuenta.completada },
                { valor: "fallida", etiqueta: "Fallidas", n: cuenta.fallida },
                ...(cuenta.cancelada ? [{ valor: "cancelada", etiqueta: "Canceladas", n: cuenta.cancelada }] : []),
              ]}
            />
          </div>
          <div className="panel">
            <div className="table-wrap">
              <table className="tabla tabla-clic">
                <thead><tr><th>Activo</th><th>Estado</th><th>Hallazgos</th><th>Inicio</th><th className="right">Duración</th><th><span className="sr-only">Acciones</span></th></tr></thead>
                <tbody>
                  {lista.map((evaluacion) => (
                    <tr key={evaluacion.id} onClick={() => navegar(`/evaluaciones/${evaluacion.id}`)}>
                      <td className="celda-titulo">
                        <Link to={`/evaluaciones/${evaluacion.id}`} onClick={(evento) => evento.stopPropagation()}>{evaluacion.activo?.nombre}</Link>
                        <span className="sub">{evaluacion.proyecto?.nombre}</span>
                      </td>
                      <td>
                        <EstadoBadge estado={evaluacion.estado} />
                        {evaluacion.enCurso && <div className="mini-prog"><Progress valor={evaluacion.progreso || 0} indeterminado={evaluacion.progreso == null} /></div>}
                      </td>
                      <td>
                        {evaluacion.estado === "completada" ? (
                          <div className="expo"><SeverityBar conteo={evaluacion.conteo} alto={10} /><span className="num small">{evaluacion.conteo.total}</span></div>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className="nowrap">{fmtFechaHora(evaluacion.iniciada_en)}<span className="sub">{hace(evaluacion.iniciada_en)}</span></td>
                      <td className="right num">{fmtDuracion(evaluacion.iniciada_en, evaluacion.finalizada_en)}</td>
                      <td className="right" onClick={(evento) => evento.stopPropagation()}>
                        {evaluacion.enCurso ? (
                          <button className="btn btn-sm" onClick={() => pedirCancelar(evaluacion)}><Icon name="x" size={14} /> Cancelar</button>
                        ) : (
                          <button className="btn btn-sm btn-icon" aria-label={`Eliminar la evaluación de ${evaluacion.activo?.nombre}`} title="Eliminar" onClick={() => pedirEliminar(evaluacion)}><Icon name="trash" size={14} /></button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {lista.length === 0 && <tr><td colSpan={6} className="muted small">No hay evaluaciones con ese estado.</td></tr>}
                </tbody>
              </table>
            </div>
            {paginas > 1 && (
              <nav className="paginacion" aria-label="Paginación de evaluaciones">
                <span className="small muted">
                  Mostrando {(actual - 1) * POR_PAGINA + 1}–{Math.min(actual * POR_PAGINA, filtradas.length)} de {filtradas.length}
                </span>
                <span className="row">
                  <button className="btn btn-sm" onClick={() => setPagina(actual - 1)} disabled={actual === 1}><Icon name="arrow-left" size={14} /> Anterior</button>
                  <span className="small num" aria-current="page">Página {actual} de {paginas}</span>
                  <button className="btn btn-sm" onClick={() => setPagina(actual + 1)} disabled={actual === paginas}>Siguiente <Icon name="arrow-right" size={14} /></button>
                </span>
              </nav>
            )}
          </div>
        </>
      )}
    </>
  );
}

// ---------- Nueva evaluación ----------
// Formulario para elegir un activo y lanzar la evaluación. Avisa si el objetivo parece fuera del laboratorio.
export function NuevaEvaluacion() {
  useTitulo("Nueva evaluación");
  const { data, iniciarEvaluacion } = useData();
  const navegar = useNavigate();
  const [params] = useSearchParams();
  const previo = data.activoPorId[params.get("activo")];
  const [proyectoId, setProyectoId] = useState(previo?.proyecto_id || "");
  const [activoId, setActivoId] = useState(previo?.id || "");
  const [autorizo, setAutorizo] = useState(false);
  const [cargando, setCargando] = useState(false);
  const [error, setError] = useState("");

  const activos = useMemo(() => data.activos.filter((activoDisponible) => !proyectoId || activoDisponible.proyecto_id === proyectoId), [data.activos, proyectoId]);
  const activo = data.activoPorId[activoId];
  const host = activo ? hostDe(activo.url_objetivo) : "";
  const permitido = activo ? esHostPrivado(host) || data.config?.alcance?.permitir_publicas : null;

  const enviar = async (evento) => {
    evento.preventDefault();
    setError("");
    setCargando(true);
    try {
      const evaluacion = await iniciarEvaluacion(activoId);
      navegar(`/evaluaciones/${evaluacion.id}`);
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
                  <select id={id} className="select" value={proyectoId} onChange={(evento) => { setProyectoId(evento.target.value); setActivoId(""); }}>
                    <option value="">Todos los proyectos</option>
                    {data.proyectos.map((proyecto) => <option key={proyecto.id} value={proyecto.id}>{proyecto.nombre}</option>)}
                  </select>
                )}
              </Campo>
              <Campo etiqueta="Activo a evaluar">
                {(id) => (
                  <select id={id} className="select" value={activoId} onChange={(evento) => setActivoId(evento.target.value)} required>
                    <option value="">Elige un activo</option>
                    {activos.map((activoDisponible) => <option key={activoDisponible.id} value={activoDisponible.id}>{activoDisponible.nombre}</option>)}
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
                    <strong>{host} parece una dirección pública.</strong> Por política, SecureScan solo evalúa redes privadas o loopback; la evaluación será rechazada.
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
              <input type="checkbox" checked={autorizo} onChange={(evento) => setAutorizo(evento.target.checked)} required />
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
            ].map(([titulo, descripcion], indice) => (
              <li key={titulo} className="paso">
                <span className="paso-dot">{indice + 1}</span>
                <div><strong>{titulo}</strong><p className="small muted">{descripcion}</p></div>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
    </>
  );
}

// ---------- Detalle ----------
// Las 4 etapas del escaneo y el rango de progreso (%) de cada una. Coinciden con las etapas que guarda el backend en scan_service.
const ETAPAS = [
  ["Validar el objetivo", 0, 12],
  ["Escanear puertos y servicios", 12, 80],
  ["Clasificar el riesgo", 80, 95],
  ["Guardar los resultados", 95, 101],
];

// Pantalla de una evaluación. Mientras está en curso muestra el progreso en vivo (la página se refresca sola cada 2 s); al terminar, el mapa de puertos y los hallazgos.
export function EvaluacionDetalle() {
  const { id } = useParams();
  const { data, cancelarEvaluacion, eliminarEvaluacion } = useData();
  const navegar = useNavigate();
  const [filtro, setFiltro] = useState("todos");
  const evaluacion = data.evaluacionPorId[id];
  useTitulo(evaluacion ? `Evaluación de ${evaluacion.activo?.nombre}` : "Evaluación");
  if (!evaluacion) return <NoEncontrado que="La evaluación" volver="/evaluaciones" etiqueta="Ver evaluaciones" />;

  const activo = data.activoPorId[evaluacion.activo_id];
  const completada = evaluacion.estado === "completada";
  // Si está pendiente el progreso es 0; si ya corre, uso el porcentaje que guarda el backend.
  const progreso = evaluacion.estado === "pendiente" ? 0 : evaluacion.progreso ?? 0;
  const hallazgos = evaluacion.hallazgos.map((hallazgo) => ({ ...hallazgo, activo, proyecto: evaluacion.proyecto, fecha: evaluacion.iniciada_en }));
  const puertosAbiertos = construirPuertos(hallazgos).filter((puerto) => puerto.severidad).length;
  // Hallazgos web = los que no son de puertos (los que vienen de ZAP). Se calculan restando los de puerto abierto.
  const hallazgosWeb = hallazgos.length - hallazgos.filter((hallazgo) => /Puerto \d+\/(tcp|udp) abierto/.test(hallazgo.evidencia || "")).length;
  const filtrados = hallazgos.filter((hallazgo) => filtro === "todos" || (filtro === "abiertos" ? hallazgo.corregido !== "si" : hallazgo.corregido === "si"));
  const corregidos = hallazgos.filter((hallazgo) => hallazgo.corregido === "si").length;
  // El hallazgo más grave que sigue abierto (por severidad y luego CVSS). Es el que destaco como primero a corregir.
  const principal = [...hallazgos].filter((hallazgo) => hallazgo.corregido !== "si").sort((primero, segundo) => ordenSev(primero.severidad) - ordenSev(segundo.severidad) || (segundo.cvss_score ?? 0) - (primero.cvss_score ?? 0))[0];

  return (
    <>
      <PageHeader
        migas={[{ texto: "Evaluaciones", to: "/evaluaciones" }, { texto: activo?.nombre || "Evaluación" }]}
        titulo={`Evaluación de ${activo?.nombre}`}
        descripcion={`Iniciada el ${fmtFechaHora(evaluacion.iniciada_en)} · ${evaluacion.proyecto?.nombre}`}
        acciones={
          <>
            {completada && evaluacionAnterior(data.evaluaciones, evaluacion) && <Link to={`/evaluaciones/${evaluacion.id}/comparar`} className="btn"><Icon name="layers" size={16} /> Comparar con la anterior</Link>}
            {completada && <Link to={`/reportes?proyecto=${evaluacion.proyecto?.id}`} className="btn"><Icon name="file" size={16} /> Generar reporte</Link>}
            {activo && !evaluacion.enCurso && <EvaluarBoton activo={activo} texto="Volver a evaluar" />}
            {evaluacion.enCurso ? (
              <button className="btn btn-danger" onClick={async () => {
                if (window.confirm("¿Cancelar esta evaluación? Se detiene el escaneo y se descartan los resultados parciales.")) {
                  try { await cancelarEvaluacion(evaluacion.id); } catch { /* aviso mostrado */ }
                }
              }}><Icon name="x" size={16} /> Cancelar evaluación</button>
            ) : (
              <button className="btn" onClick={async () => {
                if (window.confirm("¿Eliminar esta evaluación? Se borran también sus hallazgos y no se puede deshacer.")) {
                  try { await eliminarEvaluacion(evaluacion.id); navegar("/evaluaciones"); } catch { /* aviso mostrado */ }
                }
              }}><Icon name="trash" size={16} /> Eliminar</button>
            )}
          </>
        }
      />

      {evaluacion.enCurso && (
        <div className="grid-main-r">
          <Panel titulo="Escaneo en curso" descripcion="Esta página se actualiza sola">
            <div className="stack-sm">
              <div className="row-between">
                <strong>{evaluacion.etapa || "En cola"}</strong>
                <span className="num muted small">{evaluacion.progreso != null ? `${progreso}%` : ""}</span>
              </div>
              <Progress valor={progreso} indeterminado={evaluacion.estado === "pendiente"} etiqueta="Progreso de la evaluación" />
              <ol className="pasos pasos-sep">
                {ETAPAS.map(([titulo, desde, hasta], indice) => {
                  const hecho = evaluacion.estado === "en_progreso" && progreso >= hasta;
                  const actual = evaluacion.estado === "en_progreso" && progreso >= desde && progreso < hasta;
                  return (
                    <li key={titulo} className={`paso ${hecho ? "hecho" : actual ? "actual" : "espera"}`}>
                      <span className="paso-dot">{hecho ? <Icon name="check" size={13} /> : indice + 1}</span>
                      <div><strong>{titulo}</strong></div>
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

      {evaluacion.estado === "cancelada" && (
        <Aviso tipo="info">
          <strong>Cancelaste esta evaluación.</strong> No se guardaron resultados. Puedes volver a evaluar el activo o eliminar este registro.
        </Aviso>
      )}

      {evaluacion.estado === "fallida" && (
        <div className="stack">
          <ErrorNote accion={activo && <EvaluarBoton activo={activo} texto="Reintentar" pequeno />}>
            <strong>La evaluación no pudo completarse.</strong>
            <p className="small">{evaluacion.detalle_error || "Sin detalle del error."}</p>
          </ErrorNote>
          <Panel titulo="Qué puedes revisar">
            <ul className="lista-simple">
              <li>Que el activo esté encendido y responda desde la red donde corre SecureScan.</li>
              <li>Que la dirección <code>{activo?.url_objetivo}</code> esté en un rango permitido (redes privadas o loopback).</li>
              <li>Que no haya un cortafuegos bloqueando el escaneo de puertos.</li>
            </ul>
          </Panel>
        </div>
      )}

      {completada && evaluacion.detalle_error && (
        <div className="panel-gap"><Aviso tipo="warn"><strong>La evaluación terminó con una advertencia.</strong> {evaluacion.detalle_error}</Aviso></div>
      )}

      {completada && (
        <div className="grid-main">
          <div className="stack">
            <Panel className="panel-hero" titulo="Mapa de puertos" descripcion={`${plural(puertosAbiertos, "puerto abierto", "puertos abiertos")}${hallazgosWeb ? ` y ${plural(hallazgosWeb, "hallazgo web", "hallazgos web")} (no asociados a un puerto)` : ""} · toca un puerto para ver el detalle`}>
              <div className="stack-sm">
                <PortMap hallazgos={hallazgos} alSeleccionar={(hallazgo) => navegar(`/hallazgos/${hallazgo.id}`)} />
                <LeyendaSev />
              </div>
            </Panel>
            <Panel
              titulo="Hallazgos"
              acciones={<Segmented etiqueta="Estado" valor={filtro} onChange={setFiltro} opciones={[{ valor: "todos", etiqueta: "Todos", n: hallazgos.length }, { valor: "abiertos", etiqueta: "Abiertos", n: hallazgos.length - corregidos }, { valor: "corregidos", etiqueta: "Corregidos", n: corregidos }]} />}
              flush
            >
              <TablaHallazgos hallazgos={filtrados} vacio={hallazgos.length === 0 ? "Esta evaluación no encontró puertos abiertos." : "No hay hallazgos con ese estado."} />
            </Panel>
          </div>
          <div className="stack">
            <Panel titulo="Resumen">
              <ResumenSeveridad conteo={evaluacion.conteo} />
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
                <dt>Activo</dt><dd><Link to={`/activos/${evaluacion.activo_id}`}>{activo?.nombre}</Link></dd>
                <dt>Objetivo</dt><dd><code>{activo?.url_objetivo}</code></dd>
                <dt>Inicio</dt><dd>{fmtFechaHora(evaluacion.iniciada_en)}</dd>
                <dt>Fin</dt><dd>{fmtFechaHora(evaluacion.finalizada_en)}</dd>
                <dt>Duración</dt><dd className="num">{fmtDuracion(evaluacion.iniciada_en, evaluacion.finalizada_en)}</dd>
                <dt>Corregidos</dt><dd className="num">{corregidos} de {hallazgos.length}</dd>
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
// Mapa de puertos "en blanco" para mostrar mientras el escaneo aún no entrega resultados.
const ETAPA_VACIA = PUERTOS_INTERES.map(([puerto, servicio]) => ({ puerto, servicio, severidad: null }));
