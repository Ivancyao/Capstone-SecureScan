import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { EmptyState, EstadoBadge, PageHeader, Panel, Segmented, SevBadge, useTitulo } from "../components/ui.jsx";
import { LeyendaSev, SeverityBar, Sparkline } from "../components/charts.jsx";
import { PortMap } from "../components/PortMap.jsx";
import { ActivoModal, CopiarBoton, EvaluarBoton, NoEncontrado, ResumenSeveridad, TablaHallazgos, TarjetaActivo } from "../components/shared.jsx";
import { useData } from "../context/DataContext.jsx";
import { fmtDuracion, fmtFecha, fmtFechaHora, hace } from "../lib/format.js";

export function Activos() {
  useTitulo("Activos");
  const { data } = useData();
  const navegar = useNavigate();
  const [proyecto, setProyecto] = useState("");
  const [busqueda, setBusqueda] = useState("");
  const [modal, setModal] = useState(false);
  const [vista, setVista] = useState(() => {
    try { return localStorage.getItem("securescan-vista-activos") || "tarjetas"; } catch { return "tarjetas"; }
  });
  const cambiarVista = (nuevaVista) => {
    setVista(nuevaVista);
    try { localStorage.setItem("securescan-vista-activos", nuevaVista); } catch { /* ignorar */ }
  };

  const lista = data.activos.filter((activo) => (!proyecto || activo.proyecto_id === proyecto) && (!busqueda || `${activo.nombre} ${activo.url_objetivo}`.toLowerCase().includes(busqueda.toLowerCase())));

  return (
    <>
      <PageHeader
        titulo="Activos"
        descripcion="Las aplicaciones y servidores registrados para evaluar. Solo deben ser tuyos o contar con autorización."
        acciones={<button className="btn btn-primary" onClick={() => setModal(true)} disabled={data.proyectos.length === 0}><Icon name="plus" size={16} /> Registrar activo</button>}
      />
      {data.activos.length === 0 ? (
        <div className="panel">
          <EmptyState icono="server" titulo="Todavía no hay activos" texto={data.proyectos.length ? "Registra la primera aplicación o servidor que quieras evaluar." : "Primero crea un proyecto; los activos viven dentro de uno."} accion={data.proyectos.length ? <button className="btn btn-primary" onClick={() => setModal(true)}>Registrar activo</button> : <Link to="/proyectos?nuevo=1" className="btn btn-primary">Crear proyecto</Link>} />
        </div>
      ) : (
        <>
          <div className="filtros">
            <input className="input" type="search" placeholder="Buscar por nombre o dirección" value={busqueda} onChange={(evento) => setBusqueda(evento.target.value)} aria-label="Buscar activos" />
            <select className="select" value={proyecto} onChange={(evento) => setProyecto(evento.target.value)} aria-label="Filtrar por proyecto">
              <option value="">Todos los proyectos</option>
              {data.proyectos.map((proyectoDisponible) => <option key={proyectoDisponible.id} value={proyectoDisponible.id}>{proyectoDisponible.nombre}</option>)}
            </select>
            <span className="small muted">{lista.length} de {data.activos.length}</span>
            <span className="spacer" />
            <Segmented etiqueta="Vista" valor={vista} onChange={cambiarVista} opciones={[{ valor: "tarjetas", etiqueta: "Tarjetas" }, { valor: "tabla", etiqueta: "Tabla" }]} />
          </div>
          {vista === "tarjetas" ? (
            lista.length === 0 ? <p className="small muted">Ningún activo coincide con la búsqueda.</p> : (
              <div className="cards">{lista.map((activo) => <TarjetaActivo key={activo.id} activo={activo} />)}</div>
            )
          ) : (
          <div className="panel">
            <div className="table-wrap">
              <table className="tabla tabla-clic">
                <thead>
                  <tr><th>Activo</th><th>Proyecto</th><th>Exposición actual</th><th>Evolución</th><th>Última evaluación</th><th /></tr>
                </thead>
                <tbody>
                  {lista.map((activo) => (
                    <tr key={activo.id} onClick={() => navegar(`/activos/${activo.id}`)}>
                      <td className="celda-titulo">
                        <Link to={`/activos/${activo.id}`} onClick={(evento) => evento.stopPropagation()}>{activo.nombre}</Link>
                        <span className="sub mono">{activo.url_objetivo}</span>
                      </td>
                      <td>{activo.proyecto?.nombre}</td>
                      <td>
                        {activo.ultimaOk ? (
                          <div className="expo">
                            <SeverityBar conteo={activo.conteo} alto={10} />
                            <SevBadge sev={activo.maxSev} />
                          </div>
                        ) : (
                          <span className="muted small">Sin evaluar</span>
                        )}
                      </td>
                      <td><Sparkline valores={activo.serie} /></td>
                      <td className="nowrap">
                        {activo.ultima ? (
                          <>
                            <EstadoBadge estado={activo.ultima.estado} />
                            <span className="sub">{hace(activo.ultima.iniciada_en)}</span>
                          </>
                        ) : (
                          <span className="muted small">—</span>
                        )}
                      </td>
                      <td className="right" onClick={(evento) => evento.stopPropagation()}>
                        <EvaluarBoton activo={activo} pequeno texto="Evaluar" />
                      </td>
                    </tr>
                  ))}
                  {lista.length === 0 && (
                    <tr><td colSpan={6} className="muted small">Ningún activo coincide con la búsqueda.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
          )}
        </>
      )}
      <ActivoModal abierto={modal} onClose={() => setModal(false)} />
    </>
  );
}

export function ActivoDetalle() {
  const { id } = useParams();
  const { data } = useData();
  const navegar = useNavigate();
  const activo = data.activoPorId[id];
  useTitulo(activo?.nombre || "Activo");
  if (!activo) return <NoEncontrado que="El activo" volver="/activos" etiqueta="Ver activos" />;

  return (
    <>
      <PageHeader
        migas={[{ texto: "Activos", to: "/activos" }, { texto: activo.nombre }]}
        titulo={activo.nombre}
        descripcion={activo.descripcion}
        acciones={<EvaluarBoton activo={activo} grande />}
      />

      <div className="row activo-url panel-gap">
        <Icon name="globe" size={16} />
        <code>{activo.url_objetivo}</code>
        <CopiarBoton texto={activo.url_objetivo} />
      </div>

      <div className="grid-main panel-gap">
        <div className="stack">
          <Panel
            titulo="Mapa de puertos"
            descripcion={activo.ultimaOk ? `Resultado de la evaluación del ${fmtFechaHora(activo.ultimaOk.iniciada_en)}` : "Aún no hay resultados"}
            acciones={activo.ultimaOk && <Link className="btn btn-sm" to={`/evaluaciones/${activo.ultimaOk.id}`}>Ver evaluación</Link>}
          >
            {activo.ultimaOk ? (
              <div className="stack-sm">
                <PortMap hallazgos={activo.ultimaOk.hallazgos} alSeleccionar={(hallazgo) => navegar(`/hallazgos/${hallazgo.id}`)} />
                <LeyendaSev />
              </div>
            ) : (
              <EmptyState icono="radar" titulo="Este activo no se ha evaluado" texto="Inicia una evaluación para ver qué puertos y servicios tiene expuestos." accion={<EvaluarBoton activo={activo} />} />
            )}
          </Panel>

          {activo.ultimaOk && (
            <Panel titulo="Hallazgos abiertos" descripcion={`${activo.abiertos.length} de ${activo.ultimaOk.hallazgos.length} sin corregir`} flush>
              <TablaHallazgos hallazgos={activo.abiertos.map((hallazgo) => ({ ...hallazgo, activo, proyecto: activo.proyecto }))} vacio="Todo corregido. Vuelve a evaluar para confirmarlo." />
            </Panel>
          )}
        </div>

        <div className="stack">
          <Panel titulo="Exposición actual">
            <ResumenSeveridad conteo={activo.conteo} />
          </Panel>
          <Panel titulo="Historial de evaluaciones" flush>
            {activo.evaluaciones.length === 0 ? (
              <p className="small muted tabla-vacia">Sin evaluaciones.</p>
            ) : (
              <ul className="rows">
                {activo.evaluaciones.map((evaluacion) => (
                  <li key={evaluacion.id} className="clic" onClick={() => navegar(`/evaluaciones/${evaluacion.id}`)}>
                    <div className="grow">
                      <Link to={`/evaluaciones/${evaluacion.id}`} className="titulo" onClick={(evento) => evento.stopPropagation()}>{fmtFecha(evaluacion.iniciada_en)}</Link>
                      <span className="sub">{evaluacion.estado === "completada" ? `${evaluacion.conteo.total} hallazgos · ${fmtDuracion(evaluacion.iniciada_en, evaluacion.finalizada_en)}` : evaluacion.estado === "fallida" ? "No terminó" : "En curso"}</span>
                    </div>
                    <EstadoBadge estado={evaluacion.estado} />
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel titulo="Detalles">
            <dl className="kv">
              <dt>Proyecto</dt><dd><Link to={`/proyectos/${activo.proyecto_id}`}>{activo.proyecto?.nombre}</Link></dd>
              <dt>Registrado</dt><dd>{fmtFecha(activo.creado_en)}</dd>
              <dt>Evaluaciones</dt><dd className="num">{activo.evaluaciones.length}</dd>
            </dl>
          </Panel>
        </div>
      </div>
    </>
  );
}
