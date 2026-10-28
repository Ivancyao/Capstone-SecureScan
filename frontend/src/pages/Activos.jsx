import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { EmptyState, EstadoBadge, PageHeader, Panel, SevBadge, useTitulo } from "../components/ui.jsx";
import { LeyendaSev, SeverityBar, Sparkline } from "../components/charts.jsx";
import { PortMap } from "../components/PortMap.jsx";
import { ActivoModal, CopiarBoton, EvaluarBoton, NoEncontrado, ResumenSeveridad, TablaHallazgos } from "../components/shared.jsx";
import { useData } from "../context/DataContext.jsx";
import { fmtDuracion, fmtFecha, fmtFechaHora, hace } from "../lib/format.js";

export function Activos() {
  useTitulo("Activos");
  const { data } = useData();
  const nav = useNavigate();
  const [proyecto, setProyecto] = useState("");
  const [q, setQ] = useState("");
  const [modal, setModal] = useState(false);

  const lista = data.activos.filter((a) => (!proyecto || a.proyecto_id === proyecto) && (!q || `${a.nombre} ${a.url_objetivo}`.toLowerCase().includes(q.toLowerCase())));

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
            <input className="input" type="search" placeholder="Buscar por nombre o dirección" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Buscar activos" />
            <select className="select" value={proyecto} onChange={(e) => setProyecto(e.target.value)} aria-label="Filtrar por proyecto">
              <option value="">Todos los proyectos</option>
              {data.proyectos.map((p) => <option key={p.id} value={p.id}>{p.nombre}</option>)}
            </select>
            <span className="small muted">{lista.length} de {data.activos.length}</span>
          </div>
          <div className="panel">
            <div className="table-wrap">
              <table className="tabla tabla-clic">
                <thead>
                  <tr><th>Activo</th><th>Proyecto</th><th>Exposición actual</th><th>Evolución</th><th>Última evaluación</th><th /></tr>
                </thead>
                <tbody>
                  {lista.map((a) => (
                    <tr key={a.id} onClick={() => nav(`/activos/${a.id}`)}>
                      <td className="celda-titulo">
                        <Link to={`/activos/${a.id}`} onClick={(e) => e.stopPropagation()}>{a.nombre}</Link>
                        <span className="sub mono">{a.url_objetivo}</span>
                      </td>
                      <td>{a.proyecto?.nombre}</td>
                      <td>
                        {a.ultimaOk ? (
                          <div className="expo">
                            <SeverityBar conteo={a.conteo} alto={10} />
                            <SevBadge sev={a.maxSev} />
                          </div>
                        ) : (
                          <span className="muted small">Sin evaluar</span>
                        )}
                      </td>
                      <td><Sparkline valores={a.serie} /></td>
                      <td className="nowrap">
                        {a.ultima ? (
                          <>
                            <EstadoBadge estado={a.ultima.estado} />
                            <span className="sub">{hace(a.ultima.iniciada_en)}</span>
                          </>
                        ) : (
                          <span className="muted small">—</span>
                        )}
                      </td>
                      <td className="right" onClick={(e) => e.stopPropagation()}>
                        <EvaluarBoton activo={a} pequeno texto="Evaluar" />
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
        </>
      )}
      <ActivoModal abierto={modal} onClose={() => setModal(false)} />
    </>
  );
}

export function ActivoDetalle() {
  const { id } = useParams();
  const { data } = useData();
  const nav = useNavigate();
  const a = data.activoPorId[id];
  useTitulo(a?.nombre || "Activo");
  if (!a) return <NoEncontrado que="El activo" volver="/activos" etiqueta="Ver activos" />;

  return (
    <>
      <PageHeader
        migas={[{ texto: "Activos", to: "/activos" }, { texto: a.nombre }]}
        titulo={a.nombre}
        descripcion={a.descripcion}
        acciones={<EvaluarBoton activo={a} grande />}
      />

      <div className="row activo-url panel-gap">
        <Icon name="globe" size={16} />
        <code>{a.url_objetivo}</code>
        <CopiarBoton texto={a.url_objetivo} />
      </div>

      <div className="grid-main panel-gap">
        <div className="stack">
          <Panel
            titulo="Mapa de puertos"
            descripcion={a.ultimaOk ? `Resultado de la evaluación del ${fmtFechaHora(a.ultimaOk.iniciada_en)}` : "Aún no hay resultados"}
            acciones={a.ultimaOk && <Link className="btn btn-sm" to={`/evaluaciones/${a.ultimaOk.id}`}>Ver evaluación</Link>}
          >
            {a.ultimaOk ? (
              <div className="stack-sm">
                <PortMap hallazgos={a.ultimaOk.hallazgos} alSeleccionar={(h) => nav(`/hallazgos/${h.id}`)} />
                <LeyendaSev />
              </div>
            ) : (
              <EmptyState icono="radar" titulo="Este activo no se ha evaluado" texto="Inicia una evaluación para ver qué puertos y servicios tiene expuestos." accion={<EvaluarBoton activo={a} />} />
            )}
          </Panel>

          {a.ultimaOk && (
            <Panel titulo="Hallazgos abiertos" descripcion={`${a.abiertos.length} de ${a.ultimaOk.hallazgos.length} sin corregir`} flush>
              <TablaHallazgos hallazgos={a.abiertos.map((h) => ({ ...h, activo: a, proyecto: a.proyecto }))} vacio="Todo corregido. Vuelve a evaluar para confirmarlo." />
            </Panel>
          )}
        </div>

        <div className="stack">
          <Panel titulo="Exposición actual">
            <ResumenSeveridad conteo={a.conteo} />
          </Panel>
          <Panel titulo="Historial de evaluaciones" flush>
            {a.evaluaciones.length === 0 ? (
              <p className="small muted tabla-vacia">Sin evaluaciones.</p>
            ) : (
              <ul className="rows">
                {a.evaluaciones.map((e) => (
                  <li key={e.id} className="clic" onClick={() => nav(`/evaluaciones/${e.id}`)}>
                    <div className="grow">
                      <Link to={`/evaluaciones/${e.id}`} className="titulo" onClick={(ev) => ev.stopPropagation()}>{fmtFecha(e.iniciada_en)}</Link>
                      <span className="sub">{e.estado === "completada" ? `${e.conteo.total} hallazgos · ${fmtDuracion(e.iniciada_en, e.finalizada_en)}` : e.estado === "fallida" ? "No terminó" : "En curso"}</span>
                    </div>
                    <EstadoBadge estado={e.estado} />
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel titulo="Detalles">
            <dl className="kv">
              <dt>Proyecto</dt><dd><Link to={`/proyectos/${a.proyecto_id}`}>{a.proyecto?.nombre}</Link></dd>
              <dt>Registrado</dt><dd>{fmtFecha(a.creado_en)}</dd>
              <dt>Evaluaciones</dt><dd className="num">{a.evaluaciones.length}</dd>
            </dl>
          </Panel>
        </div>
      </div>
    </>
  );
}
