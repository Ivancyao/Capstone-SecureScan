import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { EmptyState, EstadoBadge, PageHeader, Panel, Tabs, Tag, useTitulo } from "../components/ui.jsx";
import { SeverityBar, Sparkline } from "../components/charts.jsx";
import { ActivoModal, EvaluarBoton, NoEncontrado, ProyectoModal, ResumenSeveridad } from "../components/shared.jsx";
import { SevBadge } from "../components/ui.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useData } from "../context/DataContext.jsx";
import { fmtFecha, fmtDuracion, hace, plural } from "../lib/format.js";

export function Proyectos() {
  useTitulo("Proyectos");
  const { data } = useData();
  const { user } = useAuth();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const [modal, setModal] = useState(params.get("nuevo") === "1");
  const duenos = Object.fromEntries((data.usuarios || []).map((u) => [u.id, u.nombre]));

  useEffect(() => {
    if (params.get("nuevo") === "1") {
      setModal(true);
      setParams({}, { replace: true });
    }
  }, [params, setParams]);

  return (
    <>
      <PageHeader
        titulo="Proyectos"
        descripcion="Cada proyecto agrupa los activos de una organización o de un contexto de trabajo, y sus reportes."
        acciones={<button className="btn btn-primary" onClick={() => setModal(true)}><Icon name="plus" size={16} /> Nuevo proyecto</button>}
      />
      {data.proyectos.length === 0 ? (
        <div className="panel">
          <EmptyState icono="folder" titulo="Aún no tienes proyectos" texto="Crea uno para empezar a registrar activos y evaluarlos." accion={<button className="btn btn-primary" onClick={() => setModal(true)}>Crear proyecto</button>} />
        </div>
      ) : (
        <div className="panel">
          <ul className="rows rows-grandes">
            {data.proyectos.map((p) => (
              <li key={p.id} className="clic" onClick={() => nav(`/proyectos/${p.id}`)}>
                <span className="icono-caja"><Icon name="folder" size={20} /></span>
                <div className="grow">
                  <Link to={`/proyectos/${p.id}`} className="titulo" onClick={(e) => e.stopPropagation()}>{p.nombre}</Link>
                  <span className="sub">{p.descripcion || "Sin descripción"}</span>
                  <span className="sub">
                    {plural(p.activos.length, "activo", "activos")}
                    {p.ultima ? ` · última evaluación ${hace(p.ultima.iniciada_en)}` : " · sin evaluaciones"}
                    {user.rol === "admin" && duenos[p.propietario_id] ? ` · de ${duenos[p.propietario_id]}` : ""}
                  </span>
                </div>
                <div className="row-bar row-bar-ancha">
                  {p.conteo.total > 0 ? <SeverityBar conteo={p.conteo} alto={10} /> : <span className="xs muted">{p.activos.some((a) => a.ultimaOk) ? "Sin hallazgos abiertos" : "Sin datos"}</span>}
                </div>
                <div className="col-sev"><SevBadge sev={p.maxSev} /></div>
                <Icon name="chevron-right" size={18} />
              </li>
            ))}
          </ul>
        </div>
      )}
      <ProyectoModal abierto={modal} onClose={() => setModal(false)} />
    </>
  );
}

export function ProyectoDetalle() {
  const { id } = useParams();
  const { data } = useData();
  const nav = useNavigate();
  const [tab, setTab] = useState("activos");
  const [modal, setModal] = useState(false);
  const p = data.proyectosPorId[id];
  useTitulo(p?.nombre || "Proyecto");
  if (!p) return <NoEncontrado que="El proyecto" volver="/proyectos" etiqueta="Ver proyectos" />;

  return (
    <>
      <PageHeader
        migas={[{ texto: "Proyectos", to: "/proyectos" }, { texto: p.nombre }]}
        titulo={p.nombre}
        descripcion={p.descripcion}
        acciones={
          <>
            <button className="btn" onClick={() => setModal(true)}><Icon name="plus" size={16} /> Registrar activo</button>
            <Link to={`/reportes?proyecto=${p.id}`} className="btn"><Icon name="file" size={16} /> Generar reporte</Link>
          </>
        }
      />

      <div className="grid-main-r panel-gap">
        <Panel titulo="Hallazgos abiertos" descripcion="De la última evaluación de cada activo">
          <ResumenSeveridad conteo={p.conteo} />
        </Panel>
        <Panel titulo="Resumen">
          <dl className="kv">
            <dt>Activos</dt><dd className="num">{p.activos.length}</dd>
            <dt>Evaluaciones</dt><dd className="num">{p.evaluaciones.length}</dd>
            <dt>Última evaluación</dt><dd>{p.ultima ? `${fmtFecha(p.ultima.iniciada_en)} (${hace(p.ultima.iniciada_en)})` : "Sin evaluaciones"}</dd>
            <dt>Reportes</dt><dd className="num">{p.reportes.length}</dd>
            <dt>Creado</dt><dd>{fmtFecha(p.creado_en)}</dd>
          </dl>
        </Panel>
      </div>

      <Tabs
        valor={tab}
        onChange={setTab}
        tabs={[
          { valor: "activos", etiqueta: "Activos", n: p.activos.length },
          { valor: "evaluaciones", etiqueta: "Evaluaciones", n: p.evaluaciones.length },
          { valor: "reportes", etiqueta: "Reportes", n: p.reportes.length },
        ]}
      />
      <div className="panel panel-tab">
        {tab === "activos" &&
          (p.activos.length === 0 ? (
            <EmptyState icono="server" titulo="Este proyecto no tiene activos" texto="Registra la primera aplicación o servidor que quieras evaluar." accion={<button className="btn btn-primary" onClick={() => setModal(true)}>Registrar activo</button>} />
          ) : (
            <ul className="rows">
              {p.activos.map((a) => (
                <li key={a.id} className="clic" onClick={() => nav(`/activos/${a.id}`)}>
                  <div className="grow">
                    <Link to={`/activos/${a.id}`} className="titulo" onClick={(e) => e.stopPropagation()}>{a.nombre}</Link>
                    <span className="sub mono">{a.url_objetivo}</span>
                  </div>
                  <div className="row-bar"><SeverityBar conteo={a.conteo} alto={10} /></div>
                  <Sparkline valores={a.serie} />
                  <div className="col-sev"><SevBadge sev={a.maxSev} /></div>
                  <span onClick={(e) => e.stopPropagation()}><EvaluarBoton activo={a} pequeno texto="Evaluar" /></span>
                </li>
              ))}
            </ul>
          ))}
        {tab === "evaluaciones" &&
          (p.evaluaciones.length === 0 ? (
            <EmptyState icono="radar" titulo="Sin evaluaciones todavía" texto="Inicia una desde cualquier activo del proyecto." />
          ) : (
            <div className="table-wrap">
              <table className="tabla tabla-clic">
                <thead><tr><th>Activo</th><th>Estado</th><th>Hallazgos</th><th>Inicio</th><th>Duración</th></tr></thead>
                <tbody>
                  {p.evaluaciones.map((e) => (
                    <tr key={e.id} onClick={() => nav(`/evaluaciones/${e.id}`)}>
                      <td className="celda-titulo"><Link to={`/evaluaciones/${e.id}`} onClick={(ev) => ev.stopPropagation()}>{e.activo?.nombre}</Link></td>
                      <td><EstadoBadge estado={e.estado} /></td>
                      <td className="num">{e.estado === "completada" ? e.conteo.total : "—"}</td>
                      <td>{fmtFecha(e.iniciada_en)}</td>
                      <td className="num">{fmtDuracion(e.iniciada_en, e.finalizada_en)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        {tab === "reportes" &&
          (p.reportes.length === 0 ? (
            <EmptyState icono="file" titulo="Sin reportes" texto="Genera un informe con las evaluaciones de este proyecto." accion={<Link to={`/reportes?proyecto=${p.id}`} className="btn btn-primary">Generar reporte</Link>} />
          ) : (
            <ul className="rows">
              {p.reportes.map((r) => (
                <li key={r.id} className="clic" onClick={() => nav(`/reportes/${r.id}`)}>
                  <span className="icono-caja"><Icon name="file" size={18} /></span>
                  <div className="grow">
                    <Link to={`/reportes/${r.id}`} className="titulo" onClick={(e) => e.stopPropagation()}>{r.titulo}</Link>
                    <span className="sub">{fmtFecha(r.generado_en)} · {r.generado_por}</span>
                  </div>
                  <Tag>{plural(r.evaluacion_ids.length, "evaluación", "evaluaciones")}</Tag>
                </li>
              ))}
            </ul>
          ))}
      </div>
      <ActivoModal abierto={modal} onClose={() => setModal(false)} proyectoId={p.id} />
    </>
  );
}
