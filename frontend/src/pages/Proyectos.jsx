import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { EmptyState, EstadoBadge, PageHeader, Panel, Tabs, Tag, useTitulo } from "../components/ui.jsx";
import { SeverityBar, Sparkline } from "../components/charts.jsx";
import { ActivoModal, EvaluarBoton, NoEncontrado, ProyectoModal, ResumenSeveridad, TarjetaProyecto } from "../components/shared.jsx";
import { SevBadge } from "../components/ui.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useData } from "../context/DataContext.jsx";
import { fmtFecha, fmtDuracion, hace, plural } from "../lib/format.js";

export function Proyectos() {
  useTitulo("Proyectos");
  const { data } = useData();
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const [modal, setModal] = useState(params.get("nuevo") === "1");
  const duenos = Object.fromEntries((data.usuarios || []).map((usuario) => [usuario.id, usuario.nombre]));

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
        <div className="cards">
          {data.proyectos.map((proyecto) => (
            <TarjetaProyecto key={proyecto.id} proyecto={proyecto} dueno={user.rol === "admin" ? duenos[proyecto.propietario_id] : null} />
          ))}
        </div>
      )}
      <ProyectoModal abierto={modal} onClose={() => setModal(false)} />
    </>
  );
}

export function ProyectoDetalle() {
  const { id } = useParams();
  const { data } = useData();
  const navegar = useNavigate();
  const [tab, setTab] = useState("activos");
  const [modal, setModal] = useState(false);
  const proyecto = data.proyectosPorId[id];
  useTitulo(proyecto?.nombre || "Proyecto");
  if (!proyecto) return <NoEncontrado que="El proyecto" volver="/proyectos" etiqueta="Ver proyectos" />;

  return (
    <>
      <PageHeader
        migas={[{ texto: "Proyectos", to: "/proyectos" }, { texto: proyecto.nombre }]}
        titulo={proyecto.nombre}
        descripcion={proyecto.descripcion}
        acciones={
          <>
            <button className="btn" onClick={() => setModal(true)}><Icon name="plus" size={16} /> Registrar activo</button>
            <Link to={`/reportes?proyecto=${proyecto.id}`} className="btn"><Icon name="file" size={16} /> Generar reporte</Link>
          </>
        }
      />

      <div className="grid-main-r panel-gap">
        <Panel titulo="Hallazgos abiertos" descripcion="De la última evaluación de cada activo">
          <ResumenSeveridad conteo={proyecto.conteo} />
        </Panel>
        <Panel titulo="Resumen">
          <dl className="kv">
            <dt>Activos</dt><dd className="num">{proyecto.activos.length}</dd>
            <dt>Evaluaciones</dt><dd className="num">{proyecto.evaluaciones.length}</dd>
            <dt>Última evaluación</dt><dd>{proyecto.ultima ? `${fmtFecha(proyecto.ultima.iniciada_en)} (${hace(proyecto.ultima.iniciada_en)})` : "Sin evaluaciones"}</dd>
            <dt>Reportes</dt><dd className="num">{proyecto.reportes.length}</dd>
            <dt>Creado</dt><dd>{fmtFecha(proyecto.creado_en)}</dd>
          </dl>
        </Panel>
      </div>

      <Tabs
        valor={tab}
        onChange={setTab}
        tabs={[
          { valor: "activos", etiqueta: "Activos", n: proyecto.activos.length },
          { valor: "evaluaciones", etiqueta: "Evaluaciones", n: proyecto.evaluaciones.length },
          { valor: "reportes", etiqueta: "Reportes", n: proyecto.reportes.length },
        ]}
      />
      <div className="panel panel-tab">
        {tab === "activos" &&
          (proyecto.activos.length === 0 ? (
            <EmptyState icono="server" titulo="Este proyecto no tiene activos" texto="Registra la primera aplicación o servidor que quieras evaluar." accion={<button className="btn btn-primary" onClick={() => setModal(true)}>Registrar activo</button>} />
          ) : (
            <ul className="rows">
              {proyecto.activos.map((activo) => (
                <li key={activo.id} className="clic" onClick={() => navegar(`/activos/${activo.id}`)}>
                  <div className="grow">
                    <Link to={`/activos/${activo.id}`} className="titulo" onClick={(evento) => evento.stopPropagation()}>{activo.nombre}</Link>
                    <span className="sub mono">{activo.url_objetivo}</span>
                  </div>
                  <div className="row-bar"><SeverityBar conteo={activo.conteo} alto={10} /></div>
                  <Sparkline valores={activo.serie} />
                  <div className="col-sev"><SevBadge sev={activo.maxSev} /></div>
                  <span onClick={(evento) => evento.stopPropagation()}><EvaluarBoton activo={activo} pequeno texto="Evaluar" /></span>
                </li>
              ))}
            </ul>
          ))}
        {tab === "evaluaciones" &&
          (proyecto.evaluaciones.length === 0 ? (
            <EmptyState icono="radar" titulo="Sin evaluaciones todavía" texto="Inicia una desde cualquier activo del proyecto." />
          ) : (
            <div className="table-wrap">
              <table className="tabla tabla-clic">
                <thead><tr><th>Activo</th><th>Estado</th><th>Hallazgos</th><th>Inicio</th><th>Duración</th></tr></thead>
                <tbody>
                  {proyecto.evaluaciones.map((evaluacion) => (
                    <tr key={evaluacion.id} onClick={() => navegar(`/evaluaciones/${evaluacion.id}`)}>
                      <td className="celda-titulo"><Link to={`/evaluaciones/${evaluacion.id}`} onClick={(evento) => evento.stopPropagation()}>{evaluacion.activo?.nombre}</Link></td>
                      <td><EstadoBadge estado={evaluacion.estado} /></td>
                      <td className="num">{evaluacion.estado === "completada" ? evaluacion.conteo.total : "—"}</td>
                      <td>{fmtFecha(evaluacion.iniciada_en)}</td>
                      <td className="num">{fmtDuracion(evaluacion.iniciada_en, evaluacion.finalizada_en)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        {tab === "reportes" &&
          (proyecto.reportes.length === 0 ? (
            <EmptyState icono="file" titulo="Sin reportes" texto="Genera un informe con las evaluaciones de este proyecto." accion={<Link to={`/reportes?proyecto=${proyecto.id}`} className="btn btn-primary">Generar reporte</Link>} />
          ) : (
            <ul className="rows">
              {proyecto.reportes.map((reporte) => (
                <li key={reporte.id} className="clic" onClick={() => navegar(`/reportes/${reporte.id}`)}>
                  <span className="icono-caja"><Icon name="file" size={18} /></span>
                  <div className="grow">
                    <Link to={`/reportes/${reporte.id}`} className="titulo" onClick={(evento) => evento.stopPropagation()}>{reporte.titulo}</Link>
                    <span className="sub">{fmtFecha(reporte.generado_en)} · {reporte.generado_por}</span>
                  </div>
                  <Tag>{plural(reporte.evaluacion_ids.length, "evaluación", "evaluaciones")}</Tag>
                </li>
              ))}
            </ul>
          ))}
      </div>
      <ActivoModal abierto={modal} onClose={() => setModal(false)} proyectoId={proyecto.id} />
    </>
  );
}
