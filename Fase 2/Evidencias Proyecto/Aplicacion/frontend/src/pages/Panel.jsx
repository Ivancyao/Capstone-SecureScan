import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Aviso, EmptyState, EstadoBadge, PageHeader, Panel, Progress, TarjetaKpi, useTitulo } from "../components/ui.jsx";
import { ChartFrame, HBars, LeyendaSev, WeeklyColumns } from "../components/charts.jsx";
import { PortMap } from "../components/PortMap.jsx";
import { ProyectoModal, ResumenSeveridad, TarjetaActivo } from "../components/shared.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useData } from "../context/DataContext.jsx";
import { fmtFechaHora, hace, plural } from "../lib/format.js";
import { SEVERIDADES } from "../lib/risk.js";

// Pantalla principal. Resume el estado de seguridad: cifras clave, evaluaciones en curso, tendencia semanal, ranking OWASP y los activos que más atención necesitan.
export default function Panel_() {
  useTitulo("Panel");
  const { user } = useAuth();
  const { data } = useData();
  const navegar = useNavigate();
  const [modal, setModal] = useState(false);
  const nombre = user?.nombre?.split(" ")[0] || "";

  // Estado vacío: si todavía no hay proyectos, en vez de un panel con ceros le explico qué hacer primero.
  if (data.proyectos.length === 0) {
    return (
      <>
        <PageHeader titulo={`Hola, ${nombre}`} descripcion="Todavía no hay nada que evaluar. Empieza creando un proyecto." />
        <div className="panel">
          <EmptyState
            icono="folder"
            titulo="Crea tu primer proyecto"
            texto="Un proyecto agrupa los activos que quieres revisar. Después registra un activo, lánzale una evaluación y aquí verás qué corregir primero."
            accion={<button className="btn btn-primary" onClick={() => setModal(true)}><Icon name="plus" size={16} /> Crear proyecto</button>}
          />
        </div>
        <ProyectoModal abierto={modal} onClose={() => setModal(false)} />
      </>
    );
  }

  // Todos estos números ya vienen calculados por derive.js (a partir de /metricas en el backend); acá solo los muestro.
  const { conteoGlobal, activosAtencion, enCurso, evaluaciones, porOwasp, semanas } = data;
  const masExpuesto = activosAtencion[0];
  // Cuento los activos que ya tienen al menos una evaluación completada.
  const evaluados = data.activos.filter((activo) => activo.ultimaOk).length;

  return (
    <>
      <PageHeader
        titulo={`Hola, ${nombre}`}
        descripcion={
          conteoGlobal.total === 0
            ? "No hay hallazgos abiertos. Mantén las evaluaciones al día para confirmarlo."
            : `${plural(conteoGlobal.total, "hallazgo abierto", "hallazgos abiertos")} en ${plural(evaluados, "activo evaluado", "activos evaluados")}. Empieza por los de mayor severidad.`
        }
        acciones={
          <Link to="/evaluaciones/nueva" className="btn btn-primary"><Icon name="play" size={15} /> Nueva evaluación</Link>
        }
      />

      {enCurso.length > 0 && (
        <div className="stack-sm panel-gap">
          {enCurso.map((evaluacion) => (
            <Link key={evaluacion.id} to={`/evaluaciones/${evaluacion.id}`} className="encurso">
              <span className="estado estado-en_progreso"><i aria-hidden="true" /></span>
              <span className="grow">
                <strong>Evaluando {evaluacion.activo?.nombre}</strong>
                <span className="small muted"> · {evaluacion.etapa || "En cola"}</span>
              </span>
              <span className="encurso-bar"><Progress valor={evaluacion.progreso || 0} indeterminado={evaluacion.progreso == null} /></span>
              <Icon name="chevron-right" size={16} />
            </Link>
          ))}
        </div>
      )}

      <div className="kpis panel-gap">
        <TarjetaKpi to="/hallazgos?sev=critica" icono="alert" etiqueta="Hallazgos críticos" valor={conteoGlobal.critica} pie={conteoGlobal.critica ? "Corregir de inmediato" : "Nada urgente"} tono="var(--sev-critica)" />
        <TarjetaKpi to="/hallazgos?sev=alta" icono="shield" etiqueta="Hallazgos altos" valor={conteoGlobal.alta} pie={conteoGlobal.alta ? "Corregir en el corto plazo" : "Sin pendientes altos"} tono="var(--sev-alta)" />
        <TarjetaKpi to="/activos" icono="server" etiqueta="Activos evaluados" valor={evaluados} pie={`de ${plural(data.activos.length, "activo registrado", "activos registrados")}`} />
        <TarjetaKpi to="/evaluaciones" icono="radar" etiqueta="Evaluaciones" valor={evaluaciones.length} pie={enCurso.length ? `${enCurso.length} en curso ahora` : "Ninguna en curso"} tono="var(--st-completada)" />
      </div>

      <div className="grid-main panel-gap">
        <Panel
          className="panel-hero"
          titulo={masExpuesto ? masExpuesto.nombre : "Mapa de puertos"}
          descripcion={masExpuesto ? `Activo más expuesto · ${plural(masExpuesto.abiertos.length, "hallazgo abierto", "hallazgos abiertos")} · evaluado ${hace(masExpuesto.ultimaOk?.iniciada_en)}` : "Cuando evalúes un activo, sus puertos aparecerán aquí."}
          acciones={masExpuesto && <Link className="btn btn-sm" to={`/evaluaciones/${masExpuesto.ultimaOk.id}`}>Ver evaluación</Link>}
        >
          {masExpuesto ? (
            <div className="stack-sm">
              <PortMap hallazgos={masExpuesto.ultimaOk.hallazgos} alSeleccionar={(hallazgo) => navegar(`/hallazgos/${hallazgo.id}`)} />
              <LeyendaSev />
            </div>
          ) : (
            <Aviso tipo="ok" icono="check-circle">Ningún activo tiene hallazgos abiertos.</Aviso>
          )}
        </Panel>

        <Panel titulo="Hallazgos abiertos" descripcion="De la última evaluación de cada activo">
          <div className="total-fig">
            <span className="total-n">{conteoGlobal.total}</span>
            <span className="muted small">en total</span>
          </div>
          <ResumenSeveridad conteo={conteoGlobal} />
        </Panel>
      </div>

      <div className="grid-main panel-gap">
        <Panel>
          <ChartFrame
            titulo="Hallazgos detectados por semana"
            descripcion="Suma de las evaluaciones completadas cada semana"
            leyenda={<LeyendaSev />}
            tabla={{
              columnas: ["Semana", ...SEVERIDADES.map((severidad) => severidad[0].toUpperCase() + severidad.slice(1)), "Total"],
              filas: semanas.map((semana) => [semana.inicio.toLocaleDateString("es-CL", { day: "numeric", month: "short" }), ...SEVERIDADES.map((severidad) => semana[severidad]), semana.total]),
            }}
          >
            <WeeklyColumns semanas={semanas} />
          </ChartFrame>
        </Panel>
        <Panel>
          <ChartFrame
            titulo="Categorías OWASP Top 10"
            descripcion="Hallazgos abiertos agrupados por categoría"
            tabla={{ columnas: ["Categoría", "Hallazgos"], filas: porOwasp.map((categoria) => [`${categoria.codigo} ${categoria.nombre}`, categoria.n]) }}
          >
            <HBars filas={porOwasp.slice(0, 6).map((categoria) => ({ ...categoria, etiqueta: `${categoria.codigo} ${categoria.nombre}`, valor: categoria.n }))} vacio="Sin hallazgos abiertos." />
          </ChartFrame>
        </Panel>
      </div>

      <div className="grid-main panel-gap">
        <div className="atencion">
          <div className="atencion-head">
            <h2 className="h-section">Activos que requieren atención</h2>
            <p className="small muted">Ordenados por la severidad más alta que tienen abierta</p>
          </div>
          {activosAtencion.length === 0 ? (
            <p className="small muted tabla-vacia">Todos los activos están al día.</p>
          ) : (
            <div className="cards cards-2">
              {activosAtencion.slice(0, 4).map((activo) => <TarjetaActivo key={activo.id} activo={activo} />)}
            </div>
          )}
        </div>

        <Panel className="panel-flat" titulo="Actividad reciente" flush acciones={<Link className="btn btn-quiet btn-sm" to="/evaluaciones">Ver todas</Link>}>
          <ul className="rows">
            {evaluaciones.slice(0, 6).map((evaluacion) => (
              <li key={evaluacion.id} className="clic" onClick={() => navegar(`/evaluaciones/${evaluacion.id}`)}>
                <div className="grow">
                  <Link to={`/evaluaciones/${evaluacion.id}`} className="titulo" onClick={(evento) => evento.stopPropagation()}>{evaluacion.activo?.nombre}</Link>
                  <span className="sub" title={fmtFechaHora(evaluacion.iniciada_en)}>{hace(evaluacion.iniciada_en)}</span>
                </div>
                <EstadoBadge estado={evaluacion.estado} />
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </>
  );
}
