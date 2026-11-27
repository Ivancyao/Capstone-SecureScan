import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Contador, EmptyState, PageHeader, Panel, SevBadge, useTitulo } from "../components/ui.jsx";
import { NoEncontrado } from "../components/shared.jsx";
import { useData } from "../context/DataContext.jsx";
import { compararEvaluaciones, evaluacionAnterior } from "../lib/comparar.js";
import { fmtCvss, fmtFechaHora, plural } from "../lib/format.js";

// Los cuatro resultados posibles de comparar dos evaluaciones: mejora, empeora, mixto o igual (lo calcula lib/comparar.js).
const VEREDICTO = {
  mejora: { icono: "check-circle", clase: "ok", texto: "La exposición bajó respecto de la evaluación anterior." },
  empeora: { icono: "alert", clase: "warn", texto: "La exposición subió: aparecieron hallazgos nuevos o más graves." },
  mixto: { icono: "info", clase: "info", texto: "Hay cambios en ambos sentidos. Revisa el detalle." },
  igual: { icono: "check-circle", clase: "info", texto: "No hubo cambios entre las dos evaluaciones." },
};

function Cifra({ icono, etiqueta, valor, pie, tono }) {
  return (
    <div className="kpi kpi-estatica" style={{ "--kpi-c": tono }}>
      <span className="kpi-top"><span className="kpi-ic"><Icon name={icono} size={18} /></span></span>
      <span className="kpi-n"><Contador valor={valor} /></span>
      <span className="kpi-et">{etiqueta}</span>
      <span className="kpi-pie">{pie}</span>
    </div>
  );
}

function Lista({ titulo, descripcion, filas, vacio, hrefDe, detalle }) {
  return (
    <Panel titulo={`${titulo} (${filas.length})`} descripcion={descripcion} flush>
      {filas.length === 0 ? (
        <p className="small muted tabla-vacia">{vacio}</p>
      ) : (
        <ul className="rows">
          {filas.map((fila, indice) => {
            const hallazgo = fila.ahora || fila;
            return (
              <li key={`${hallazgo.id}-${indice}`}>
                <div className="grow">
                  <Link to={hrefDe(hallazgo)} className="titulo">{hallazgo.nombre_vulnerabilidad}</Link>
                  <span className="sub">{detalle ? detalle(fila) : `CVSS ${fmtCvss(hallazgo.cvss_score)}${hallazgo.categoria_owasp ? ` · ${hallazgo.categoria_owasp}` : ""}`}</span>
                </div>
                {fila.antes ? (
                  <span className="row-inline"><SevBadge sev={fila.antes.severidad} /><Icon name="arrow-right" size={14} /><SevBadge sev={fila.ahora.severidad} /></span>
                ) : (
                  <SevBadge sev={hallazgo.severidad} />
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

// Compara una evaluación con la anterior del mismo activo (o con otra que se elija) y muestra qué hallazgos son nuevos, cuáles se resolvieron y cuáles siguen.
export function Comparar() {
  const { id } = useParams();
  const { data } = useData();
  const navegar = useNavigate();
  const [params, setParams] = useSearchParams();
  const actual = data.evaluacionPorId[id];
  useTitulo(actual ? `Comparar ${actual.activo?.nombre}` : "Comparar evaluaciones");
  if (!actual) return <NoEncontrado que="La evaluación" volver="/evaluaciones" etiqueta="Ver evaluaciones" />;

  // Solo se comparan evaluaciones completadas y del mismo activo; si no hay al menos dos, aviso que falta una.
  const completadas = data.evaluaciones.filter((evaluacion) => evaluacion.activo_id === actual.activo_id && evaluacion.estado === "completada");
  const base = (params.get("con") && data.evaluacionPorId[params.get("con")]) || evaluacionAnterior(data.evaluaciones, actual);
  const migas = [{ texto: "Evaluaciones", to: "/evaluaciones" }, { texto: actual.activo?.nombre || "Evaluación", to: `/evaluaciones/${actual.id}` }, { texto: "Comparar" }];

  if (!base || base.activo_id !== actual.activo_id || base.id === actual.id) {
    return (
      <>
        <PageHeader migas={migas} titulo={`Comparar ${actual.activo?.nombre}`} />
        <div className="panel">
          <EmptyState icono="radar" titulo="Falta una evaluación para comparar" texto="Este activo necesita al menos dos evaluaciones completadas. Vuelve a evaluarlo y aquí verás qué cambió." accion={<Link to={`/evaluaciones/${actual.id}`} className="btn">Volver a la evaluación</Link>} />
        </div>
      </>
    );
  }

  // El orden cronológico lo decide la fecha, no el orden en que se eligieron
  // Por si el usuario elige las evaluaciones al revés, ordeno por fecha para que siempre "antes" sea la más antigua.
  const [antes, despues] = new Date(base.iniciada_en) <= new Date(actual.iniciada_en) ? [base, actual] : [actual, base];
  const comparacion = compararEvaluaciones(antes, despues);
  const estiloVeredicto = VEREDICTO[comparacion.veredicto];
  const etiqueta = (evaluacion) => fmtFechaHora(evaluacion.iniciada_en);
  const elegir = (clave, valor) => {
    const parametros = new URLSearchParams(params);
    parametros.set(clave, valor);
    if (clave === "con") setParams(parametros, { replace: true });
    else navegar(`/evaluaciones/${valor}/comparar?${parametros.toString()}`, { replace: true });
  };

  return (
    <>
      <PageHeader
        migas={migas}
        titulo={`Qué cambió en ${actual.activo?.nombre}`}
        descripcion={`${plural(comparacion.totalAntes, "hallazgo", "hallazgos")} antes, ${plural(comparacion.totalAhora, "hallazgo", "hallazgos")} ahora.`}
        acciones={<Link to={`/evaluaciones/${despues.id}`} className="btn"><Icon name="arrow-left" size={16} /> Ver evaluación</Link>}
      />

      <div className="comparar-sel panel-gap">
        <label className="field">
          <span className="label">Antes</span>
          <select className="select" value={antes.id} onChange={(evento) => elegir(antes.id === base.id ? "con" : "id", evento.target.value)}>
            {completadas.map((completada) => <option key={completada.id} value={completada.id}>{etiqueta(completada)}</option>)}
          </select>
        </label>
        <Icon name="arrow-right" size={18} className="comparar-flecha" />
        <label className="field">
          <span className="label">Ahora</span>
          <select className="select" value={despues.id} onChange={(evento) => elegir(despues.id === base.id ? "con" : "id", evento.target.value)}>
            {completadas.map((completada) => <option key={completada.id} value={completada.id}>{etiqueta(completada)}</option>)}
          </select>
        </label>
      </div>

      <div className={`notice notice-${estiloVeredicto.clase} panel-gap`} role="status">
        <Icon name={estiloVeredicto.icono} size={18} />
        <div>{estiloVeredicto.texto}</div>
      </div>

      <div className="kpis panel-gap">
        <Cifra icono="alert" etiqueta="Nuevos" valor={comparacion.nuevos.length} pie="Aparecieron en esta evaluación" tono="var(--sev-alta)" />
        <Cifra icono="check-circle" etiqueta="Resueltos" valor={comparacion.resueltos.length} pie="Ya no aparecen" tono="var(--sev-baja)" />
        <Cifra icono="layers" etiqueta="Persisten" valor={comparacion.persisten.length} pie="Siguen igual" tono="var(--accent)" />
        <Cifra icono="refresh" etiqueta="Cambiaron de severidad" valor={comparacion.cambiaron.length} pie="Subieron o bajaron" tono="var(--sev-media)" />
      </div>

      <div className="stack">
        <Lista titulo="Nuevos" descripcion="Detectados ahora y no antes. Empieza por los más graves." filas={comparacion.nuevos} vacio="No aparecieron hallazgos nuevos." hrefDe={(hallazgo) => `/hallazgos/${hallazgo.id}`} />
        <Lista titulo="Resueltos" descripcion="Estaban en la evaluación anterior y ya no se detectan." filas={comparacion.resueltos} vacio="Ningún hallazgo desapareció." hrefDe={(hallazgo) => `/evaluaciones/${antes.id}`} />
        <Lista titulo="Cambiaron de severidad" descripcion="El mismo hallazgo, con otra severidad." filas={comparacion.cambiaron} vacio="Ningún hallazgo cambió de severidad." hrefDe={(hallazgo) => `/hallazgos/${hallazgo.id}`} detalle={(fila) => (fila.sube ? "Empeoró" : "Mejoró")} />
        <Lista titulo="Persisten" descripcion="Siguen abiertos desde la evaluación anterior." filas={comparacion.persisten} vacio="No quedan hallazgos de la evaluación anterior." hrefDe={(hallazgo) => `/hallazgos/${hallazgo.id}`} />
      </div>
    </>
  );
}
