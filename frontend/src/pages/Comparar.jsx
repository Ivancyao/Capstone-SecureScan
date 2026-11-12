import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Contador, EmptyState, PageHeader, Panel, SevBadge, useTitulo } from "../components/ui.jsx";
import { NoEncontrado } from "../components/shared.jsx";
import { useData } from "../context/DataContext.jsx";
import { compararEvaluaciones, evaluacionAnterior } from "../lib/comparar.js";
import { fmtCvss, fmtFechaHora, plural } from "../lib/format.js";

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
          {filas.map((f, i) => {
            const h = f.ahora || f;
            return (
              <li key={`${h.id}-${i}`}>
                <div className="grow">
                  <Link to={hrefDe(h)} className="titulo">{h.nombre_vulnerabilidad}</Link>
                  <span className="sub">{detalle ? detalle(f) : `CVSS ${fmtCvss(h.cvss_score)}${h.categoria_owasp ? ` · ${h.categoria_owasp}` : ""}`}</span>
                </div>
                {f.antes ? (
                  <span className="row-inline"><SevBadge sev={f.antes.severidad} /><Icon name="arrow-right" size={14} /><SevBadge sev={f.ahora.severidad} /></span>
                ) : (
                  <SevBadge sev={h.severidad} />
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

export function Comparar() {
  const { id } = useParams();
  const { data } = useData();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const actual = data.evaluacionPorId[id];
  useTitulo(actual ? `Comparar ${actual.activo?.nombre}` : "Comparar evaluaciones");
  if (!actual) return <NoEncontrado que="La evaluación" volver="/evaluaciones" etiqueta="Ver evaluaciones" />;

  const completadas = data.evaluaciones.filter((e) => e.activo_id === actual.activo_id && e.estado === "completada");
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
  const [antes, despues] = new Date(base.iniciada_en) <= new Date(actual.iniciada_en) ? [base, actual] : [actual, base];
  const c = compararEvaluaciones(antes, despues);
  const v = VEREDICTO[c.veredicto];
  const etiqueta = (e) => fmtFechaHora(e.iniciada_en);
  const elegir = (clave, valor) => {
    const p = new URLSearchParams(params);
    p.set(clave, valor);
    if (clave === "con") setParams(p, { replace: true });
    else nav(`/evaluaciones/${valor}/comparar?${p.toString()}`, { replace: true });
  };

  return (
    <>
      <PageHeader
        migas={migas}
        titulo={`Qué cambió en ${actual.activo?.nombre}`}
        descripcion={`${plural(c.totalAntes, "hallazgo", "hallazgos")} antes, ${plural(c.totalAhora, "hallazgo", "hallazgos")} ahora.`}
        acciones={<Link to={`/evaluaciones/${despues.id}`} className="btn"><Icon name="arrow-left" size={16} /> Ver evaluación</Link>}
      />

      <div className="comparar-sel panel-gap">
        <label className="field">
          <span className="label">Antes</span>
          <select className="select" value={antes.id} onChange={(e) => elegir(antes.id === base.id ? "con" : "id", e.target.value)}>
            {completadas.map((e) => <option key={e.id} value={e.id}>{etiqueta(e)}</option>)}
          </select>
        </label>
        <Icon name="arrow-right" size={18} className="comparar-flecha" />
        <label className="field">
          <span className="label">Ahora</span>
          <select className="select" value={despues.id} onChange={(e) => elegir(despues.id === base.id ? "con" : "id", e.target.value)}>
            {completadas.map((e) => <option key={e.id} value={e.id}>{etiqueta(e)}</option>)}
          </select>
        </label>
      </div>

      <div className={`notice notice-${v.clase} panel-gap`} role="status">
        <Icon name={v.icono} size={18} />
        <div>{v.texto}</div>
      </div>

      <div className="kpis panel-gap">
        <Cifra icono="alert" etiqueta="Nuevos" valor={c.nuevos.length} pie="Aparecieron en esta evaluación" tono="var(--sev-alta)" />
        <Cifra icono="check-circle" etiqueta="Resueltos" valor={c.resueltos.length} pie="Ya no aparecen" tono="var(--sev-baja)" />
        <Cifra icono="layers" etiqueta="Persisten" valor={c.persisten.length} pie="Siguen igual" tono="var(--accent)" />
        <Cifra icono="refresh" etiqueta="Cambiaron de severidad" valor={c.cambiaron.length} pie="Subieron o bajaron" tono="var(--sev-media)" />
      </div>

      <div className="stack">
        <Lista titulo="Nuevos" descripcion="Detectados ahora y no antes. Empieza por los más graves." filas={c.nuevos} vacio="No aparecieron hallazgos nuevos." hrefDe={(h) => `/hallazgos/${h.id}`} />
        <Lista titulo="Resueltos" descripcion="Estaban en la evaluación anterior y ya no se detectan." filas={c.resueltos} vacio="Ningún hallazgo desapareció." hrefDe={(h) => `/evaluaciones/${antes.id}`} />
        <Lista titulo="Cambiaron de severidad" descripcion="El mismo hallazgo, con otra severidad." filas={c.cambiaron} vacio="Ningún hallazgo cambió de severidad." hrefDe={(h) => `/hallazgos/${h.id}`} detalle={(f) => (f.sube ? "Empeoró" : "Mejoró")} />
        <Lista titulo="Persisten" descripcion="Siguen abiertos desde la evaluación anterior." filas={c.persisten} vacio="No quedan hallazgos de la evaluación anterior." hrefDe={(h) => `/hallazgos/${h.id}`} />
      </div>
    </>
  );
}
