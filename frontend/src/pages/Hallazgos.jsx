import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Aviso, EmptyState, PageHeader, Panel, Segmented, SevBadge, SevMark, Tag, useTitulo } from "../components/ui.jsx";
import { CvssMeter } from "../components/charts.jsx";
import { CopiarBoton, EvaluarBoton, NoEncontrado, TablaHallazgos, nombreHerramienta } from "../components/shared.jsx";
import { useData } from "../context/DataContext.jsx";
import { useToast } from "../context/ToastContext.jsx";
import { fmtCvss, fmtFecha, fmtFechaHora, hace } from "../lib/format.js";
import { HERRAMIENTAS, OWASP, SEV, SEVERIDADES, ordenSev, owaspCodigo, puertoDeHallazgo } from "../lib/risk.js";

export function Hallazgos() {
  useTitulo("Hallazgos");
  const { data } = useData();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  const [sevs, setSevs] = useState([]);
  const [herr, setHerr] = useState("");
  const [owasp, setOwasp] = useState("");
  const [estado, setEstado] = useState("abiertos");
  const [historico, setHistorico] = useState(false);
  const [orden, setOrden] = useState("severidad");

  const base = data.hallazgos.filter((h) => historico || h.vigente);
  const porSev = Object.fromEntries(SEVERIDADES.map((s) => [s, base.filter((h) => h.severidad === s).length]));

  const lista = useMemo(() => {
    const t = q.trim().toLowerCase();
    const r = base.filter(
      (h) =>
        (!t || `${h.nombre_vulnerabilidad} ${h.evidencia} ${h.activo?.nombre} ${h.categoria_owasp}`.toLowerCase().includes(t)) &&
        (!sevs.length || sevs.includes(h.severidad)) &&
        (!herr || h.herramienta_origen === herr) &&
        (!owasp || owaspCodigo(h.categoria_owasp) === owasp) &&
        (estado === "todos" || (estado === "abiertos" ? h.corregido !== "si" : h.corregido === "si"))
    );
    return r.sort((a, b) => {
      if (orden === "cvss") return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
      if (orden === "fecha") return new Date(b.fecha) - new Date(a.fecha);
      return ordenSev(a.severidad) - ordenSev(b.severidad) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
    });
  }, [base, q, sevs, herr, owasp, estado, orden]);

  const hayFiltros = q || sevs.length || herr || owasp || estado !== "abiertos" || historico;
  const limpiar = () => {
    setQ(""); setSevs([]); setHerr(""); setOwasp(""); setEstado("abiertos"); setHistorico(false);
    if (params.get("q")) setParams({}, { replace: true });
  };
  const alternarSev = (s) => setSevs((x) => (x.includes(s) ? x.filter((y) => y !== s) : [...x, s]));
  const categorias = [...new Set(data.hallazgos.map((h) => owaspCodigo(h.categoria_owasp)))].sort();

  return (
    <>
      <PageHeader titulo="Hallazgos" descripcion="Todas las vulnerabilidades y exposiciones detectadas, de la más grave a la menos grave." />
      {data.hallazgos.length === 0 ? (
        <div className="panel">
          <EmptyState icono="alert" titulo="Sin hallazgos todavía" texto="Los hallazgos aparecen cuando una evaluación termina. Lanza una para empezar." accion={<Link to="/evaluaciones/nueva" className="btn btn-primary">Nueva evaluación</Link>} />
        </div>
      ) : (
        <>
          <div className="filtros-bloque">
            <div className="filtros">
              <div className="search-inline">
                <Icon name="search" size={16} />
                <input className="input" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar por nombre, puerto o activo" aria-label="Buscar hallazgos" />
              </div>
              <div className="chips" role="group" aria-label="Filtrar por severidad">
                {SEVERIDADES.map((s) => (
                  <button key={s} type="button" className="chip" aria-pressed={sevs.includes(s)} onClick={() => alternarSev(s)}>
                    <SevMark sev={s} /> {SEV[s].label} <span className="n num">{porSev[s]}</span>
                  </button>
                ))}
              </div>
            </div>
            <div className="filtros">
              <Segmented etiqueta="Estado" valor={estado} onChange={setEstado} opciones={[{ valor: "abiertos", etiqueta: "Abiertos" }, { valor: "corregidos", etiqueta: "Corregidos" }, { valor: "todos", etiqueta: "Todos" }]} />
              <select className="select" value={herr} onChange={(e) => setHerr(e.target.value)} aria-label="Herramienta">
                <option value="">Cualquier herramienta</option>
                {Object.entries(HERRAMIENTAS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <select className="select" value={owasp} onChange={(e) => setOwasp(e.target.value)} aria-label="Categoría OWASP">
                <option value="">Cualquier categoría OWASP</option>
                {categorias.map((c) => <option key={c} value={c}>{c} {OWASP[c]}</option>)}
              </select>
              <select className="select" value={orden} onChange={(e) => setOrden(e.target.value)} aria-label="Ordenar por">
                <option value="severidad">Orden: severidad</option>
                <option value="cvss">Orden: CVSS</option>
                <option value="fecha">Orden: más recientes</option>
              </select>
              <label className="check"><input type="checkbox" checked={historico} onChange={(e) => setHistorico(e.target.checked)} /> Incluir evaluaciones anteriores</label>
              {hayFiltros && <button className="btn btn-quiet btn-sm" onClick={limpiar}>Limpiar filtros</button>}
            </div>
          </div>

          <p className="small muted resultado-n" role="status">{lista.length} {lista.length === 1 ? "hallazgo" : "hallazgos"}</p>
          <div className="panel">
            {lista.length === 0 ? (
              <EmptyState icono="search" titulo="Ningún hallazgo coincide" texto="Prueba con otros filtros o quita alguno." accion={<button className="btn" onClick={limpiar}>Limpiar filtros</button>} />
            ) : (
              <TablaHallazgos hallazgos={lista} mostrarActivo mostrarFecha={historico} />
            )}
          </div>
        </>
      )}
    </>
  );
}

export function HallazgoDetalle() {
  const { id } = useParams();
  const { data, marcarCorregido } = useData();
  const toast = useToast();
  const nav = useNavigate();
  const [cargando, setCargando] = useState(false);
  const h = data.hallazgosPorId[id];
  useTitulo(h?.nombre_vulnerabilidad || "Hallazgo");
  if (!h) return <NoEncontrado que="El hallazgo" volver="/hallazgos" etiqueta="Ver hallazgos" />;

  const a = h.activo;
  const corregido = h.corregido === "si";
  const puerto = puertoDeHallazgo(h);
  const cod = owaspCodigo(h.categoria_owasp);
  // ¿En qué evaluaciones del activo aparece el mismo hallazgo?
  const historia = (a?.evaluaciones || [])
    .filter((e) => e.estado === "completada")
    .map((e) => ({ e, presente: e.hallazgos.some((x) => x.nombre_vulnerabilidad === h.nombre_vulnerabilidad) }))
    .reverse();
  const otros = (a?.abiertos || []).filter((x) => x.id !== h.id).sort((x, y) => ordenSev(x.severidad) - ordenSev(y.severidad)).slice(0, 4);

  const alternar = async () => {
    setCargando(true);
    try {
      await marcarCorregido(h.id, !corregido);
      toast.ok(corregido ? "Hallazgo reabierto" : "Marcado como corregido", corregido ? undefined : "Vuelve a evaluar el activo para confirmar la corrección.");
    } catch {
      /* aviso mostrado */
    } finally {
      setCargando(false);
    }
  };

  return (
    <>
      <PageHeader
        migas={[{ texto: "Hallazgos", to: "/hallazgos" }, { texto: h.nombre_vulnerabilidad }]}
        titulo={h.nombre_vulnerabilidad}
        descripcion={
          <span className="row ph-meta">
            <SevBadge sev={h.severidad} />
            <Tag>{nombreHerramienta(h.herramienta_origen)}</Tag>
            {corregido ? <Tag tono="ok">Corregido</Tag> : <Tag>Abierto</Tag>}
            {!h.vigente && <Tag tono="warn">De una evaluación anterior</Tag>}
          </span>
        }
        acciones={
          <button className={`btn ${corregido ? "" : "btn-primary"}`} onClick={alternar} disabled={cargando}>
            <Icon name={corregido ? "refresh" : "check"} size={16} />
            {corregido ? "Reabrir hallazgo" : "Marcar como corregido"}
          </button>
        }
      />

      <div className="grid-main">
        <div className="stack">
          <Panel titulo="Qué se encontró">
            <div className="stack-sm">
              <pre className="codeblock">{h.evidencia}</pre>
              <dl className="kv">
                <dt>Activo</dt><dd><Link to={`/activos/${a?.id}`}>{a?.nombre}</Link> <span className="muted">· {a?.proyecto?.nombre}</span></dd>
                {puerto && <><dt>Puerto</dt><dd className="num">{puerto.puerto}/{puerto.protocolo}{puerto.servicio ? ` (${puerto.servicio})` : ""}</dd></>}
                <dt>Detectado</dt><dd>{fmtFechaHora(h.fecha)} <span className="muted">({hace(h.fecha)})</span></dd>
                <dt>Evaluación</dt><dd><Link to={`/evaluaciones/${h.evaluacion_id}`}>Ver evaluación completa</Link></dd>
              </dl>
            </div>
          </Panel>

          <Panel titulo="Cómo corregirlo" descripcion={SEV[h.severidad].accion}>
            <div className="prose"><p>{h.recomendacion}</p></div>
            <div className="row panel-actions-top">
              {a && <EvaluarBoton activo={a} texto="Volver a evaluar para confirmar" />}
            </div>
          </Panel>

          {historia.length > 1 && (
            <Panel titulo="Presencia en evaluaciones" descripcion="Si este hallazgo seguía abierto en cada evaluación del activo">
              <ul className="historia">
                {historia.map(({ e, presente }) => (
                  <li key={e.id} className={presente ? "si" : "no"}>
                    <span className="historia-dot" aria-hidden="true">{presente ? <Icon name="alert" size={12} /> : <Icon name="check" size={12} />}</span>
                    <Link to={`/evaluaciones/${e.id}`}>{fmtFecha(e.iniciada_en)}</Link>
                    <span className="muted small">{presente ? "Presente" : "No apareció"}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>

        <div className="stack">
          <Panel titulo="Riesgo">
            <div className="stack-sm">
              <div className="cvss-fig">
                <span className="cvss-n">{fmtCvss(h.cvss_score)}</span>
                <span className="small muted">CVSS estimado, de 10</span>
              </div>
              <CvssMeter valor={h.cvss_score} />
              <dl className="kv">
                <dt>Severidad</dt><dd>{SEV[h.severidad].label} ({SEV[h.severidad].rango})</dd>
                <dt>OWASP Top 10</dt><dd>{h.categoria_owasp || "Sin categoría"}</dd>
              </dl>
              <Aviso>El puntaje se estima por reglas según el servicio expuesto; no es un cálculo vectorial completo de CVSS.</Aviso>
              {cod !== "—" && <Link to="/ayuda#owasp" className="small">¿Qué es {cod}?</Link>}
            </div>
          </Panel>

          {otros.length > 0 && (
            <Panel titulo="Otros hallazgos de este activo" flush>
              <ul className="rows">
                {otros.map((x) => (
                  <li key={x.id} className="clic" onClick={() => nav(`/hallazgos/${x.id}`)}>
                    <div className="grow">
                      <Link to={`/hallazgos/${x.id}`} className="titulo" onClick={(e) => e.stopPropagation()}>{x.nombre_vulnerabilidad}</Link>
                    </div>
                    <SevBadge sev={x.severidad} />
                  </li>
                ))}
              </ul>
            </Panel>
          )}
          <CopiarBoton texto={`${h.nombre_vulnerabilidad} — ${h.evidencia}`} etiqueta="Copiar resumen" />
        </div>
      </div>
    </>
  );
}
