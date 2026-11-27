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

// Lista de hallazgos con filtros combinables: texto, severidad, herramienta, categoría OWASP y estado. Por defecto solo muestra los vigentes y abiertos.
export function Hallazgos() {
  useTitulo("Hallazgos");
  const { data } = useData();
  const [params, setParams] = useSearchParams();
  const [busqueda, setBusqueda] = useState(params.get("q") || "");
  const [severidades, setSeveridades] = useState(() => (params.get("sev") || "").split(",").filter((severidad) => SEVERIDADES.includes(severidad)));
  const [herramienta, setHerramienta] = useState("");
  const [owasp, setOwasp] = useState("");
  const [estado, setEstado] = useState("abiertos");
  const [historico, setHistorico] = useState(false);
  const [orden, setOrden] = useState("severidad");

  // "Vigente" = pertenece a la última evaluación completada de su activo. Con la opción histórico se ven también los antiguos.
  const base = data.hallazgos.filter((hallazgo) => historico || hallazgo.vigente);
  const porSev = Object.fromEntries(SEVERIDADES.map((severidad) => [severidad, base.filter((hallazgo) => hallazgo.severidad === severidad).length]));

  // Aplico todos los filtros y el orden elegido (severidad, CVSS o fecha). useMemo evita recalcular si no cambió nada.
  const lista = useMemo(() => {
    const texto = busqueda.trim().toLowerCase();
    const resultado = base.filter(
      (hallazgo) =>
        (!texto || `${hallazgo.nombre_vulnerabilidad} ${hallazgo.evidencia} ${hallazgo.activo?.nombre} ${hallazgo.categoria_owasp}`.toLowerCase().includes(texto)) &&
        (!severidades.length || severidades.includes(hallazgo.severidad)) &&
        (!herramienta || hallazgo.herramienta_origen === herramienta) &&
        (!owasp || owaspCodigo(hallazgo.categoria_owasp) === owasp) &&
        (estado === "todos" || (estado === "abiertos" ? hallazgo.corregido !== "si" : hallazgo.corregido === "si"))
    );
    return resultado.sort((primero, segundo) => {
      if (orden === "cvss") return (segundo.cvss_score ?? 0) - (primero.cvss_score ?? 0);
      if (orden === "fecha") return new Date(segundo.fecha) - new Date(primero.fecha);
      return ordenSev(primero.severidad) - ordenSev(segundo.severidad) || (segundo.cvss_score ?? 0) - (primero.cvss_score ?? 0);
    });
  }, [base, busqueda, severidades, herramienta, owasp, estado, orden]);

  const hayFiltros = busqueda || severidades.length || herramienta || owasp || estado !== "abiertos" || historico;
  const limpiar = () => {
    setBusqueda(""); setSeveridades([]); setHerramienta(""); setOwasp(""); setEstado("abiertos"); setHistorico(false);
    if (params.get("q")) setParams({}, { replace: true });
  };
  const alternarSev = (severidad) => setSeveridades((seleccionadas) => (seleccionadas.includes(severidad) ? seleccionadas.filter((otra) => otra !== severidad) : [...seleccionadas, severidad]));
  const categorias = [...new Set(data.hallazgos.map((hallazgo) => owaspCodigo(hallazgo.categoria_owasp)))].sort();

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
                <input className="input" type="search" value={busqueda} onChange={(evento) => setBusqueda(evento.target.value)} placeholder="Buscar por nombre, puerto o activo" aria-label="Buscar hallazgos" />
              </div>
              <div className="chips" role="group" aria-label="Filtrar por severidad">
                {SEVERIDADES.map((severidad) => (
                  <button key={severidad} type="button" className="chip" aria-pressed={severidades.includes(severidad)} onClick={() => alternarSev(severidad)}>
                    <SevMark sev={severidad} /> {SEV[severidad].label} <span className="n num">{porSev[severidad]}</span>
                  </button>
                ))}
              </div>
            </div>
            <div className="filtros">
              <Segmented etiqueta="Estado" valor={estado} onChange={setEstado} opciones={[{ valor: "abiertos", etiqueta: "Abiertos" }, { valor: "corregidos", etiqueta: "Corregidos" }, { valor: "todos", etiqueta: "Todos" }]} />
              <select className="select" value={herramienta} onChange={(evento) => setHerramienta(evento.target.value)} aria-label="Herramienta">
                <option value="">Cualquier herramienta</option>
                {Object.entries(HERRAMIENTAS).map(([herramienta, nombre]) => <option key={herramienta} value={herramienta}>{nombre}</option>)}
              </select>
              <select className="select" value={owasp} onChange={(evento) => setOwasp(evento.target.value)} aria-label="Categoría OWASP">
                <option value="">Cualquier categoría OWASP</option>
                {categorias.map((categoria) => <option key={categoria} value={categoria}>{categoria} {OWASP[categoria]}</option>)}
              </select>
              <select className="select" value={orden} onChange={(evento) => setOrden(evento.target.value)} aria-label="Ordenar por">
                <option value="severidad">Orden: severidad</option>
                <option value="cvss">Orden: CVSS</option>
                <option value="fecha">Orden: más recientes</option>
              </select>
              <label className="check"><input type="checkbox" checked={historico} onChange={(evento) => setHistorico(evento.target.checked)} /> Incluir evaluaciones anteriores</label>
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

// Detalle de un hallazgo: evidencia, recomendación, categoría OWASP, historial en las evaluaciones y botón para marcarlo como corregido.
export function HallazgoDetalle() {
  const { id } = useParams();
  const { data, marcarCorregido } = useData();
  const toast = useToast();
  const navegar = useNavigate();
  const [cargando, setCargando] = useState(false);
  const hallazgo = data.hallazgosPorId[id];
  useTitulo(hallazgo?.nombre_vulnerabilidad || "Hallazgo");
  if (!hallazgo) return <NoEncontrado que="El hallazgo" volver="/hallazgos" etiqueta="Ver hallazgos" />;

  const activo = hallazgo.activo;
  const corregido = hallazgo.corregido === "si";
  const puerto = puertoDeHallazgo(hallazgo);
  const codigo = owaspCodigo(hallazgo.categoria_owasp);
  // ¿En qué evaluaciones del activo aparece el mismo hallazgo?
  const historia = (activo?.evaluaciones || [])
    .filter((evaluacion) => evaluacion.estado === "completada")
    .map((evaluacion) => ({ e: evaluacion, presente: evaluacion.hallazgos.some((otro) => otro.nombre_vulnerabilidad === hallazgo.nombre_vulnerabilidad) }))
    .reverse();
  const otros = (activo?.abiertos || []).filter((otro) => otro.id !== hallazgo.id).sort((otro, segundo) => ordenSev(otro.severidad) - ordenSev(segundo.severidad)).slice(0, 4);

  // Marcar como corregido solo cambia el seguimiento. Para confirmar de verdad la corrección hay que volver a evaluar el activo (por eso lo aviso).
  const alternar = async () => {
    setCargando(true);
    try {
      await marcarCorregido(hallazgo.id, !corregido);
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
        migas={[{ texto: "Hallazgos", to: "/hallazgos" }, { texto: hallazgo.nombre_vulnerabilidad }]}
        titulo={hallazgo.nombre_vulnerabilidad}
        descripcion={
          <span className="row ph-meta">
            <SevBadge sev={hallazgo.severidad} />
            <Tag>{nombreHerramienta(hallazgo.herramienta_origen)}</Tag>
            {corregido ? <Tag tono="ok">Corregido</Tag> : <Tag>Abierto</Tag>}
            {!hallazgo.vigente && <Tag tono="warn">De una evaluación anterior</Tag>}
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
              <pre className="codeblock">{hallazgo.evidencia}</pre>
              <dl className="kv">
                <dt>Activo</dt><dd><Link to={`/activos/${activo?.id}`}>{activo?.nombre}</Link> <span className="muted">· {activo?.proyecto?.nombre}</span></dd>
                {puerto && <><dt>Puerto</dt><dd className="num">{puerto.puerto}/{puerto.protocolo}{puerto.servicio ? ` (${puerto.servicio})` : ""}</dd></>}
                <dt>Detectado</dt><dd>{fmtFechaHora(hallazgo.fecha)} <span className="muted">({hace(hallazgo.fecha)})</span></dd>
                <dt>Evaluación</dt><dd><Link to={`/evaluaciones/${hallazgo.evaluacion_id}`}>Ver evaluación completa</Link></dd>
              </dl>
            </div>
          </Panel>

          <Panel titulo="Cómo corregirlo" descripcion={SEV[hallazgo.severidad].accion}>
            <div className="prose"><p>{hallazgo.recomendacion}</p></div>
            <div className="row panel-actions-top">
              {activo && <EvaluarBoton activo={activo} texto="Volver a evaluar para confirmar" />}
            </div>
          </Panel>

          {historia.length > 1 && (
            <Panel titulo="Presencia en evaluaciones" descripcion="Si este hallazgo seguía abierto en cada evaluación del activo">
              <ul className="historia">
                {historia.map(({ e: evaluacion, presente }) => (
                  <li key={evaluacion.id} className={presente ? "si" : "no"}>
                    <span className="historia-dot" aria-hidden="true">{presente ? <Icon name="alert" size={12} /> : <Icon name="check" size={12} />}</span>
                    <Link to={`/evaluaciones/${evaluacion.id}`}>{fmtFecha(evaluacion.iniciada_en)}</Link>
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
                <span className="cvss-n">{fmtCvss(hallazgo.cvss_score)}</span>
                <span className="small muted">CVSS estimado, de 10</span>
              </div>
              <CvssMeter valor={hallazgo.cvss_score} />
              <dl className="kv">
                <dt>Severidad</dt><dd>{SEV[hallazgo.severidad].label} ({SEV[hallazgo.severidad].rango})</dd>
                <dt>OWASP Top 10</dt><dd>{hallazgo.categoria_owasp || "Sin categoría"}</dd>
              </dl>
              <Aviso>El puntaje se estima por reglas según el servicio expuesto; no es un cálculo vectorial completo de CVSS.</Aviso>
              {codigo !== "—" && <Link to="/ayuda#owasp" className="small">¿Qué es {codigo}?</Link>}
            </div>
          </Panel>

          {otros.length > 0 && (
            <Panel titulo="Otros hallazgos de este activo" flush>
              <ul className="rows">
                {otros.map((otro) => (
                  <li key={otro.id} className="clic" onClick={() => navegar(`/hallazgos/${otro.id}`)}>
                    <div className="grow">
                      <Link to={`/hallazgos/${otro.id}`} className="titulo" onClick={(evento) => evento.stopPropagation()}>{otro.nombre_vulnerabilidad}</Link>
                    </div>
                    <SevBadge sev={otro.severidad} />
                  </li>
                ))}
              </ul>
            </Panel>
          )}
          <CopiarBoton texto={`${hallazgo.nombre_vulnerabilidad} — ${hallazgo.evidencia}`} etiqueta="Copiar resumen" />
        </div>
      </div>
    </>
  );
}
