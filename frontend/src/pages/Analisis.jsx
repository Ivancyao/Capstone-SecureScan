import { useCallback, useEffect, useRef, useState } from "react";
import { Icon } from "../components/Icon.jsx";
import { Aviso, EmptyState, PageHeader, Panel, Progress, Segmented, SevBadge, useTitulo } from "../components/ui.jsx";
import { useToast } from "../context/ToastContext.jsx";
import { fmtFechaHora, fmtKb, hace } from "../lib/format.js";
import { api } from "../services/index.js";

const VEREDICTOS = {
  malicioso: { texto: "Peligroso", color: "var(--sev-critica)", fondo: "var(--sev-critica-bg)", icono: "alert" },
  sospechoso: { texto: "Sospechoso", color: "var(--sev-media)", fondo: "var(--sev-media-bg)", icono: "alert" },
  limpio: { texto: "Sin detecciones", color: "var(--ok)", fondo: "var(--ok-bg)", icono: "check" },
  sin_datos: { texto: "Sin veredicto", color: "var(--ink-3)", fondo: "var(--surface-2)", icono: "info" },
};
const NIVEL_SEV = { alto: "alta", medio: "media", bajo: "baja" };
const SEV_CAB = { alta: "alta", media: "media", baja: "baja" };

function Veredicto({ valor, grande = false }) {
  const estiloVeredicto = VEREDICTOS[valor] || VEREDICTOS.sin_datos;
  return (
    <span className={`veredicto ${grande ? "grande" : ""}`} style={{ "--v-color": estiloVeredicto.color, "--v-fondo": estiloVeredicto.fondo }}>
      <Icon name={estiloVeredicto.icono} size={grande ? 20 : 14} />
      {estiloVeredicto.texto}
    </span>
  );
}

function Resultado({ analisis }) {
  const detalle = analisis.detalle || {};
  const virustotal = detalle.virustotal;
  const cabeceras = detalle.cabeceras;
  const copiar = () => navigator.clipboard?.writeText(analisis.sha256).catch(() => {});
  return (
    <div className="analisis-resultado">
      <div className="analisis-cabecera">
        <Veredicto valor={analisis.veredicto} grande />
        <div>
          <p className="analisis-resumen">{analisis.resumen}</p>
          <p className="small muted analisis-objetivo">
            <Icon name={analisis.tipo === "url" ? "globe" : "file"} size={14} /> {analisis.objetivo}
            {analisis.tamano_bytes != null && <span> · {fmtKb(Math.max(1, Math.round(analisis.tamano_bytes / 1024)))}</span>}
          </p>
        </div>
      </div>

      {analisis.sha256 && (
        <p className="small analisis-hash">
          <span className="muted">SHA-256</span> <code>{analisis.sha256}</code>
          <button className="btn btn-quiet btn-icon btn-sm" onClick={copiar} aria-label="Copiar huella SHA-256" title="Copiar">
            <Icon name="copy" size={14} />
          </button>
        </p>
      )}

      {(detalle.avisos || []).map((aviso, indice) => (
        <Aviso key={indice} tipo="info">{aviso}</Aviso>
      ))}

      {virustotal && (
        <section className="analisis-bloque">
          <h3 className="h-section">Motores antivirus (VirusTotal)</h3>
          <div className="vt-barra" role="img" aria-label={`${virustotal.malicioso} maliciosos, ${virustotal.sospechoso} sospechosos, ${virustotal.inofensivo} inofensivos, ${virustotal.sin_deteccion} sin detección`}>
            <i style={{ flex: virustotal.malicioso, background: "var(--sev-critica)" }} />
            <i style={{ flex: virustotal.sospechoso, background: "var(--sev-media)" }} />
            <i style={{ flex: virustotal.inofensivo, background: "var(--ok)" }} />
            <i style={{ flex: virustotal.sin_deteccion, background: "var(--line-strong)" }} />
          </div>
          <p className="small">
            <strong className="num">{virustotal.malicioso + virustotal.sospechoso}</strong> de <span className="num">{virustotal.motores}</span> motores lo marcan como peligroso o sospechoso.
          </p>
          {virustotal.detecciones?.length > 0 && (
            <ul className="vt-lista">
              {virustotal.detecciones.map((deteccion) => (
                <li key={deteccion.motor}>
                  <span>{deteccion.motor}</span>
                  <code>{deteccion.resultado}</code>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {detalle.senales?.length > 0 && (
        <section className="analisis-bloque">
          <h3 className="h-section">Indicadores locales</h3>
          <ul className="senales">
            {detalle.senales.map((senal) => (
              <li key={senal.codigo}>
                <SevBadge sev={NIVEL_SEV[senal.nivel] || "informativa"} />
                <span>{senal.texto}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {cabeceras && (
        <section className="analisis-bloque">
          <h3 className="h-section">Cabeceras de seguridad del sitio</h3>
          {!cabeceras.contactado ? (
            <p className="small muted">{cabeceras.motivo}</p>
          ) : cabeceras.hallazgos.length === 0 ? (
            <p className="small">El sitio respondió (HTTP {cabeceras.codigo_http}) y trae las cabeceras de seguridad básicas.</p>
          ) : (
            <ul className="senales">
              {cabeceras.hallazgos.map((hallazgo, indice) => (
                <li key={indice}>
                  <SevBadge sev={SEV_CAB[hallazgo.severidad] || "baja"} />
                  <span>
                    <strong>{hallazgo.titulo}.</strong> {hallazgo.detalle}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}

export function Analisis() {
  useTitulo("Análisis rápido");
  const toast = useToast();
  const [modo, setModo] = useState("url");
  const [url, setUrl] = useState("");
  const [archivo, setArchivo] = useState(null);
  const [subir, setSubir] = useState(false);
  const [arrastrando, setArrastrando] = useState(false);
  const [estado, setEstado] = useState(null);
  const [historial, setHistorial] = useState([]);
  const [actual, setActual] = useState(null);
  const [enviando, setEnviando] = useState(false);
  const inputRef = useRef(null);
  const sondeo = useRef(null);

  const cargarHistorial = useCallback(async () => {
    try {
      setHistorial(await api.listarAnalisis());
    } catch (error) {
      toast.error("No se pudo cargar el historial", error.message);
    }
  }, [toast]);

  useEffect(() => {
    api.analisisEstado().then(setEstado).catch(() => setEstado({ virustotal: false, max_mb: 20 }));
    cargarHistorial();
    return () => clearTimeout(sondeo.current);
  }, [cargarHistorial]);

  const seguir = useCallback(
    (id) => {
      const paso = async () => {
        try {
          const analisis = await api.obtenerAnalisis(id);
          setActual(analisis);
          if (analisis.estado === "pendiente") {
            sondeo.current = setTimeout(paso, 1500);
          } else {
            setEnviando(false);
            cargarHistorial();
          }
        } catch (error) {
          setEnviando(false);
          toast.error("No se pudo consultar el análisis", error.message);
        }
      };
      paso();
    },
    [cargarHistorial, toast]
  );

  const analizar = async (evento) => {
    evento.preventDefault();
    clearTimeout(sondeo.current);
    setEnviando(true);
    setActual(null);
    try {
      const analisis = modo === "url" ? await api.analizarUrl(url.trim()) : await api.analizarArchivo(archivo, subir);
      setActual(analisis);
      if (analisis.estado === "pendiente") seguir(analisis.id);
      else {
        setEnviando(false);
        cargarHistorial();
      }
    } catch (error) {
      setEnviando(false);
      toast.error("No se pudo iniciar el análisis", error.message);
    }
  };

  const elegir = (archivoElegido) => {
    if (!archivoElegido) return;
    if (estado && archivoElegido.size > estado.max_mb * 1024 * 1024) {
      toast.error("Archivo demasiado grande", `El máximo es ${estado.max_mb} MB.`);
      return;
    }
    setArchivo(archivoElegido);
  };

  const eliminar = async (analisis) => {
    if (!window.confirm(`¿Eliminar el análisis de «${analisis.objetivo}»?`)) return;
    try {
      await api.eliminarAnalisis(analisis.id);
      if (actual?.id === analisis.id) setActual(null);
      cargarHistorial();
      toast.ok("Análisis eliminado");
    } catch (error) {
      toast.error("No se pudo eliminar", error.message);
    }
  };

  const listo = modo === "url" ? /^https?:\/\/\S+/i.test(url.trim()) : !!archivo;

  return (
    <>
      <PageHeader
        titulo="Análisis rápido"
        descripcion="Pega una URL o sube un archivo para saber si tiene señales de malware, phishing o mala configuración. Es distinto de una evaluación: no escanea puertos ni vulnerabilidades."
      />

      {estado && !estado.virustotal && (
        <Aviso tipo="warn">
          VirusTotal no está configurado en el servidor, así que solo verás indicadores locales (sin la opinión de los motores antivirus). El administrador puede activarlo definiendo <code>VIRUSTOTAL_API_KEY</code>.
        </Aviso>
      )}

      <div className="grid-main">
        <Panel titulo="¿Qué quieres revisar?">
          <form onSubmit={analizar} className="stack">
            <Segmented
              etiqueta="Tipo de análisis"
              valor={modo}
              onChange={(nuevoModo) => setModo(nuevoModo)}
              opciones={[
                { valor: "url", etiqueta: "URL" },
                { valor: "archivo", etiqueta: "Archivo" },
              ]}
            />

            {modo === "url" ? (
              <div className="field">
                <label htmlFor="an-url">Dirección del sitio o enlace</label>
                <input id="an-url" className="input" type="url" inputMode="url" placeholder="https://ejemplo.cl/descarga" value={url} onChange={(evento) => setUrl(evento.target.value)} autoComplete="off" />
                <span className="hint">La reputación se consulta sin tocar el sitio. Las cabeceras de seguridad solo se leen si el sitio está en una red permitida (misma regla que las evaluaciones).</span>
              </div>
            ) : (
              <>
                <div
                  className={`dropzone ${arrastrando ? "on" : ""} ${archivo ? "con-archivo" : ""}`}
                  onDragOver={(evento) => { evento.preventDefault(); setArrastrando(true); }}
                  onDragLeave={() => setArrastrando(false)}
                  onDrop={(evento) => { evento.preventDefault(); setArrastrando(false); elegir(evento.dataTransfer.files?.[0]); }}
                >
                  <Icon name={archivo ? "file" : "download"} size={26} />
                  {archivo ? (
                    <p><strong>{archivo.name}</strong><br /><span className="small muted">{fmtKb(Math.max(1, Math.round(archivo.size / 1024)))}</span></p>
                  ) : (
                    <p>Arrastra un archivo aquí<br /><span className="small muted">o elígelo desde tu equipo (máx. {estado?.max_mb ?? 20} MB)</span></p>
                  )}
                  <input ref={inputRef} id="an-archivo" type="file" className="visually-hidden" onChange={(evento) => elegir(evento.target.files?.[0])} />
                  <button type="button" className="btn btn-sm" onClick={() => inputRef.current?.click()}>{archivo ? "Cambiar archivo" : "Elegir archivo"}</button>
                </div>
                <label className="check">
                  <input type="checkbox" checked={subir} onChange={(evento) => setSubir(evento.target.checked)} />
                  <span>
                    Si VirusTotal no conoce el archivo, permitir que lo reciba para analizarlo
                    <span className="hint block">Lo que se sube pasa a ser visible para la comunidad de seguridad. No lo marques con documentos privados. Si no lo marcas, solo se consulta su huella SHA-256.</span>
                  </span>
                </label>
              </>
            )}

            <div>
              <button className="btn btn-primary" type="submit" disabled={!listo || enviando}>
                <Icon name="search" size={16} /> {enviando ? "Analizando…" : "Analizar"}
              </button>
            </div>
          </form>
        </Panel>

        <Panel titulo="Resultado">
          {enviando && actual?.estado !== "completado" && (
            <div className="stack-sm">
              <Progress indeterminado etiqueta="Analizando" />
              <p className="small muted">Consultando fuentes. Si VirusTotal debe analizar el elemento por primera vez, puede tardar hasta un minuto.</p>
            </div>
          )}
          {!enviando && !actual && <EmptyState icono="shield" titulo="Aún no hay un análisis" texto="El resultado aparece aquí en cuanto termina." />}
          {actual && actual.estado !== "pendiente" && <Resultado analisis={actual} />}
        </Panel>
      </div>

      <Panel titulo="Historial" descripcion="Solo tú ves estos análisis. Los archivos no se guardan: solo su huella y el resultado.">
        {historial.length === 0 ? (
          <EmptyState icono="clock" titulo="Sin análisis todavía" texto="Los que hagas quedarán registrados aquí." />
        ) : (
          <ul className="historial">
            {historial.map((analisis) => (
              <li key={analisis.id}>
                <button className="historial-main" onClick={() => setActual(analisis)} aria-label={`Ver análisis de ${analisis.objetivo}`}>
                  <Icon name={analisis.tipo === "url" ? "globe" : "file"} size={16} />
                  <span className="historial-obj">{analisis.objetivo}</span>
                  <Veredicto valor={analisis.veredicto || "sin_datos"} />
                  <time className="small muted" dateTime={analisis.creado_en} title={fmtFechaHora(analisis.creado_en)}>{hace(analisis.creado_en)}</time>
                </button>
                <button className="btn btn-quiet btn-icon btn-sm" onClick={() => eliminar(analisis)} aria-label={`Eliminar análisis de ${analisis.objetivo}`} title="Eliminar">
                  <Icon name="trash" size={15} />
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  );
}
