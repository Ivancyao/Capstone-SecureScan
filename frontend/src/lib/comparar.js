// Comparación entre dos evaluaciones del mismo activo.
// Un hallazgo se identifica por su nombre: "Puerto 3306/tcp abierto (mysql)" o "Falta la política de seguridad de contenido (CSP)".
import { ordenSev } from "./risk.js";

const clave = (h) => (h.nombre_vulnerabilidad || "").trim().toLowerCase();

// Si una evaluación repite un nombre, se conserva el más severo.
function indexar(evaluacion) {
  const m = new Map();
  (evaluacion?.hallazgos || []).forEach((h) => {
    const previo = m.get(clave(h));
    if (!previo || ordenSev(h.severidad) < ordenSev(previo.severidad)) m.set(clave(h), h);
  });
  return m;
}

const porSeveridad = (a, b) => ordenSev(a.severidad) - ordenSev(b.severidad) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0) || a.nombre_vulnerabilidad.localeCompare(b.nombre_vulnerabilidad);

/**
 * @param base    evaluación anterior (punto de partida)
 * @param actual  evaluación más reciente
 * @returns nuevos (solo en actual), resueltos (solo en base), persisten (en ambas, misma severidad),
 *          cambiaron (en ambas, distinta severidad: { antes, ahora, sube }) y el balance de hallazgos.
 */
export function compararEvaluaciones(base, actual) {
  const a = indexar(base);
  const b = indexar(actual);
  const nuevos = [];
  const resueltos = [];
  const persisten = [];
  const cambiaron = [];
  b.forEach((h, k) => {
    const antes = a.get(k);
    if (!antes) nuevos.push(h);
    else if (antes.severidad === h.severidad) persisten.push(h);
    else cambiaron.push({ antes, ahora: h, sube: ordenSev(h.severidad) < ordenSev(antes.severidad) });
  });
  a.forEach((h, k) => {
    if (!b.has(k)) resueltos.push(h);
  });
  nuevos.sort(porSeveridad);
  resueltos.sort(porSeveridad);
  persisten.sort(porSeveridad);
  cambiaron.sort((x, y) => porSeveridad(x.ahora, y.ahora));
  const totalAntes = a.size;
  const totalAhora = b.size;
  const empeora = nuevos.length > 0 || cambiaron.some((c) => c.sube);
  const mejora = resueltos.length > 0 || cambiaron.some((c) => !c.sube);
  return {
    nuevos,
    resueltos,
    persisten,
    cambiaron,
    totalAntes,
    totalAhora,
    balance: totalAhora - totalAntes,
    veredicto: empeora && mejora ? "mixto" : empeora ? "empeora" : mejora ? "mejora" : "igual",
  };
}

// Evaluación completada inmediatamente anterior a la dada, del mismo activo.
export function evaluacionAnterior(evaluaciones = [], actual) {
  const previas = evaluaciones
    .filter((e) => e.activo_id === actual.activo_id && e.estado === "completada" && new Date(e.iniciada_en) < new Date(actual.iniciada_en))
    .sort((x, y) => new Date(y.iniciada_en) - new Date(x.iniciada_en));
  return previas[0] || null;
}
