// Comparación entre dos evaluaciones del mismo activo.
// Un hallazgo se identifica por su nombre: "Puerto 3306/tcp abierto (mysql)" o "Falta la política de seguridad de contenido (CSP)".
import { ordenSev } from "./risk.js";

// Dos hallazgos se consideran "el mismo" si tienen el mismo nombre (sin importar mayúsculas).
const clave = (hallazgo) => (hallazgo.nombre_vulnerabilidad || "").trim().toLowerCase();

// Si una evaluación repite un nombre, se conserva el más severo.
function indexar(evaluacion) {
  const porClave = new Map();
  (evaluacion?.hallazgos || []).forEach((hallazgo) => {
    const previo = porClave.get(clave(hallazgo));
    if (!previo || ordenSev(hallazgo.severidad) < ordenSev(previo.severidad)) porClave.set(clave(hallazgo), hallazgo);
  });
  return porClave;
}

const porSeveridad = (primero, segundo) => ordenSev(primero.severidad) - ordenSev(segundo.severidad) || (segundo.cvss_score ?? 0) - (primero.cvss_score ?? 0) || primero.nombre_vulnerabilidad.localeCompare(segundo.nombre_vulnerabilidad);

/**
 * @param base    evaluación anterior (punto de partida)
 * @param actual  evaluación más reciente
 * @returns nuevos (solo en actual), resueltos (solo en base), persisten (en ambas, misma severidad),
 *          cambiaron (en ambas, distinta severidad: { antes, ahora, sube }) y el balance de hallazgos.
 */
// Compara dos evaluaciones del mismo activo y separa los hallazgos en: nuevos, resueltos, que persisten y que cambiaron de severidad.
// El veredicto final es "mejora", "empeora", "mixto" o "igual".
export function compararEvaluaciones(base, actual) {
  const porClaveBase = indexar(base);
  const porClaveActual = indexar(actual);
  const nuevos = [];
  const resueltos = [];
  const persisten = [];
  const cambiaron = [];
  porClaveActual.forEach((hallazgo, claveHallazgo) => {
    const antes = porClaveBase.get(claveHallazgo);
    if (!antes) nuevos.push(hallazgo);
    else if (antes.severidad === hallazgo.severidad) persisten.push(hallazgo);
    else cambiaron.push({ antes, ahora: hallazgo, sube: ordenSev(hallazgo.severidad) < ordenSev(antes.severidad) });
  });
  porClaveBase.forEach((hallazgo, claveHallazgo) => {
    if (!porClaveActual.has(claveHallazgo)) resueltos.push(hallazgo);
  });
  nuevos.sort(porSeveridad);
  resueltos.sort(porSeveridad);
  persisten.sort(porSeveridad);
  cambiaron.sort((primero, segundo) => porSeveridad(primero.ahora, segundo.ahora));
  const totalAntes = porClaveBase.size;
  const totalAhora = porClaveActual.size;
  const empeora = nuevos.length > 0 || cambiaron.some((cambio) => cambio.sube);
  const mejora = resueltos.length > 0 || cambiaron.some((cambio) => !cambio.sube);
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
// Busca la evaluación completada inmediatamente anterior, que es con la que se compara por defecto.
export function evaluacionAnterior(evaluaciones = [], actual) {
  const previas = evaluaciones
    .filter((evaluacion) => evaluacion.activo_id === actual.activo_id && evaluacion.estado === "completada" && new Date(evaluacion.iniciada_en) < new Date(actual.iniciada_en))
    .sort((primero, segundo) => new Date(segundo.iniciada_en) - new Date(primero.iniciada_en));
  return previas[0] || null;
}
