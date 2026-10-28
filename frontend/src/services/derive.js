// Cálculos derivados del estado crudo. Con la API real, los totales por severidad, por categoría OWASP y por
// semana vienen de GET /metricas (consultas GROUP BY en la base). Aquí quedan como respaldo para el modo de ejemplo.
import { contar, maxSeveridad, ordenSev, SEVERIDADES, owaspCodigo, OWASP } from "../lib/risk.js";

const enCurso = (e) => e.estado === "pendiente" || e.estado === "en_progreso";
const porFechaDesc = (a, b) => new Date(b.iniciada_en) - new Date(a.iniciada_en);

function inicioSemana(fecha) {
  const d = new Date(fecha);
  d.setHours(0, 0, 0, 0);
  const dia = (d.getDay() + 6) % 7; // lunes = 0
  d.setDate(d.getDate() - dia);
  return d;
}

// Con la API real, estas cifras llegan ya agregadas desde la base de datos (GET /metricas).
function desdeMetricas(m) {
  const conteoGlobal = { ...m.por_severidad, total: Object.values(m.por_severidad).reduce((a, b) => a + b, 0) };
  const porCodigo = {};
  m.por_owasp.forEach(({ categoria, n }) => {
    const cod = owaspCodigo(categoria);
    porCodigo[cod] = (porCodigo[cod] || 0) + n;
  });
  const porOwasp = Object.entries(porCodigo)
    .map(([codigo, n]) => ({ codigo, nombre: OWASP[codigo] || codigo, n }))
    .sort((a, b) => b.n - a.n);
  const semanas = m.por_semana.map((s) => {
    const [y, mes, d] = s.inicio.split("-").map(Number);
    return { ...s, inicio: new Date(y, mes - 1, d) };
  });
  return { conteoGlobal, porOwasp, semanas };
}

export function derive(snap) {
  if (!snap) return null;
  const proyectosPorId = Object.fromEntries(snap.proyectos.map((p) => [p.id, p]));
  const activosPorId = Object.fromEntries(snap.activos.map((a) => [a.id, a]));

  const evaluaciones = [...snap.evaluaciones]
    .sort(porFechaDesc)
    .map((e) => {
      const activo = activosPorId[e.activo_id];
      return {
        ...e,
        activo,
        proyecto: activo ? proyectosPorId[activo.proyecto_id] : null,
        conteo: contar(e.hallazgos),
        maxSev: maxSeveridad(e.hallazgos),
        enCurso: enCurso(e),
      };
    });

  const activos = snap.activos.map((a) => {
    const evs = evaluaciones.filter((e) => e.activo_id === a.id);
    const ultima = evs[0] || null;
    const ultimaOk = evs.find((e) => e.estado === "completada") || null;
    const abiertos = ultimaOk ? ultimaOk.hallazgos.filter((h) => h.corregido !== "si") : [];
    const serie = [...evs].filter((e) => e.estado === "completada").reverse().map((e) => e.hallazgos.filter((h) => h.corregido !== "si").length);
    return {
      ...a,
      proyecto: proyectosPorId[a.proyecto_id] || null,
      evaluaciones: evs,
      ultima,
      ultimaOk,
      abiertos,
      conteo: contar(abiertos),
      maxSev: maxSeveridad(abiertos),
      serie,
      enCurso: ultima ? enCurso(ultima) : false,
    };
  });
  const activoPorId = Object.fromEntries(activos.map((a) => [a.id, a]));

  // Hallazgos aplanados. "vigente" = pertenece a la última evaluación completada de su activo.
  const hallazgos = [];
  evaluaciones.forEach((e) => {
    const a = activoPorId[e.activo_id];
    const vigente = a?.ultimaOk?.id === e.id;
    e.hallazgos.forEach((h) => {
      hallazgos.push({
        ...h,
        evaluacion_id: e.id,
        fecha: e.iniciada_en,
        activo: a,
        proyecto: e.proyecto,
        vigente,
      });
    });
  });
  const hallazgosPorId = Object.fromEntries(hallazgos.map((h) => [h.id, h]));

  const proyectos = snap.proyectos.map((p) => {
    const acts = activos.filter((a) => a.proyecto_id === p.id);
    const abiertos = acts.flatMap((a) => a.abiertos);
    const evs = evaluaciones.filter((e) => e.proyecto?.id === p.id);
    return {
      ...p,
      activos: acts,
      evaluaciones: evs,
      reportes: snap.reportes.filter((r) => r.proyecto_id === p.id),
      conteo: contar(abiertos),
      maxSev: maxSeveridad(abiertos),
      ultima: evs[0] || null,
      enCurso: evs.some((e) => e.enCurso),
    };
  });

  const abiertos = hallazgos.filter((h) => h.vigente && h.corregido !== "si");
  const corregidos = hallazgos.filter((h) => h.vigente && h.corregido === "si");
  const conteoGlobal = contar(abiertos);

  // GROUP BY categoría OWASP
  const owasp = {};
  abiertos.forEach((h) => {
    const cod = owaspCodigo(h.categoria_owasp);
    owasp[cod] = (owasp[cod] || 0) + 1;
  });
  const porOwasp = Object.entries(owasp)
    .map(([codigo, n]) => ({ codigo, nombre: OWASP[codigo] || codigo, n }))
    .sort((a, b) => b.n - a.n);

  // Hallazgos detectados por semana (últimas 8), apilados por severidad
  const semanas = [];
  const base = inicioSemana(new Date());
  for (let i = 7; i >= 0; i--) {
    const d = new Date(base);
    d.setDate(d.getDate() - i * 7);
    semanas.push({ inicio: d, ...Object.fromEntries(SEVERIDADES.map((s) => [s, 0])), total: 0 });
  }
  evaluaciones.forEach((e) => {
    if (e.estado !== "completada") return;
    const ini = inicioSemana(e.iniciada_en).getTime();
    const sem = semanas.find((s) => s.inicio.getTime() === ini);
    if (!sem) return;
    e.hallazgos.forEach((h) => {
      sem[h.severidad] += 1;
      sem.total += 1;
    });
  });

  const activosAtencion = activos
    .filter((a) => a.abiertos.length > 0)
    .sort((a, b) => ordenSev(a.maxSev) - ordenSev(b.maxSev) || b.abiertos.length - a.abiertos.length);

  const agregadas = snap.metricas ? desdeMetricas(snap.metricas) : null;

  return {
    proyectos,
    proyectosPorId: Object.fromEntries(proyectos.map((p) => [p.id, p])),
    activos,
    activoPorId,
    evaluaciones,
    evaluacionPorId: Object.fromEntries(evaluaciones.map((e) => [e.id, e])),
    hallazgos,
    hallazgosPorId,
    abiertos,
    corregidos,
    conteoGlobal: agregadas?.conteoGlobal ?? conteoGlobal,
    porOwasp: agregadas?.porOwasp ?? porOwasp,
    semanas: agregadas?.semanas ?? semanas,
    activosAtencion,
    enCurso: evaluaciones.filter((e) => e.enCurso),
    reportes: snap.reportes,
    usuarios: snap.usuarios,
    config: snap.config,
    capacidades: snap.capacidades,
  };
}
