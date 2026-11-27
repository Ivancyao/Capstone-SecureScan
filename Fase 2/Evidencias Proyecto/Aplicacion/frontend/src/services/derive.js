// Cálculos derivados del estado crudo. Con la API real, los totales por severidad, por categoría OWASP y por
// semana vienen de GET /metricas (consultas GROUP BY en la base). Aquí quedan como respaldo para el modo de ejemplo.
import { contar, maxSeveridad, ordenSev, SEVERIDADES, owaspCodigo, OWASP } from "../lib/risk.js";

// Una evaluación está "en curso" si sigue pendiente o en progreso.
const enCurso = (evaluacion) => evaluacion.estado === "pendiente" || evaluacion.estado === "en_progreso";
const porFechaDesc = (primera, segunda) => new Date(segunda.iniciada_en) - new Date(primera.iniciada_en);

// Devuelve el lunes de la semana de una fecha (para agrupar la tendencia por semana).
function inicioSemana(fecha) {
  const inicio = new Date(fecha);
  inicio.setHours(0, 0, 0, 0);
  const dia = (inicio.getDay() + 6) % 7; // lunes = 0
  inicio.setDate(inicio.getDate() - dia);
  return inicio;
}

// Con la API real, estas cifras llegan ya agregadas desde la base de datos (GET /metricas).
// Con el backend real, los totales ya vienen calculados en la base de datos; acá solo los dejo en el formato que usan los gráficos.
function desdeMetricas(metricas) {
  const conteoGlobal = { ...metricas.por_severidad, total: Object.values(metricas.por_severidad).reduce((suma, valor) => suma + valor, 0) };
  const porCodigo = {};
  metricas.por_owasp.forEach(({ categoria, n: cantidad }) => {
    const codigo = owaspCodigo(categoria);
    porCodigo[codigo] = (porCodigo[codigo] || 0) + cantidad;
  });
  const porOwasp = Object.entries(porCodigo)
    .map(([codigo, cantidad]) => ({ codigo, nombre: OWASP[codigo] || codigo, n: cantidad }))
    .sort((primero, segundo) => segundo.n - primero.n);
  const semanas = metricas.por_semana.map((semana) => {
    const [anio, mes, dia] = semana.inicio.split("-").map(Number);
    return { ...semana, inicio: new Date(anio, mes - 1, dia) };
  });
  return { conteoGlobal, porOwasp, semanas };
}

// Esta función arma todos los datos "cocinados" que usan las pantallas a partir de lo que entrega el backend (proyectos, activos, evaluaciones...).
// La idea es calcular acá una sola vez (conteos, última evaluación, hallazgos vigentes) y que cada pantalla solo los muestre.
export function derive(snap) {
  if (!snap) return null;
  const proyectosPorId = Object.fromEntries(snap.proyectos.map((proyecto) => [proyecto.id, proyecto]));
  const activosPorId = Object.fromEntries(snap.activos.map((activo) => [activo.id, activo]));

  const evaluaciones = [...snap.evaluaciones]
    .sort(porFechaDesc)
    .map((evaluacion) => {
      const activo = activosPorId[evaluacion.activo_id];
      return {
        ...evaluacion,
        // El servidor guarda una cancelación como "fallida" con la etapa "Cancelada"; aquí se distingue
        estado: evaluacion.etapa === "Cancelada" ? "cancelada" : evaluacion.estado,
        activo,
        proyecto: activo ? proyectosPorId[activo.proyecto_id] : null,
        conteo: contar(evaluacion.hallazgos),
        maxSev: maxSeveridad(evaluacion.hallazgos),
        enCurso: enCurso(evaluacion),
      };
    });

  // Por cada activo calculo su última evaluación, la última completada, los hallazgos abiertos y la serie para el gráfico pequeño.
  const activos = snap.activos.map((activo) => {
    const evaluacionesDelActivo = evaluaciones.filter((evaluacion) => evaluacion.activo_id === activo.id);
    const ultima = evaluacionesDelActivo[0] || null;
    const ultimaOk = evaluacionesDelActivo.find((evaluacion) => evaluacion.estado === "completada") || null;
    const abiertos = ultimaOk ? ultimaOk.hallazgos.filter((hallazgo) => hallazgo.corregido !== "si") : [];
    const serie = [...evaluacionesDelActivo].filter((evaluacion) => evaluacion.estado === "completada").reverse().map((evaluacion) => evaluacion.hallazgos.filter((hallazgo) => hallazgo.corregido !== "si").length);
    return {
      ...activo,
      proyecto: proyectosPorId[activo.proyecto_id] || null,
      evaluaciones: evaluacionesDelActivo,
      ultima,
      ultimaOk,
      abiertos,
      conteo: contar(abiertos),
      maxSev: maxSeveridad(abiertos),
      serie,
      enCurso: ultima ? enCurso(ultima) : false,
    };
  });
  const activoPorId = Object.fromEntries(activos.map((activo) => [activo.id, activo]));

  // Importante: un hallazgo es "vigente" solo si pertenece a la ÚLTIMA evaluación completada de su activo. Los anteriores son historial y no cuentan como riesgo actual.
  // Hallazgos aplanados. "vigente" = pertenece a la última evaluación completada de su activo.
  const hallazgos = [];
  evaluaciones.forEach((evaluacion) => {
    const activo = activoPorId[evaluacion.activo_id];
    const vigente = activo?.ultimaOk?.id === evaluacion.id;
    evaluacion.hallazgos.forEach((hallazgo) => {
      hallazgos.push({
        ...hallazgo,
        evaluacion_id: evaluacion.id,
        fecha: evaluacion.iniciada_en,
        activo,
        proyecto: evaluacion.proyecto,
        vigente,
      });
    });
  });
  const hallazgosPorId = Object.fromEntries(hallazgos.map((hallazgo) => [hallazgo.id, hallazgo]));

  const proyectos = snap.proyectos.map((proyecto) => {
    const activosDelProyecto = activos.filter((activo) => activo.proyecto_id === proyecto.id);
    const abiertos = activosDelProyecto.flatMap((activo) => activo.abiertos);
    const evaluacionesDelProyecto = evaluaciones.filter((evaluacion) => evaluacion.proyecto?.id === proyecto.id);
    return {
      ...proyecto,
      activos: activosDelProyecto,
      evaluaciones: evaluacionesDelProyecto,
      reportes: snap.reportes.filter((reporte) => reporte.proyecto_id === proyecto.id),
      conteo: contar(abiertos),
      maxSev: maxSeveridad(abiertos),
      ultima: evaluacionesDelProyecto[0] || null,
      enCurso: evaluacionesDelProyecto.some((evaluacion) => evaluacion.enCurso),
    };
  });

  // "Abiertos" = vigentes y no marcados como corregidos. Es el número de riesgo que se muestra en el panel.
  const abiertos = hallazgos.filter((hallazgo) => hallazgo.vigente && hallazgo.corregido !== "si");
  const corregidos = hallazgos.filter((hallazgo) => hallazgo.vigente && hallazgo.corregido === "si");
  const conteoGlobal = contar(abiertos);

  // GROUP BY categoría OWASP
  const owasp = {};
  abiertos.forEach((hallazgo) => {
    const codigo = owaspCodigo(hallazgo.categoria_owasp);
    owasp[codigo] = (owasp[codigo] || 0) + 1;
  });
  const porOwasp = Object.entries(owasp)
    .map(([codigo, cantidad]) => ({ codigo, nombre: OWASP[codigo] || codigo, n: cantidad }))
    .sort((primero, segundo) => segundo.n - primero.n);

  // Hallazgos detectados por semana (últimas 8), apilados por severidad
  const semanas = [];
  const base = inicioSemana(new Date());
  for (let i = 7; i >= 0; i--) {
    const fecha = new Date(base);
    fecha.setDate(fecha.getDate() - i * 7);
    semanas.push({ inicio: fecha, ...Object.fromEntries(SEVERIDADES.map((severidad) => [severidad, 0])), total: 0 });
  }
  evaluaciones.forEach((evaluacion) => {
    if (evaluacion.estado !== "completada") return;
    const inicioDeSemana = inicioSemana(evaluacion.iniciada_en).getTime();
    const semanaDelEstado = semanas.find((semana) => semana.inicio.getTime() === inicioDeSemana);
    if (!semanaDelEstado) return;
    evaluacion.hallazgos.forEach((hallazgo) => {
      semanaDelEstado[hallazgo.severidad] += 1;
      semanaDelEstado.total += 1;
    });
  });

  // Los activos que más atención necesitan: primero los de mayor severidad y, si empatan, los que tienen más hallazgos abiertos.
  const activosAtencion = activos
    .filter((activo) => activo.abiertos.length > 0)
    .sort((primero, segundo) => ordenSev(primero.maxSev) - ordenSev(segundo.maxSev) || segundo.abiertos.length - primero.abiertos.length);

  // Si el backend entregó métricas agregadas, uso esas; si no (modo de ejemplo), uso mi cálculo local.
  const agregadas = snap.metricas ? desdeMetricas(snap.metricas) : null;

  return {
    proyectos,
    proyectosPorId: Object.fromEntries(proyectos.map((proyecto) => [proyecto.id, proyecto])),
    activos,
    activoPorId,
    evaluaciones,
    evaluacionPorId: Object.fromEntries(evaluaciones.map((evaluacion) => [evaluacion.id, evaluacion])),
    hallazgos,
    hallazgosPorId,
    abiertos,
    corregidos,
    conteoGlobal: agregadas?.conteoGlobal ?? conteoGlobal,
    porOwasp: agregadas?.porOwasp ?? porOwasp,
    semanas: agregadas?.semanas ?? semanas,
    activosAtencion,
    enCurso: evaluaciones.filter((evaluacion) => evaluacion.enCurso),
    reportes: snap.reportes,
    usuarios: snap.usuarios,
    config: snap.config,
    capacidades: snap.capacidades,
  };
}
