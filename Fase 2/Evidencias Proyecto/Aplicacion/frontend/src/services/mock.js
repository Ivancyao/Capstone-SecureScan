// API simulada en el navegador. Mantiene el mismo contrato que http.js para poder
// diseñar y grabar la demo sin backend. Los datos viven en localStorage.
import { construirSeed } from "./seed.js";
import { hallazgoDesdePuerto, hallazgoWeb } from "../lib/risk.js";
import { hostDe, uid } from "../lib/format.js";

// Modo demo: toda esta "API" vive en el navegador (localStorage) y no habla con ningún servidor. Me sirvió para diseñar las pantallas antes de tener el backend
// y para poder mostrar la app aunque no haya internet. En la defensa se usa la API real, no esto.
const KEY = "securescan-demo-v1";
const TOKEN = "securescan-token";

let baseDeDatos = cargar();

function cargar() {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed?.version === 1) return parsed;
    }
  } catch {
    /* sin almacenamiento: seguimos en memoria */
  }
  return construirSeed();
}
function guardar() {
  try {
    localStorage.setItem(KEY, JSON.stringify(baseDeDatos));
  } catch {
    /* ignorar */
  }
}
// Guarda un análisis simulado (sin VirusTotal).
function guardarAnalisis(usuario, { tipo, objetivo, tamano_bytes = null, senales, veredicto }) {
  const frases = {
    malicioso: "Peligroso: se detectó una firma de malware conocida.",
    sospechoso: "Sospechoso: algún indicador local lo señala. No lo abras ni lo compartas hasta confirmarlo.",
    sin_datos: "Sin veredicto: VirusTotal no está configurado, solo hay indicadores locales.",
  };
  const ahora = new Date().toISOString();
  const analisis = {
    id: uid(), usuario_id: usuario.id, tipo, objetivo, sha256: null, tamano_bytes, estado: "completado", veredicto, resumen: frases[veredicto],
    detalle: { virustotal: null, senales, cabeceras: null, avisos: ["Modo de ejemplo: no hay conexión con VirusTotal."] }, creado_en: ahora, finalizado_en: ahora,
  };
  (baseDeDatos.analisis = baseDeDatos.analisis || []).push(analisis);
  guardar();
  return clon(analisis);
}
// Pequeña demora para que se sienta como una llamada real.
const esperar = (milisegundos = 220) => new Promise((terminar) => setTimeout(terminar, milisegundos));
const clon = (valor) => JSON.parse(JSON.stringify(valor));
const fallo = (msg) => {
  throw new Error(msg);
};

// ---------- Sesión ----------
function usuarioActual() {
  let id = null;
  try {
    id = localStorage.getItem(TOKEN);
  } catch {
    /* ignorar */
  }
  const usuario = baseDeDatos.usuarios.find((candidato) => candidato.id === id);
  return usuario && usuario.activo !== false ? usuario : null;
}
function requerirUsuario() {
  return usuarioActual() || fallo("Sesión expirada. Vuelve a iniciar sesión.");
}
const publico = ({ password, ...usuarioSinClave }) => usuarioSinClave;

// ---------- Simulación de escaneo ----------
const esIPv4 = (host) => /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
// Versión simplificada de la regla del backend para decidir si se "escanea" un host en el modo demo.
function esPrivada(host) {
  if (host === "localhost") return true;
  if (!esIPv4(host)) return /(\.local|\.lab|\.duoc\.cl)$/i.test(host) || !host.includes(".");
  const [primerOcteto, segundoOcteto] = host.split(".").map(Number);
  return primerOcteto === 10 || primerOcteto === 127 || (primerOcteto === 172 && segundoOcteto >= 16 && segundoOcteto <= 31) || (primerOcteto === 192 && segundoOcteto === 168) || (primerOcteto === 169 && segundoOcteto === 254);
}
function perfilPara(activo) {
  if (!baseDeDatos.perfiles[activo.id]) {
    const opciones = [
      { puertos: [{ puerto: 22, servicio: "ssh", producto: "OpenSSH", version: "8.9p1" }, { puerto: 80, servicio: "http", producto: "nginx", version: "1.22" }], web: ["csp"] },
      { puertos: [{ puerto: 443, servicio: "https", producto: "Apache httpd", version: "2.4.57" }, { puerto: 3306, servicio: "mysql", producto: "MySQL", version: "8.0" }], web: ["hsts"] },
      { puertos: [{ puerto: 21, servicio: "ftp", producto: "vsftpd", version: "3.0.3" }, { puerto: 22, servicio: "ssh", producto: "OpenSSH", version: "8.4" }, { puerto: 8080, servicio: "http-proxy", producto: "Tomcat" }], web: ["cors", "cookie_httponly"] },
    ];
    let hash = 0;
    for (const caracter of activo.url_objetivo) hash = (hash * 31 + caracter.charCodeAt(0)) >>> 0;
    baseDeDatos.perfiles[activo.id] = opciones[hash % opciones.length];
  }
  return baseDeDatos.perfiles[activo.id];
}

function etapaDe(pct) {
  if (pct < 12) return "Validando el objetivo";
  if (pct < 80) return "Escaneando puertos y servicios";
  if (pct < 95) return "Clasificando el riesgo";
  return "Guardando resultados";
}

// Avanza el estado de las evaluaciones simuladas según el tiempo transcurrido.
// Simula el avance de un escaneo según el tiempo transcurrido.
function resolver(evaluacion) {
  const sim = evaluacion._sim;
  if (!sim) return evaluacion;
  const transcurrido = Date.now() - new Date(evaluacion.iniciada_en).getTime();
  if (transcurrido < 1200) return { ...evaluacion, estado: "pendiente", progreso: 0, etapa: "En cola" };
  if (transcurrido < sim.dur) {
    const pct = Math.min(99, Math.round(((transcurrido - 1200) / (sim.dur - 1200)) * 100));
    return { ...evaluacion, estado: "en_progreso", progreso: pct, etapa: etapaDe(pct) };
  }
  // Terminó: se materializa el resultado.
  const final = { ...evaluacion };
  delete final._sim;
  final.finalizada_en = new Date(new Date(evaluacion.iniciada_en).getTime() + sim.dur).toISOString();
  if (sim.error) {
    final.estado = "fallida";
    final.detalle_error = sim.error;
    final.hallazgos = [];
  } else {
    final.estado = "completada";
    final.hallazgos = [...sim.puertos.map(hallazgoDesdePuerto), ...sim.web.map(hallazgoWeb)].map((hallazgo, indice) => ({
      ...hallazgo,
      id: `${evaluacion.id}-h${indice + 1}`,
      evaluacion_id: evaluacion.id,
      corregido: "no",
    }));
  }
  const posicion = baseDeDatos.evaluaciones.findIndex((candidata) => candidata.id === evaluacion.id);
  if (posicion >= 0) baseDeDatos.evaluaciones[posicion] = final;
  guardar();
  return final;
}

// ---------- Visibilidad por rol (propiedad de proyectos, como en el backend) ----------
// Igual que en el backend real: cada usuario ve lo suyo y el admin ve todo.
function visibles(usuario) {
  const proyectos = baseDeDatos.proyectos.filter((proyecto) => usuario.rol === "admin" || proyecto.propietario_id === usuario.id);
  const ids = new Set(proyectos.map((proyecto) => proyecto.id));
  const activos = baseDeDatos.activos.filter((activo) => ids.has(activo.proyecto_id));
  const idsDeActivos = new Set(activos.map((activo) => activo.id));
  const evaluaciones = baseDeDatos.evaluaciones.filter((evaluacion) => idsDeActivos.has(evaluacion.activo_id)).map(resolver);
  const reportes = baseDeDatos.reportes.filter((reporte) => ids.has(reporte.proyecto_id));
  return { proyectos, activos, evaluaciones, reportes };
}

// Mismas funciones que http.js, así las pantallas no notan la diferencia.
export const mock = {
  modo: "demo",

  // Auth
  async login(email, password) {
    await esperar();
    const usuario = baseDeDatos.usuarios.find((candidato) => candidato.email.toLowerCase() === String(email).trim().toLowerCase());
    if (!usuario || usuario.password !== password) fallo("Correo o contraseña incorrectos.");
    if (usuario.activo === false) fallo("Esta cuenta está desactivada. Contacta a un administrador.");
    try {
      localStorage.setItem(TOKEN, usuario.id);
    } catch {
      /* ignorar */
    }
    return { access_token: usuario.id, token_type: "bearer" };
  },
  async register({ nombre, email, password }) {
    await esperar();
    if (baseDeDatos.usuarios.some((existente) => existente.email.toLowerCase() === email.trim().toLowerCase())) fallo("Ese correo ya está registrado.");
    const usuarioNuevo = { id: uid(), nombre: nombre.trim(), email: email.trim(), password, rol: "usuario", activo: true, creado_en: new Date().toISOString() };
    baseDeDatos.usuarios.push(usuarioNuevo);
    guardar();
    return publico(usuarioNuevo);
  },
  async me() {
    await esperar(80);
    return publico(requerirUsuario());
  },
  logout() {
    try {
      localStorage.removeItem(TOKEN);
    } catch {
      /* ignorar */
    }
  },
  hayToken() {
    return !!usuarioActual();
  },

  // Lectura
  async snapshot() {
    const usuario = requerirUsuario();
    const valor = visibles(usuario);
    return clon({
      ...valor,
      usuarios: usuario.rol === "admin" ? baseDeDatos.usuarios.map(publico) : [],
      config: baseDeDatos.config,
      capacidades: { usuarios: true, reportes: true, configuracion: true, corregir: true },
    });
  },

  // Escritura
  async crearProyecto(data) {
    await esperar();
    const usuario = requerirUsuario();
    const proyecto = { id: uid(), nombre: data.nombre.trim(), descripcion: (data.descripcion || "").trim() || null, propietario_id: usuario.id, creado_en: new Date().toISOString() };
    baseDeDatos.proyectos.unshift(proyecto);
    guardar();
    return clon(proyecto);
  },
  async crearActivo(proyectoId, data) {
    await esperar();
    const usuario = requerirUsuario();
    const proyecto = baseDeDatos.proyectos.find((candidato) => candidato.id === proyectoId && (usuario.rol === "admin" || candidato.propietario_id === usuario.id));
    if (!proyecto) fallo("Proyecto no encontrado");
    const activoNuevo = { id: uid(), proyecto_id: proyectoId, nombre: data.nombre.trim(), url_objetivo: data.url_objetivo.trim(), descripcion: (data.descripcion || "").trim() || null, creado_en: new Date().toISOString() };
    baseDeDatos.activos.push(activoNuevo);
    guardar();
    return clon(activoNuevo);
  },
  async iniciarEvaluacion(activoId) {
    await esperar();
    const usuario = requerirUsuario();
    const activo = visibles(usuario).activos.find((candidato) => candidato.id === activoId);
    if (!activo) fallo("Activo no encontrado");
    const enCurso = visibles(usuario).evaluaciones.some((evaluacion) => evaluacion.activo_id === activoId && (evaluacion.estado === "pendiente" || evaluacion.estado === "en_progreso"));
    if (enCurso) fallo("Ya hay una evaluación en curso para este activo.");
    const host = hostDe(activo.url_objetivo);
    const perfil = perfilPara(activo);
    const sim = { dur: 11000, puertos: perfil.puertos, web: baseDeDatos.config.motores.zap.activo ? perfil.web : [] };
    if (!baseDeDatos.config.alcance.permitir_publicas && !esPrivada(host)) {
      sim.dur = 4500;
      sim.error = `Objetivo bloqueado: ${host} corresponde a una dirección pública. SecureScan solo evalúa redes privadas o loopback (ALLOW_PUBLIC_SCANS=false).`;
    }
    const evaluacion = { id: uid(), activo_id: activoId, estado: "pendiente", iniciada_en: new Date().toISOString(), finalizada_en: null, detalle_error: null, hallazgos: [], _sim: sim };
    baseDeDatos.evaluaciones.push(evaluacion);
    guardar();
    return clon(resolver(evaluacion));
  },
  async cancelarEvaluacion(id) {
    await esperar(150);
    const usuario = requerirUsuario();
    const bruta = visibles(usuario).evaluaciones.find((candidata) => candidata.id === id);
    if (!bruta) fallo("Evaluación no encontrada");
    const actual = resolver(bruta);
    if (actual.estado !== "pendiente" && actual.estado !== "en_progreso") fallo("La evaluación ya terminó; no hay nada que cancelar.");
    delete bruta._sim;
    Object.assign(bruta, { estado: "fallida", etapa: "Cancelada", detalle_error: "Cancelada por el usuario.", finalizada_en: new Date().toISOString(), hallazgos: [] });
    guardar();
    return clon(bruta);
  },
  async eliminarEvaluacion(id) {
    await esperar(150);
    const usuario = requerirUsuario();
    const bruta = visibles(usuario).evaluaciones.find((candidata) => candidata.id === id);
    if (!bruta) fallo("Evaluación no encontrada");
    const actual = resolver(bruta);
    if (actual.estado === "pendiente" || actual.estado === "en_progreso") fallo("La evaluación está en curso: cancélala antes de eliminarla.");
    baseDeDatos.evaluaciones = baseDeDatos.evaluaciones.filter((otra) => otra.id !== id);
    guardar();
  },
  // ---------- Análisis de URL / archivo (simulado: solo indicadores locales, sin VirusTotal) ----------
  async analisisEstado() {
    requerirUsuario();
    return { virustotal: false, max_mb: 20 };
  },
  async listarAnalisis() {
    await esperar(120);
    const usuario = requerirUsuario();
    return clon((baseDeDatos.analisis || []).filter((analisis) => analisis.usuario_id === usuario.id).sort((analisis, segundo) => segundo.creado_en.localeCompare(analisis.creado_en)));
  },
  async obtenerAnalisis(id) {
    const usuario = requerirUsuario();
    const analisis = (baseDeDatos.analisis || []).find((candidato) => candidato.id === id && candidato.usuario_id === usuario.id);
    return analisis ? clon(analisis) : fallo("Análisis no encontrado");
  },
  async analizarUrl(url) {
    await esperar(500);
    const usuario = requerirUsuario();
    if (!/^https?:\/\//i.test(url)) fallo("La URL debe empezar con http:// o https://");
    const senales = [];
    if (/^http:/i.test(url)) senales.push({ codigo: "sin_https", nivel: "bajo", texto: "No usa HTTPS: el tráfico viaja sin cifrar." });
    if (/\/\/\d{1,3}(\.\d{1,3}){3}/.test(url)) senales.push({ codigo: "ip_literal", nivel: "medio", texto: "La dirección es una IP en vez de un nombre: es habitual en sitios temporales o de phishing." });
    if (/\/\/(bit\.ly|tinyurl\.com|t\.co)\//i.test(url)) senales.push({ codigo: "acortador", nivel: "medio", texto: "Es un acortador de enlaces: oculta el destino real." });
    const veredicto = senales.some((senal) => senal.nivel !== "bajo") ? "sospechoso" : "sin_datos";
    return guardarAnalisis(usuario, { tipo: "url", objetivo: url, senales, veredicto });
  },
  async analizarArchivo(archivo) {
    await esperar(600);
    const usuario = requerirUsuario();
    const texto = await archivo.slice(0, 1024).text().catch(() => "");
    const senales = [];
    if (texto.includes("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) senales.push({ codigo: "eicar", nivel: "alto", texto: "Contiene la firma de prueba EICAR: los antivirus la detectan a propósito. Es inofensiva, pero confirma que el análisis funciona.", concluyente: true });
    if (/\.(pdf|docx?|xlsx?|jpe?g|png)\.(exe|scr|bat|cmd|js|vbs)$/i.test(archivo.name)) senales.push({ codigo: "doble_extension", nivel: "alto", texto: "Doble extensión: un ejecutable disfrazado de documento es una táctica común de malware." });
    const veredicto = senales.some((senal) => senal.concluyente) ? "malicioso" : senales.length ? "sospechoso" : "sin_datos";
    return guardarAnalisis(usuario, { tipo: "archivo", objetivo: archivo.name, tamano_bytes: archivo.size, senales, veredicto });
  },
  async eliminarAnalisis(id) {
    await esperar(100);
    const usuario = requerirUsuario();
    baseDeDatos.analisis = (baseDeDatos.analisis || []).filter((analisis) => !(analisis.id === id && analisis.usuario_id === usuario.id));
    guardar();
  },
  async marcarCorregido(hallazgoId, corregido) {
    await esperar(120);
    requerirUsuario();
    for (const evaluacion of baseDeDatos.evaluaciones) {
      const hallazgo = evaluacion.hallazgos.find((candidato) => candidato.id === hallazgoId);
      if (hallazgo) {
        hallazgo.corregido = corregido ? "si" : "no";
        guardar();
        return clon(hallazgo);
      }
    }
    return fallo("Hallazgo no encontrado");
  },
  async crearReporte({ proyecto_id, titulo, evaluacion_ids }) {
    await esperar(700);
    const usuario = requerirUsuario();
    const proyecto = baseDeDatos.proyectos.find((candidato) => candidato.id === proyecto_id);
    if (!proyecto) fallo("Proyecto no encontrado");
    const slug = proyecto.nombre.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    const reporte = { id: uid(), proyecto_id, titulo: titulo || `Informe de seguridad — ${proyecto.nombre}`, nombre_archivo: `informe-${slug}.pdf`, generado_en: new Date().toISOString(), generado_por: usuario.nombre, evaluacion_ids, tamano_kb: 80 + evaluacion_ids.length * 34 };
    baseDeDatos.reportes.unshift(reporte);
    guardar();
    return clon(reporte);
  },
  async eliminarReporte(id) {
    await esperar(120);
    baseDeDatos.reportes = baseDeDatos.reportes.filter((reporte) => reporte.id !== id);
    guardar();
  },
  async cambiarRol(usuarioId, rol) {
    await esperar(150);
    const usuario = requerirUsuario();
    if (usuario.rol !== "admin") fallo("Solo un administrador puede cambiar roles.");
    const objetivo = baseDeDatos.usuarios.find((candidato) => candidato.id === usuarioId);
    if (!objetivo) fallo("Usuario no encontrado");
    if (objetivo.id === usuario.id) fallo("No puedes cambiar tu propio rol.");
    objetivo.rol = rol;
    guardar();
  },
  async alternarUsuario(usuarioId) {
    await esperar(150);
    const usuario = requerirUsuario();
    if (usuario.rol !== "admin") fallo("Solo un administrador puede desactivar cuentas.");
    const objetivo = baseDeDatos.usuarios.find((candidato) => candidato.id === usuarioId);
    if (!objetivo) fallo("Usuario no encontrado");
    if (objetivo.id === usuario.id) fallo("No puedes desactivar tu propia cuenta.");
    objetivo.activo = objetivo.activo === false;
    guardar();
  },
  async invitarUsuario({ nombre, email, rol }) {
    await esperar();
    const usuario = requerirUsuario();
    if (usuario.rol !== "admin") fallo("Solo un administrador puede crear cuentas.");
    if (baseDeDatos.usuarios.some((existente) => existente.email.toLowerCase() === email.trim().toLowerCase())) fallo("Ese correo ya está registrado.");
    const nuevo = { id: uid(), nombre: nombre.trim(), email: email.trim(), password: "Demo1234!", rol, activo: true, creado_en: new Date().toISOString() };
    baseDeDatos.usuarios.push(nuevo);
    guardar();
    return { ...publico(nuevo), password_temporal: "Demo1234!" };
  },
  async actualizarPerfil({ nombre }) {
    await esperar();
    const usuario = requerirUsuario();
    usuario.nombre = nombre.trim();
    guardar();
    return publico(usuario);
  },
  async cambiarPassword({ actual, nueva }) {
    await esperar();
    const usuario = requerirUsuario();
    if (usuario.password !== actual) fallo("La contraseña actual no coincide.");
    usuario.password = nueva;
    guardar();
  },
  async guardarConfig(config) {
    await esperar();
    const usuario = requerirUsuario();
    if (usuario.rol !== "admin") fallo("Solo un administrador puede cambiar la configuración.");
    baseDeDatos.config = clon(config);
    guardar();
    return clon(baseDeDatos.config);
  },
  async restablecer() {
    baseDeDatos = construirSeed();
    guardar();
  },
};
