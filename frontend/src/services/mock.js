// API simulada en el navegador. Mantiene el mismo contrato que http.js para poder
// diseñar y grabar la demo sin backend. Los datos viven en localStorage.
import { construirSeed } from "./seed.js";
import { hallazgoDesdePuerto, hallazgoWeb } from "../lib/risk.js";
import { hostDe, uid } from "../lib/format.js";

const KEY = "securescan-demo-v1";
const TOKEN = "securescan-token";

let db = cargar();

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
    localStorage.setItem(KEY, JSON.stringify(db));
  } catch {
    /* ignorar */
  }
}
const esperar = (ms = 220) => new Promise((r) => setTimeout(r, ms));
const clon = (x) => JSON.parse(JSON.stringify(x));
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
  const u = db.usuarios.find((x) => x.id === id);
  return u && u.activo !== false ? u : null;
}
function requerirUsuario() {
  return usuarioActual() || fallo("Sesión expirada. Vuelve a iniciar sesión.");
}
const publico = ({ password, ...u }) => u;

// ---------- Simulación de escaneo ----------
const esIPv4 = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
function esPrivada(h) {
  if (h === "localhost") return true;
  if (!esIPv4(h)) return /(\.local|\.lab|\.duoc\.cl)$/i.test(h) || !h.includes(".");
  const [a, b] = h.split(".").map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}
function perfilPara(activo) {
  if (!db.perfiles[activo.id]) {
    const opciones = [
      { puertos: [{ puerto: 22, servicio: "ssh", producto: "OpenSSH", version: "8.9p1" }, { puerto: 80, servicio: "http", producto: "nginx", version: "1.22" }], web: ["csp"] },
      { puertos: [{ puerto: 443, servicio: "https", producto: "Apache httpd", version: "2.4.57" }, { puerto: 3306, servicio: "mysql", producto: "MySQL", version: "8.0" }], web: ["hsts"] },
      { puertos: [{ puerto: 21, servicio: "ftp", producto: "vsftpd", version: "3.0.3" }, { puerto: 22, servicio: "ssh", producto: "OpenSSH", version: "8.4" }, { puerto: 8080, servicio: "http-proxy", producto: "Tomcat" }], web: ["cors", "cookie_httponly"] },
    ];
    let h = 0;
    for (const c of activo.url_objetivo) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    db.perfiles[activo.id] = opciones[h % opciones.length];
  }
  return db.perfiles[activo.id];
}

function etapaDe(pct) {
  if (pct < 12) return "Validando el objetivo";
  if (pct < 80) return "Escaneando puertos y servicios";
  if (pct < 95) return "Clasificando el riesgo";
  return "Guardando resultados";
}

// Avanza el estado de las evaluaciones simuladas según el tiempo transcurrido.
function resolver(ev) {
  const sim = ev._sim;
  if (!sim) return ev;
  const t = Date.now() - new Date(ev.iniciada_en).getTime();
  if (t < 1200) return { ...ev, estado: "pendiente", progreso: 0, etapa: "En cola" };
  if (t < sim.dur) {
    const pct = Math.min(99, Math.round(((t - 1200) / (sim.dur - 1200)) * 100));
    return { ...ev, estado: "en_progreso", progreso: pct, etapa: etapaDe(pct) };
  }
  // Terminó: se materializa el resultado.
  const final = { ...ev };
  delete final._sim;
  final.finalizada_en = new Date(new Date(ev.iniciada_en).getTime() + sim.dur).toISOString();
  if (sim.error) {
    final.estado = "fallida";
    final.detalle_error = sim.error;
    final.hallazgos = [];
  } else {
    final.estado = "completada";
    final.hallazgos = [...sim.puertos.map(hallazgoDesdePuerto), ...sim.web.map(hallazgoWeb)].map((h, i) => ({
      ...h,
      id: `${ev.id}-h${i + 1}`,
      evaluacion_id: ev.id,
      corregido: "no",
    }));
  }
  const i = db.evaluaciones.findIndex((x) => x.id === ev.id);
  if (i >= 0) db.evaluaciones[i] = final;
  guardar();
  return final;
}

// ---------- Visibilidad por rol (propiedad de proyectos, como en el backend) ----------
function visibles(u) {
  const proyectos = db.proyectos.filter((p) => u.rol === "admin" || p.propietario_id === u.id);
  const ids = new Set(proyectos.map((p) => p.id));
  const activos = db.activos.filter((a) => ids.has(a.proyecto_id));
  const aids = new Set(activos.map((a) => a.id));
  const evaluaciones = db.evaluaciones.filter((e) => aids.has(e.activo_id)).map(resolver);
  const reportes = db.reportes.filter((r) => ids.has(r.proyecto_id));
  return { proyectos, activos, evaluaciones, reportes };
}

export const mock = {
  modo: "demo",

  // Auth
  async login(email, password) {
    await esperar();
    const u = db.usuarios.find((x) => x.email.toLowerCase() === String(email).trim().toLowerCase());
    if (!u || u.password !== password) fallo("Correo o contraseña incorrectos.");
    if (u.activo === false) fallo("Esta cuenta está desactivada. Contacta a un administrador.");
    try {
      localStorage.setItem(TOKEN, u.id);
    } catch {
      /* ignorar */
    }
    return { access_token: u.id, token_type: "bearer" };
  },
  async register({ nombre, email, password }) {
    await esperar();
    if (db.usuarios.some((u) => u.email.toLowerCase() === email.trim().toLowerCase())) fallo("Ese correo ya está registrado.");
    const u = { id: uid(), nombre: nombre.trim(), email: email.trim(), password, rol: "usuario", activo: true, creado_en: new Date().toISOString() };
    db.usuarios.push(u);
    guardar();
    return publico(u);
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
    const u = requerirUsuario();
    const v = visibles(u);
    return clon({
      ...v,
      usuarios: u.rol === "admin" ? db.usuarios.map(publico) : [],
      config: db.config,
      capacidades: { usuarios: true, reportes: true, configuracion: true, corregir: true },
    });
  },

  // Escritura
  async crearProyecto(data) {
    await esperar();
    const u = requerirUsuario();
    const p = { id: uid(), nombre: data.nombre.trim(), descripcion: (data.descripcion || "").trim() || null, propietario_id: u.id, creado_en: new Date().toISOString() };
    db.proyectos.unshift(p);
    guardar();
    return clon(p);
  },
  async crearActivo(proyectoId, data) {
    await esperar();
    const u = requerirUsuario();
    const p = db.proyectos.find((x) => x.id === proyectoId && (u.rol === "admin" || x.propietario_id === u.id));
    if (!p) fallo("Proyecto no encontrado");
    const a = { id: uid(), proyecto_id: proyectoId, nombre: data.nombre.trim(), url_objetivo: data.url_objetivo.trim(), descripcion: (data.descripcion || "").trim() || null, creado_en: new Date().toISOString() };
    db.activos.push(a);
    guardar();
    return clon(a);
  },
  async iniciarEvaluacion(activoId) {
    await esperar();
    const u = requerirUsuario();
    const a = visibles(u).activos.find((x) => x.id === activoId);
    if (!a) fallo("Activo no encontrado");
    const enCurso = visibles(u).evaluaciones.some((e) => e.activo_id === activoId && (e.estado === "pendiente" || e.estado === "en_progreso"));
    if (enCurso) fallo("Ya hay una evaluación en curso para este activo.");
    const host = hostDe(a.url_objetivo);
    const perfil = perfilPara(a);
    const sim = { dur: 11000, puertos: perfil.puertos, web: db.config.motores.zap.activo ? perfil.web : [] };
    if (!db.config.alcance.permitir_publicas && !esPrivada(host)) {
      sim.dur = 4500;
      sim.error = `Objetivo bloqueado: ${host} corresponde a una dirección pública. SecureScan solo evalúa redes privadas, loopback o link-local (ALLOW_PUBLIC_SCANS=false).`;
    }
    const ev = { id: uid(), activo_id: activoId, estado: "pendiente", iniciada_en: new Date().toISOString(), finalizada_en: null, detalle_error: null, hallazgos: [], _sim: sim };
    db.evaluaciones.push(ev);
    guardar();
    return clon(resolver(ev));
  },
  async marcarCorregido(hallazgoId, corregido) {
    await esperar(120);
    requerirUsuario();
    for (const e of db.evaluaciones) {
      const h = e.hallazgos.find((x) => x.id === hallazgoId);
      if (h) {
        h.corregido = corregido ? "si" : "no";
        guardar();
        return clon(h);
      }
    }
    return fallo("Hallazgo no encontrado");
  },
  async crearReporte({ proyecto_id, titulo, evaluacion_ids }) {
    await esperar(700);
    const u = requerirUsuario();
    const p = db.proyectos.find((x) => x.id === proyecto_id);
    if (!p) fallo("Proyecto no encontrado");
    const slug = p.nombre.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    const r = { id: uid(), proyecto_id, titulo: titulo || `Informe de seguridad — ${p.nombre}`, nombre_archivo: `informe-${slug}.pdf`, generado_en: new Date().toISOString(), generado_por: u.nombre, evaluacion_ids, tamano_kb: 80 + evaluacion_ids.length * 34 };
    db.reportes.unshift(r);
    guardar();
    return clon(r);
  },
  async eliminarReporte(id) {
    await esperar(120);
    db.reportes = db.reportes.filter((r) => r.id !== id);
    guardar();
  },
  async cambiarRol(usuarioId, rol) {
    await esperar(150);
    const u = requerirUsuario();
    if (u.rol !== "admin") fallo("Solo un administrador puede cambiar roles.");
    const t = db.usuarios.find((x) => x.id === usuarioId);
    if (!t) fallo("Usuario no encontrado");
    if (t.id === u.id) fallo("No puedes cambiar tu propio rol.");
    t.rol = rol;
    guardar();
  },
  async alternarUsuario(usuarioId) {
    await esperar(150);
    const u = requerirUsuario();
    if (u.rol !== "admin") fallo("Solo un administrador puede desactivar cuentas.");
    const t = db.usuarios.find((x) => x.id === usuarioId);
    if (!t) fallo("Usuario no encontrado");
    if (t.id === u.id) fallo("No puedes desactivar tu propia cuenta.");
    t.activo = t.activo === false;
    guardar();
  },
  async invitarUsuario({ nombre, email, rol }) {
    await esperar();
    const u = requerirUsuario();
    if (u.rol !== "admin") fallo("Solo un administrador puede crear cuentas.");
    if (db.usuarios.some((x) => x.email.toLowerCase() === email.trim().toLowerCase())) fallo("Ese correo ya está registrado.");
    const nuevo = { id: uid(), nombre: nombre.trim(), email: email.trim(), password: "Demo1234!", rol, activo: true, creado_en: new Date().toISOString() };
    db.usuarios.push(nuevo);
    guardar();
    return { ...publico(nuevo), password_temporal: "Demo1234!" };
  },
  async actualizarPerfil({ nombre }) {
    await esperar();
    const u = requerirUsuario();
    u.nombre = nombre.trim();
    guardar();
    return publico(u);
  },
  async cambiarPassword({ actual, nueva }) {
    await esperar();
    const u = requerirUsuario();
    if (u.password !== actual) fallo("La contraseña actual no coincide.");
    u.password = nueva;
    guardar();
  },
  async guardarConfig(config) {
    await esperar();
    const u = requerirUsuario();
    if (u.rol !== "admin") fallo("Solo un administrador puede cambiar la configuración.");
    db.config = clon(config);
    guardar();
    return clon(db.config);
  },
  async restablecer() {
    db = construirSeed();
    guardar();
  },
};
