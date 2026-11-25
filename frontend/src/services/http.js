// Cliente de la API real (FastAPI). Mismo contrato que mock.js: las pantallas no saben cuál usan.
// Dirección del backend. En desarrollo es localhost:8000; se cambia con VITE_API_URL.
const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const TOKEN = "token";

// El token JWT lo guardo en localStorage. Lo sé: es el compromiso habitual de una SPA (si hubiera XSS se podría robar).
// Lo mitigo no usando dangerouslySetInnerHTML ni eval en ninguna parte. Todo va en try/catch porque localStorage puede estar bloqueado.
const getToken = () => {
  try {
    return localStorage.getItem(TOKEN);
  } catch {
    return null;
  }
};
const setToken = (token) => {
  try {
    localStorage.setItem(TOKEN, token);
  } catch {
    /* ignorar */
  }
};
const clearToken = () => {
  try {
    localStorage.removeItem(TOKEN);
  } catch {
    /* ignorar */
  }
};

// Bandera para que, si fallan varias consultas a la vez por token vencido, solo redirija una vez al login.
let redirigiendo = false; // evita lanzar la redirección varias veces si fallan varias consultas a la vez
let rolActual = null; // se recuerda al pedir /auth/me, para saber si se puede listar usuarios

// Función base de todas las llamadas: agrega el token en la cabecera y arma el cuerpo según el caso (JSON, formulario del login o archivo).
async function llamar(path, { method = "GET", body, form, multipart } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (multipart) {
    payload = multipart; // FormData: el navegador fija el Content-Type con su boundary
  } else if (form) {
    payload = new URLSearchParams(form); // el login usa application/x-www-form-urlencoded
  } else if (body) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  try {
    return await fetch(`${API_URL}${path}`, { method, headers, body: payload });
  } catch {
    throw new Error(`No se pudo conectar con el servidor (${API_URL}). Verifica que el backend esté encendido.`);
  }
}

// FastAPI devuelve el error en `detail` (texto o lista); lo convierto a un mensaje legible para mostrarlo en pantalla.
async function errorDe(respuesta) {
  const err = await respuesta.json().catch(() => ({}));
  const detail = Array.isArray(err.detail) ? err.detail.map((problema) => problema.msg).join(", ") : err.detail;
  return new Error(detail || `Error ${respuesta.status}`);
}

// Si el servidor responde 401 con token guardado (vencido o cuenta desactivada), cierro la sesión local y mando al login.
async function request(path, opciones) {
  const respuesta = await llamar(path, opciones);
  if (!respuesta.ok) {
    // Token vencido o cuenta desactivada: se cierra la sesión local para volver al ingreso.
    if (respuesta.status === 401 && getToken() && path !== "/auth/login" && !redirigiendo) {
      redirigiendo = true;
      clearToken();
      rolActual = null;
      window.location.assign("/login");
    }
    throw await errorDe(respuesta);
  }
  if (respuesta.status === 204) return null;
  return respuesta.json();
}

// Aquí está cada operación que puede hacer la app, una por endpoint. Las pantallas llaman a estas funciones y no saben nada de URLs.
export const http = {
  modo: "api",

  async login(email, password) {
    const respuesta = await request("/auth/login", { method: "POST", form: { username: email, password } });
    setToken(respuesta.access_token);
    return respuesta;
  },
  register: (data) => request("/auth/register", { method: "POST", body: data }),
  async me() {
    const usuario = await request("/auth/me");
    rolActual = usuario.rol;
    return usuario;
  },
  logout() {
    clearToken();
    rolActual = null;
  },
  hayToken: () => !!getToken(),

  // Estado completo en pocas consultas, todas en paralelo.
  // Cargo todo lo que necesitan las pantallas en paralelo con Promise.all (más rápido que una por una).
  // La lista de usuarios solo se pide si el rol es admin.
  async snapshot() {
    if (!rolActual) await this.me();
    const [proyectos, activos, evaluaciones, reportes, config, usuarios, metricas] = await Promise.all([
      request("/proyectos"),
      request("/activos"),
      request("/evaluaciones?ultimas=10"), // las 10 más recientes de cada activo; metricas cubre todo el historial
      request("/reportes"),
      request("/configuracion"),
      rolActual === "admin" ? request("/usuarios") : Promise.resolve([]),
      request("/metricas"),
    ]);
    return {
      proyectos,
      activos,
      evaluaciones,
      reportes,
      usuarios,
      config,
      metricas,
      capacidades: { usuarios: true, reportes: true, configuracion: true, corregir: true },
    };
  },

  crearProyecto: (data) => request("/proyectos", { method: "POST", body: data }),
  crearActivo: (proyectoId, data) => request(`/proyectos/${proyectoId}/activos`, { method: "POST", body: data }),
  iniciarEvaluacion: (activoId) => request(`/activos/${activoId}/evaluaciones`, { method: "POST" }),

  marcarCorregido: (hallazgoId, corregido) =>
    request(`/hallazgos/${hallazgoId}`, { method: "PATCH", body: { corregido: corregido ? "si" : "no" } }),

  crearReporte: ({ proyecto_id, titulo, evaluacion_ids }) =>
    request(`/proyectos/${proyecto_id}/reportes`, { method: "POST", body: { titulo: titulo || null, evaluacion_ids } }),
  cancelarEvaluacion: (id) => request(`/evaluaciones/${id}/cancelar`, { method: "POST" }),
  eliminarEvaluacion: (id) => request(`/evaluaciones/${id}`, { method: "DELETE" }),
  // Análisis de URL / archivo (módulo independiente de las evaluaciones)
  analisisEstado: () => request("/analisis/estado"),
  listarAnalisis: () => request("/analisis"),
  obtenerAnalisis: (id) => request(`/analisis/${id}`),
  analizarUrl: (url) => request("/analisis/url", { method: "POST", body: { url } }),
  analizarArchivo(archivo, subir) {
    const formulario = new FormData();
    formulario.append("archivo", archivo);
    formulario.append("subir", subir ? "true" : "false");
    return request("/analisis/archivo", { method: "POST", multipart: formulario });
  },
  eliminarAnalisis: (id) => request(`/analisis/${id}`, { method: "DELETE" }),
  eliminarReporte: (id) => request(`/reportes/${id}`, { method: "DELETE" }),
  // El PDF exige el token, así que se baja con fetch y se entrega al navegador como archivo.
  // El PDF exige el token, así que no puedo usar un enlace normal: lo descargo con fetch, creo un enlace temporal en memoria y le hago clic por código.
  async descargarReporte(reporte) {
    const respuesta = await llamar(`/reportes/${reporte.id}/descargar`);
    if (!respuesta.ok) throw await errorDe(respuesta);
    const url = URL.createObjectURL(await respuesta.blob());
    const enlace = document.createElement("a");
    enlace.href = url;
    enlace.download = reporte.nombre_archivo || "informe.pdf";
    document.body.appendChild(enlace);
    enlace.click();
    enlace.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  },

  cambiarRol: (id, rol) => request(`/usuarios/${id}`, { method: "PATCH", body: { rol } }),
  alternarUsuario: (id, activar) => request(`/usuarios/${id}`, { method: "PATCH", body: { activo: !!activar } }),
  invitarUsuario: (data) => request("/usuarios", { method: "POST", body: data }),

  actualizarPerfil: ({ nombre }) => request("/auth/me", { method: "PATCH", body: { nombre } }),
  cambiarPassword: ({ actual, nueva }) => request("/auth/password", { method: "POST", body: { actual, nueva } }),

  guardarConfig: (config) => request("/configuracion", { method: "PUT", body: config }),
  restablecer: async () => {},
};
