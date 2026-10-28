// Cliente de la API real (FastAPI). Mismo contrato que mock.js: las pantallas no saben cuál usan.
const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const TOKEN = "token";

export const getToken = () => {
  try {
    return localStorage.getItem(TOKEN);
  } catch {
    return null;
  }
};
const setToken = (t) => {
  try {
    localStorage.setItem(TOKEN, t);
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

let redirigiendo = false; // evita lanzar la redirección varias veces si fallan varias consultas a la vez
let rolActual = null; // se recuerda al pedir /auth/me, para saber si se puede listar usuarios

async function llamar(path, { method = "GET", body, form } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (form) {
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

async function errorDe(res) {
  const err = await res.json().catch(() => ({}));
  const detail = Array.isArray(err.detail) ? err.detail.map((d) => d.msg).join(", ") : err.detail;
  return new Error(detail || `Error ${res.status}`);
}

async function request(path, opciones) {
  const res = await llamar(path, opciones);
  if (!res.ok) {
    // Token vencido o cuenta desactivada: se cierra la sesión local para volver al ingreso.
    if (res.status === 401 && getToken() && path !== "/auth/login" && !redirigiendo) {
      redirigiendo = true;
      clearToken();
      rolActual = null;
      window.location.assign("/login");
    }
    throw await errorDe(res);
  }
  if (res.status === 204) return null;
  return res.json();
}

export const http = {
  modo: "api",

  async login(email, password) {
    const r = await request("/auth/login", { method: "POST", form: { username: email, password } });
    setToken(r.access_token);
    return r;
  },
  register: (data) => request("/auth/register", { method: "POST", body: data }),
  async me() {
    const u = await request("/auth/me");
    rolActual = u.rol;
    return u;
  },
  logout() {
    clearToken();
    rolActual = null;
  },
  hayToken: () => !!getToken(),

  // Estado completo en pocas consultas, todas en paralelo.
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
  crearActivo: (pid, data) => request(`/proyectos/${pid}/activos`, { method: "POST", body: data }),
  iniciarEvaluacion: (aid) => request(`/activos/${aid}/evaluaciones`, { method: "POST" }),

  marcarCorregido: (hallazgoId, corregido) =>
    request(`/hallazgos/${hallazgoId}`, { method: "PATCH", body: { corregido: corregido ? "si" : "no" } }),

  crearReporte: ({ proyecto_id, titulo, evaluacion_ids }) =>
    request(`/proyectos/${proyecto_id}/reportes`, { method: "POST", body: { titulo: titulo || null, evaluacion_ids } }),
  eliminarReporte: (id) => request(`/reportes/${id}`, { method: "DELETE" }),
  // El PDF exige el token, así que se baja con fetch y se entrega al navegador como archivo.
  async descargarReporte(reporte) {
    const res = await llamar(`/reportes/${reporte.id}/descargar`);
    if (!res.ok) throw await errorDe(res);
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = reporte.nombre_archivo || "informe.pdf";
    document.body.appendChild(a);
    a.click();
    a.remove();
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
