// Reglas de riesgo del front. Replican las del motor de riesgo del backend (risk.py)
// para poder generar datos de ejemplo coherentes y explicar las bandas en pantalla.

export const SEVERIDADES = ["critica", "alta", "media", "baja", "informativa"];

export const SEV = {
  critica: { label: "Crítica", rango: "9,0 – 10,0", accion: "Corregir de inmediato" },
  alta: { label: "Alta", rango: "7,0 – 8,9", accion: "Corregir en el corto plazo" },
  media: { label: "Media", rango: "4,0 – 6,9", accion: "Planificar la corrección" },
  baja: { label: "Baja", rango: "0,1 – 3,9", accion: "Corregir cuando sea posible" },
  informativa: { label: "Informativa", rango: "0,0", accion: "Revisar, sin riesgo directo" },
};

export const ordenSev = (s) => {
  const i = SEVERIDADES.indexOf(s);
  return i === -1 ? 99 : i;
};

// Bandas oficiales de CVSS v3.1 (igual que el backend).
export function sevDesdeCvss(cvss) {
  if (cvss == null || cvss <= 0) return "informativa";
  if (cvss < 4) return "baja";
  if (cvss < 7) return "media";
  if (cvss < 9) return "alta";
  return "critica";
}

export const ESTADOS = {
  pendiente: "Pendiente",
  en_progreso: "En progreso",
  completada: "Completada",
  fallida: "Fallida",
};

export const ROLES = {
  admin: "Administrador",
  analista: "Analista",
  usuario: "Usuario",
};

export const HERRAMIENTAS = {
  nmap: "Nmap",
  owasp_zap: "OWASP ZAP",
};

// ---------- OWASP Top 10 (2021) ----------
export const OWASP = {
  A01: "Broken Access Control",
  A02: "Cryptographic Failures",
  A03: "Injection",
  A04: "Insecure Design",
  A05: "Security Misconfiguration",
  A06: "Vulnerable and Outdated Components",
  A07: "Identification and Authentication Failures",
  A08: "Software and Data Integrity Failures",
  A09: "Security Logging and Monitoring Failures",
  A10: "Server-Side Request Forgery",
};
export const owaspCodigo = (texto) => (texto || "").slice(0, 3) || "—";
export const A02 = "A02:2021 - Cryptographic Failures";
export const A03 = "A03:2021 - Injection";
export const A05 = "A05:2021 - Security Misconfiguration";
export const A01 = "A01:2021 - Broken Access Control";

// ---------- Reglas por puerto/servicio (espejo de risk.py) ----------
const DB_PUERTOS = {
  1433: "Microsoft SQL Server",
  1521: "Oracle DB",
  3306: "MySQL/MariaDB",
  5432: "PostgreSQL",
  6379: "Redis",
  9200: "Elasticsearch",
  27017: "MongoDB",
};

export function reglaPuerto(puerto, servicio) {
  const s = (servicio || "").toLowerCase();
  if (puerto === 23 || s === "telnet")
    return { nombre: "Telnet expuesto (credenciales sin cifrar)", owasp: A02, cvss: 7.5, rec: "Deshabilitar Telnet y reemplazarlo por SSH con autenticación por llave." };
  if (puerto === 21 || s === "ftp")
    return { nombre: "FTP expuesto (tráfico sin cifrar)", owasp: A02, cvss: 5.3, rec: "Reemplazar FTP por SFTP o FTPS y restringir el acceso por IP." };
  if (puerto === 139 || puerto === 445 || s === "microsoft-ds" || s === "netbios-ssn")
    return { nombre: "SMB/NetBIOS expuesto", owasp: A05, cvss: 7.5, rec: "No exponer SMB fuera de la red interna; aplicar reglas de firewall." };
  if (puerto === 3389 || s === "ms-wbt-server")
    return { nombre: "Escritorio remoto (RDP) expuesto", owasp: A05, cvss: 7.5, rec: "Restringir RDP mediante VPN o lista de IP permitidas y exigir MFA." };
  if (DB_PUERTOS[puerto])
    return { nombre: `Base de datos expuesta (${DB_PUERTOS[puerto]})`, owasp: A05, cvss: 7.5, rec: "Las bases de datos no deben ser accesibles desde la red; limitar a la capa de aplicación." };
  if (puerto === 22 || s === "ssh")
    return { nombre: "Servicio SSH expuesto", owasp: A05, cvss: 3.7, rec: "Deshabilitar login por contraseña, usar llaves y limitar IPs de origen." };
  if (puerto === 5900 || s === "vnc")
    return { nombre: "VNC expuesto", owasp: A05, cvss: 7.5, rec: "No exponer VNC directamente; usar túnel SSH o VPN." };
  if (s.startsWith("http") && !s.includes("ssl") && !s.includes("https"))
    return { nombre: "Servicio HTTP expuesto sin cifrado", owasp: A05, cvss: 5.3, rec: "Configurar HTTPS (TLS), redirigir HTTP a HTTPS y restringir servicios innecesarios." };
  if (s.includes("https") || s.includes("ssl"))
    return { nombre: "Servicio HTTPS expuesto", owasp: A05, cvss: 0.0, rec: "Verificar la configuración TLS (versiones y cifrados vigentes) y renovar certificados a tiempo." };
  return { nombre: `Puerto ${puerto}/tcp abierto (${servicio})`, owasp: A05, cvss: 0.0, rec: "Confirmar que el servicio es necesario; si no lo es, cerrar el puerto." };
}

// Convierte un puerto abierto en los campos de un hallazgo (como clasificar_puerto del backend).
export function hallazgoDesdePuerto(p) {
  const r = reglaPuerto(p.puerto, p.servicio);
  const detalle = [p.producto, p.version].filter(Boolean).join(" ");
  let evidencia = `Puerto ${p.puerto}/tcp abierto — servicio: ${p.servicio}`;
  if (detalle) evidencia += ` (${detalle})`;
  return {
    nombre_vulnerabilidad: r.nombre,
    categoria_owasp: r.owasp,
    cvss_score: r.cvss,
    severidad: sevDesdeCvss(r.cvss),
    evidencia,
    recomendacion: r.rec,
    herramienta_origen: "nmap",
  };
}

// Extrae puerto y servicio desde la evidencia (formato del backend).
export function puertoDeHallazgo(h) {
  const m = /Puerto (\d+)\/(tcp|udp) abierto(?: — servicio: ([^\s(]+))?/.exec(h?.evidencia || "");
  if (!m) return null;
  return { puerto: Number(m[1]), protocolo: m[2], servicio: m[3] || "" };
}

// Puertos de interés que el mapa muestra siempre (abiertos o cerrados).
export const PUERTOS_INTERES = [
  [21, "ftp"], [22, "ssh"], [23, "telnet"], [25, "smtp"], [53, "dns"],
  [80, "http"], [110, "pop3"], [139, "netbios"], [143, "imap"], [443, "https"],
  [445, "smb"], [1433, "mssql"], [3000, "http"], [3306, "mysql"], [3389, "rdp"],
  [5432, "postgres"], [5900, "vnc"], [6379, "redis"], [8080, "http-alt"], [27017, "mongodb"],
];

// Catálogo de hallazgos web (solo para los datos de ejemplo del modo demo).
export const CATALOGO_WEB = {
  csp: { nombre: "Cabecera Content-Security-Policy ausente", owasp: A05, cvss: 5.0, evidencia: "La respuesta de / no incluye la cabecera Content-Security-Policy.", rec: "Definir una política CSP restrictiva que limite el origen de scripts, estilos y marcos." },
  cookie_httponly: { nombre: "Cookie de sesión sin atributo HttpOnly", owasp: A05, cvss: 3.1, evidencia: "Set-Cookie: sid=…; Path=/ (sin HttpOnly ni SameSite).", rec: "Marcar las cookies de sesión con HttpOnly, Secure y SameSite=Lax o Strict." },
  xss: { nombre: "Cross-Site Scripting reflejado (XSS)", owasp: A03, cvss: 6.1, evidencia: "El parámetro q de /search se refleja sin codificar en la respuesta.", rec: "Codificar la salida según el contexto, validar la entrada y aplicar una política CSP." },
  sqli: { nombre: "Inyección SQL", owasp: A03, cvss: 9.1, evidencia: "El parámetro q de /rest/products/search altera la consulta SQL (respuesta con error de sintaxis).", rec: "Usar consultas parametrizadas o un ORM; nunca concatenar entrada del usuario en SQL." },
  csrf: { nombre: "Formulario sin token anti-CSRF", owasp: A01, cvss: 6.5, evidencia: "El formulario POST /login no incluye un token anti-CSRF.", rec: "Incluir un token anti-CSRF por sesión y validar el origen de la petición." },
  version_servidor: { nombre: "Divulgación de versión del servidor", owasp: A05, cvss: 3.7, evidencia: "Cabecera Server: Apache/2.4.7 (Ubuntu).", rec: "Ocultar la versión del servidor en las cabeceras de respuesta." },
  hsts: { nombre: "Cabecera Strict-Transport-Security ausente", owasp: A02, cvss: 4.3, evidencia: "La respuesta HTTPS no incluye Strict-Transport-Security.", rec: "Agregar HSTS con max-age de al menos 6 meses." },
  cors: { nombre: "CORS permisivo (Access-Control-Allow-Origin: *)", owasp: A05, cvss: 5.3, evidencia: "Access-Control-Allow-Origin: * en /api/notas.", rec: "Permitir solo los orígenes que realmente consumen la API." },
};

export function hallazgoWeb(clave) {
  const c = CATALOGO_WEB[clave];
  return {
    nombre_vulnerabilidad: c.nombre,
    categoria_owasp: c.owasp,
    cvss_score: c.cvss,
    severidad: sevDesdeCvss(c.cvss),
    evidencia: c.evidencia,
    recomendacion: c.rec,
    herramienta_origen: "owasp_zap",
  };
}

// Conteo por severidad de una lista de hallazgos.
export function contar(hallazgos = []) {
  const c = { critica: 0, alta: 0, media: 0, baja: 0, informativa: 0, total: 0 };
  hallazgos.forEach((h) => {
    if (c[h.severidad] !== undefined) c[h.severidad] += 1;
    c.total += 1;
  });
  return c;
}

export function maxSeveridad(hallazgos = []) {
  let best = null;
  hallazgos.forEach((h) => {
    if (best === null || ordenSev(h.severidad) < ordenSev(best)) best = h.severidad;
  });
  return best;
}
