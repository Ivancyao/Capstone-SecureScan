// Datos de ejemplo del modo demo. Todo es ficticio y está pensado para mostrar cada pantalla.
import { hallazgoDesdePuerto, hallazgoWeb } from "../lib/risk.js";

const DIA = 86400000;
const hace = (dias, horas = 0) => new Date(Date.now() - dias * DIA - horas * 3600000).toISOString();
const P = (puerto, servicio, producto = "", version = "") => ({ puerto, servicio, producto, version });

// Perfil de cada activo: qué puertos tiene abiertos hoy (usado también por los escaneos simulados).
const PERFILES = {
  a1: { puertos: [P(3000, "http", "Node.js Express framework")], web: ["csp", "xss", "sqli"] },
  a2: { puertos: [P(22, "ssh", "OpenSSH", "5.9p1"), P(80, "http", "Apache httpd", "2.4.7"), P(3306, "mysql", "MySQL", "5.5.62")], web: ["csrf", "version_servidor", "sqli"] },
  a3: { puertos: [P(21, "ftp", "vsftpd", "2.3.4"), P(22, "ssh", "OpenSSH", "7.4"), P(445, "microsoft-ds", "Samba smbd", "3.0.20")], web: [] },
  a4: { puertos: [P(22, "ssh", "OpenSSH", "9.2p1"), P(443, "https", "nginx", "1.24.0")], web: [] },
  a5: { puertos: [P(5432, "postgresql", "PostgreSQL DB", "14.9"), P(6379, "redis", "Redis key-value store", "6.2.6"), P(8080, "http-proxy", "Gunicorn")], web: ["cors"] },
  a6: { puertos: [P(80, "http", "nginx", "1.18.0"), P(443, "https", "nginx", "1.18.0"), P(3306, "mysql", "MariaDB", "10.3"), P(3389, "ms-wbt-server", "Microsoft Terminal Services")], web: ["hsts"] },
};

// Cada elemento describe una evaluación histórica.
const EVALS = [
  { id: "e1", a: "a1", dias: 34, dur: 14, puertos: [P(3000, "http", "Node.js Express framework")], web: ["csp"] },
  { id: "e2", a: "a1", dias: 15, dur: 21, puertos: [P(3000, "http", "Node.js Express framework")], web: ["csp", "xss", "sqli"] },
  { id: "e3", a: "a1", dias: 2, dur: 19, puertos: PERFILES.a1.puertos, web: PERFILES.a1.web },
  { id: "e4", a: "a2", dias: 28, dur: 26, puertos: PERFILES.a2.puertos, web: ["csrf", "version_servidor"] },
  { id: "e5", a: "a2", dias: 9, dur: 31, puertos: PERFILES.a2.puertos, web: PERFILES.a2.web },
  { id: "e6", a: "a3", dias: 21, dur: 17, puertos: [P(21, "ftp", "vsftpd", "2.3.4"), P(22, "ssh", "OpenSSH", "7.4"), P(23, "telnet", "Linux telnetd"), P(445, "microsoft-ds", "Samba smbd", "3.0.20")], web: [] },
  { id: "e7", a: "a3", dias: 6, dur: 15, puertos: PERFILES.a3.puertos, web: [], corregidos: ["Servicio SSH expuesto"] },
  { id: "e8", a: "a4", dias: 12, dur: 11, puertos: [P(22, "ssh", "OpenSSH", "9.2p1"), P(80, "http", "nginx", "1.18.0"), P(443, "https", "nginx", "1.18.0")], web: ["hsts"] },
  { id: "e9", a: "a4", dias: 1, dur: 9, puertos: PERFILES.a4.puertos, web: [] },
  { id: "e10", a: "a5", dias: 4, dur: 24, puertos: PERFILES.a5.puertos, web: PERFILES.a5.web },
  { id: "e11", a: "a6", dias: 18, dur: 22, puertos: PERFILES.a6.puertos, web: PERFILES.a6.web },
  { id: "e12", a: "a6", dias: 3, dur: 300, fallida: "Tiempo de espera agotado (300 s): el objetivo no respondió al escaneo. Verifique que el servicio esté encendido y accesible desde la red de SecureScan.", puertos: [], web: [] },
];

function construirEvaluacion(e, idx) {
  const inicio = hace(e.dias, 2 + (idx % 5));
  const fin = new Date(new Date(inicio).getTime() + e.dur * 1000).toISOString();
  const base = {
    id: e.id,
    activo_id: e.a,
    iniciada_en: inicio,
    finalizada_en: fin,
  };
  if (e.fallida) {
    return { ...base, estado: "fallida", detalle_error: e.fallida, hallazgos: [] };
  }
  const hallazgos = [...e.puertos.map(hallazgoDesdePuerto), ...(e.web || []).map(hallazgoWeb)].map((h, i) => ({
    ...h,
    id: `${e.id}-h${i + 1}`,
    evaluacion_id: e.id,
    corregido: (e.corregidos || []).includes(h.nombre_vulnerabilidad) ? "si" : "no",
  }));
  return { ...base, estado: "completada", detalle_error: null, hallazgos };
}

export function construirSeed() {
  return {
    version: 1,
    usuarios: [
      { id: "u1", nombre: "Ivan Escobar", email: "admin@securescan.local", password: "Demo1234!", rol: "admin", activo: true, creado_en: hace(60) },
      { id: "u2", nombre: "Camila Rojas", email: "analista@securescan.local", password: "Demo1234!", rol: "analista", activo: true, creado_en: hace(40) },
      { id: "u3", nombre: "Matías Soto", email: "usuario@securescan.local", password: "Demo1234!", rol: "usuario", activo: true, creado_en: hace(12) },
    ],
    proyectos: [
      { id: "p1", nombre: "Laboratorio de pruebas Duoc UC", descripcion: "Aplicaciones vulnerables a propósito para validar el escáner en un entorno controlado.", propietario_id: "u1", creado_en: hace(58) },
      { id: "p2", nombre: "Portal institucional piloto", descripcion: "Sitio informativo de una unidad académica, en ambiente de pruebas.", propietario_id: "u1", creado_en: hace(30) },
      { id: "p3", nombre: "Tienda pyme (staging)", descripcion: "Comercio electrónico de una pyme evaluada antes de salir a producción.", propietario_id: "u2", creado_en: hace(22) },
    ],
    activos: [
      { id: "a1", proyecto_id: "p1", nombre: "OWASP Juice Shop", url_objetivo: "http://juiceshop:3000", descripcion: "Aplicación web vulnerable de referencia para practicar el OWASP Top 10.", creado_en: hace(57) },
      { id: "a2", proyecto_id: "p1", nombre: "DVWA", url_objetivo: "http://dvwa.lab.local", descripcion: "Damn Vulnerable Web Application sobre Apache y MySQL.", creado_en: hace(50) },
      { id: "a3", proyecto_id: "p1", nombre: "Servidor de archivos del laboratorio", url_objetivo: "192.168.56.20", descripcion: "Servidor con FTP y carpetas compartidas, usado para probar servicios heredados.", creado_en: hace(44) },
      { id: "a4", proyecto_id: "p2", nombre: "Portal piloto", url_objetivo: "https://portal-pruebas.duoc.local", descripcion: "Sitio institucional detrás de nginx.", creado_en: hace(29) },
      { id: "a5", proyecto_id: "p2", nombre: "API de notas", url_objetivo: "http://10.10.4.15:8080", descripcion: "API interna que consulta PostgreSQL y usa Redis como caché.", creado_en: hace(27) },
      { id: "a6", proyecto_id: "p3", nombre: "Tienda online", url_objetivo: "https://staging.tienda-demo.local", descripcion: "Catálogo y carrito de compras de la pyme.", creado_en: hace(21) },
    ],
    evaluaciones: EVALS.map(construirEvaluacion),
    reportes: [
      { id: "r1", proyecto_id: "p1", titulo: "Informe de seguridad — Laboratorio Duoc UC", nombre_archivo: "informe-laboratorio-duoc-uc.pdf", generado_en: hace(2, 3), generado_por: "Ivan Escobar", evaluacion_ids: ["e3", "e5", "e7"], tamano_kb: 184 },
      { id: "r2", proyecto_id: "p2", titulo: "Informe de seguridad — Portal piloto", nombre_archivo: "informe-portal-piloto.pdf", generado_en: hace(1, 1), generado_por: "Ivan Escobar", evaluacion_ids: ["e9", "e10"], tamano_kb: 132 },
      { id: "r3", proyecto_id: "p3", titulo: "Informe de seguridad — Tienda pyme", nombre_archivo: "informe-tienda-pyme.pdf", generado_en: hace(17), generado_por: "Camila Rojas", evaluacion_ids: ["e11"], tamano_kb: 96 },
    ],
    perfiles: PERFILES,
    config: {
      motores: {
        nmap: { activo: true, puertos: "predeterminado", timeout_s: 300, detectar_versiones: true },
        zap: { activo: false },
        nikto: { activo: false },
      },
      alcance: {
        permitir_publicas: false,
        rangos: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
      },
      retencion_dias: 365,
    },
  };
}
