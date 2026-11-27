const fecha = new Intl.DateTimeFormat("es-CL", { day: "numeric", month: "short", year: "numeric" });
const fechaHora = new Intl.DateTimeFormat("es-CL", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
const corta = new Intl.DateTimeFormat("es-CL", { day: "numeric", month: "short" });

// El servidor guarda las fechas en UTC y las envía sin zona horaria ("2026-11-13T12:51:00").
// Sin esta función, el navegador las leería como hora local y mostraría 3 horas de más en Chile.
// Si el texto ya trae zona ("Z" o "+00:00"), se respeta tal cual.
// Detalle que me costó descubrir: el servidor manda las fechas en UTC pero sin la "Z", entonces el navegador las lee como hora local y mostraba 3 horas de más.
// Esta función agrega la Z cuando falta.
export const aFecha = (iso) => {
  if (iso instanceof Date) return iso;
  const texto = String(iso);
  return new Date(/(Z|[+-]\d{2}:?\d{2})$/i.test(texto) || !texto.includes("T") ? texto : texto + "Z");
};

export const fmtFecha = (iso) => (iso ? fecha.format(aFecha(iso)) : "—");
export const fmtFechaHora = (iso) => (iso ? fechaHora.format(aFecha(iso)) : "—");
export const fmtFechaCorta = (iso) => (iso ? corta.format(aFecha(iso)) : "—");

// Texto relativo: "hace 5 min", "hace 2 días"...
export function hace(iso) {
  if (!iso) return "—";
  const segundos = Math.max(0, (Date.now() - aFecha(iso).getTime()) / 1000);
  if (segundos < 60) return "hace un momento";
  const minutos = Math.floor(segundos / 60);
  if (minutos < 60) return `hace ${minutos} min`;
  const horas = Math.floor(minutos / 60);
  if (horas < 24) return `hace ${horas} h`;
  const dias = Math.floor(horas / 24);
  if (dias < 30) return dias === 1 ? "hace 1 día" : `hace ${dias} días`;
  const mes = Math.floor(dias / 30);
  return mes === 1 ? "hace 1 mes" : `hace ${mes} meses`;
}

export function fmtDuracion(inicio, fin) {
  if (!inicio || !fin) return "—";
  const segundos = Math.round((aFecha(fin) - aFecha(inicio)) / 1000);
  if (segundos < 60) return `${segundos} s`;
  return `${Math.floor(segundos / 60)} min ${segundos % 60} s`;
}

// El CVSS se muestra con una coma decimal (7,5), como se escribe en Chile.
export const fmtCvss = (numero) => (numero == null ? "—" : Number(numero).toFixed(1).replace(".", ","));
export const plural = (cantidad, uno, varios) => `${cantidad} ${cantidad === 1 ? uno : varios}`;
export const iniciales = (nombre = "") =>
  nombre.split(/\s+/).filter(Boolean).slice(0, 2).map((palabra) => palabra[0].toUpperCase()).join("");
export const fmtKb = (kilobytes) => (kilobytes >= 1024 ? `${(kilobytes / 1024).toFixed(1).replace(".", ",")} MB` : `${kilobytes} KB`);

// Host de una URL de activo, tolerando entradas sin esquema ("10.0.0.5", "dvwa.lab.local").
export function hostDe(url = "") {
  try {
    return new URL(url.includes("://") ? url : `http://${url}`).hostname;
  } catch {
    return url;
  }
}

export function uid() {
  try {
    return crypto.randomUUID();
  } catch {
    return "id-" + Math.random().toString(36).slice(2) + Date.now().toString(36);
  }
}

// ¿El host está en un rango que SecureScan permite escanear? (mismo criterio que el backend)
// Aviso en el formulario: me dice si el objetivo parece de laboratorio. Es solo una ayuda visual; la validación de verdad la hace el backend.
export function esHostPrivado(host = "") {
  if (!host) return false;
  if (host === "localhost") return true;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return /(\.local|\.lab|\.duoc\.cl)$/i.test(host) || !host.includes(".");
  const [primerOcteto, segundoOcteto] = host.split(".").map(Number);
  return primerOcteto === 10 || primerOcteto === 127 || (primerOcteto === 172 && segundoOcteto >= 16 && segundoOcteto <= 31) || (primerOcteto === 192 && segundoOcteto === 168);
}
