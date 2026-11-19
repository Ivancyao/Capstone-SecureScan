const fecha = new Intl.DateTimeFormat("es-CL", { day: "numeric", month: "short", year: "numeric" });
const fechaHora = new Intl.DateTimeFormat("es-CL", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
const corta = new Intl.DateTimeFormat("es-CL", { day: "numeric", month: "short" });

// El servidor guarda las fechas en UTC y las envía sin zona horaria ("2026-11-13T12:51:00").
// Sin esta función, el navegador las leería como hora local y mostraría 3 horas de más en Chile.
// Si el texto ya trae zona ("Z" o "+00:00"), se respeta tal cual.
export const aFecha = (iso) => {
  if (iso instanceof Date) return iso;
  const t = String(iso);
  return new Date(/(Z|[+-]\d{2}:?\d{2})$/i.test(t) || !t.includes("T") ? t : t + "Z");
};

export const fmtFecha = (iso) => (iso ? fecha.format(aFecha(iso)) : "—");
export const fmtFechaHora = (iso) => (iso ? fechaHora.format(aFecha(iso)) : "—");
export const fmtFechaCorta = (iso) => (iso ? corta.format(aFecha(iso)) : "—");

export function hace(iso) {
  if (!iso) return "—";
  const s = Math.max(0, (Date.now() - aFecha(iso).getTime()) / 1000);
  if (s < 60) return "hace un momento";
  const m = Math.floor(s / 60);
  if (m < 60) return `hace ${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `hace ${h} h`;
  const d = Math.floor(h / 24);
  if (d < 30) return d === 1 ? "hace 1 día" : `hace ${d} días`;
  const mes = Math.floor(d / 30);
  return mes === 1 ? "hace 1 mes" : `hace ${mes} meses`;
}

export function fmtDuracion(inicio, fin) {
  if (!inicio || !fin) return "—";
  const s = Math.round((aFecha(fin) - aFecha(inicio)) / 1000);
  if (s < 60) return `${s} s`;
  return `${Math.floor(s / 60)} min ${s % 60} s`;
}

export const fmtCvss = (n) => (n == null ? "—" : Number(n).toFixed(1).replace(".", ","));
export const plural = (n, uno, varios) => `${n} ${n === 1 ? uno : varios}`;
export const iniciales = (nombre = "") =>
  nombre.split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join("");
export const fmtKb = (kb) => (kb >= 1024 ? `${(kb / 1024).toFixed(1).replace(".", ",")} MB` : `${kb} KB`);

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
export function esHostPrivado(h = "") {
  if (!h) return false;
  if (h === "localhost") return true;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return /(\.local|\.lab|\.duoc\.cl)$/i.test(h) || !h.includes(".");
  const [a, b] = h.split(".").map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}
