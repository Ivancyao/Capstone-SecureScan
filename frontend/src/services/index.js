// Punto único de acceso a datos. Por defecto usa la API real; VITE_USE_MOCK=true activa los datos de ejemplo en el navegador.
// Las páginas solo importan `api`; no saben de dónde vienen los datos.
import { mock } from "./mock.js";
import { http } from "./http.js";

export const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true";
export const api = USE_MOCK ? mock : http;
