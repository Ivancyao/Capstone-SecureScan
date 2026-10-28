import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../services/index.js";
import { derive } from "../services/derive.js";
import { useToast } from "./ToastContext.jsx";

const DataCtx = createContext(null);
export const useData = () => useContext(DataCtx);

export function DataProvider({ children }) {
  const toast = useToast();
  const [snap, setSnap] = useState(null);
  const [error, setError] = useState(null);
  const previas = useRef(new Map()); // id evaluación -> estado, para avisar cuando termina

  const refrescar = useCallback(async () => {
    try {
      const s = await api.snapshot();
      setSnap(s);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    refrescar();
  }, [refrescar]);

  const data = useMemo(() => derive(snap), [snap]);
  const hayEnCurso = !!data && data.enCurso.length > 0;

  // Mientras hay un escaneo corriendo, se consulta el estado cada 2 segundos.
  useEffect(() => {
    if (!hayEnCurso) return;
    const t = setInterval(refrescar, 2000);
    return () => clearInterval(t);
  }, [hayEnCurso, refrescar]);

  // Aviso cuando una evaluación pasa de "en curso" a terminada.
  useEffect(() => {
    if (!data) return;
    data.evaluaciones.forEach((e) => {
      const antes = previas.current.get(e.id);
      if (antes && (antes === "pendiente" || antes === "en_progreso")) {
        if (e.estado === "completada") toast.ok("Evaluación completada", `${e.activo?.nombre}: ${e.conteo.total} hallazgos.`);
        if (e.estado === "fallida") toast.error("La evaluación falló", e.activo?.nombre);
      }
      previas.current.set(e.id, e.estado);
    });
  }, [data, toast]);

  // Cada acción llama a la API, actualiza y avisa. Los errores vuelven a quien llamó.
  const accion = useCallback(
    (fn, okTitulo) =>
      async (...args) => {
        try {
          const r = await fn(...args);
          await refrescar();
          if (okTitulo) toast.ok(okTitulo);
          return r;
        } catch (e) {
          toast.error("No se pudo completar la acción", e.message);
          throw e;
        }
      },
    [refrescar, toast]
  );

  const acciones = useMemo(
    () => ({
      crearProyecto: accion((d) => api.crearProyecto(d), "Proyecto creado"),
      crearActivo: accion((pid, d) => api.crearActivo(pid, d), "Activo registrado"),
      iniciarEvaluacion: accion((aid) => api.iniciarEvaluacion(aid), "Evaluación iniciada"),
      marcarCorregido: accion((id, v) => api.marcarCorregido(id, v), null),
      crearReporte: accion((d) => api.crearReporte(d), "Reporte generado"),
      eliminarReporte: accion((id) => api.eliminarReporte(id), "Reporte eliminado"),
      cambiarRol: accion((id, rol) => api.cambiarRol(id, rol), "Rol actualizado"),
      alternarUsuario: accion((id, activar) => api.alternarUsuario(id, activar), "Cuenta actualizada"),
      invitarUsuario: accion((d) => api.invitarUsuario(d), "Cuenta creada"),
      guardarConfig: accion((c) => api.guardarConfig(c), "Configuración guardada"),
      restablecer: accion(() => api.restablecer(), "Datos de ejemplo restablecidos"),
    }),
    [accion]
  );

  const value = useMemo(() => ({ data, error, cargando: !snap && !error, refrescar, ...acciones }), [data, error, snap, refrescar, acciones]);
  return <DataCtx.Provider value={value}>{children}</DataCtx.Provider>;
}
