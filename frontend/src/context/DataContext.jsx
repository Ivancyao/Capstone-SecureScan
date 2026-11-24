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
      const instantanea = await api.snapshot();
      setSnap(instantanea);
      setError(null);
    } catch (problema) {
      setError(problema.message);
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
    const intervalo = setInterval(refrescar, 2000);
    return () => clearInterval(intervalo);
  }, [hayEnCurso, refrescar]);

  // Aviso cuando una evaluación pasa de "en curso" a terminada.
  useEffect(() => {
    if (!data) return;
    data.evaluaciones.forEach((evaluacion) => {
      const antes = previas.current.get(evaluacion.id);
      if (antes && (antes === "pendiente" || antes === "en_progreso")) {
        if (evaluacion.estado === "completada") toast.ok("Evaluación completada", `${evaluacion.activo?.nombre}: ${evaluacion.conteo.total} hallazgos.`);
        if (evaluacion.estado === "fallida") toast.error("La evaluación falló", evaluacion.activo?.nombre);
      }
      previas.current.set(evaluacion.id, evaluacion.estado);
    });
  }, [data, toast]);

  // Cada acción llama a la API, actualiza y avisa. Los errores vuelven a quien llamó.
  const accion = useCallback(
    (funcion, okTitulo) =>
      async (...args) => {
        try {
          const resultado = await funcion(...args);
          await refrescar();
          if (okTitulo) toast.ok(okTitulo);
          return resultado;
        } catch (problema) {
          toast.error("No se pudo completar la acción", problema.message);
          throw problema;
        }
      },
    [refrescar, toast]
  );

  const acciones = useMemo(
    () => ({
      crearProyecto: accion((datos) => api.crearProyecto(datos), "Proyecto creado"),
      crearActivo: accion((proyectoId, datos) => api.crearActivo(proyectoId, datos), "Activo registrado"),
      iniciarEvaluacion: accion((activoId) => api.iniciarEvaluacion(activoId), "Evaluación iniciada"),
      cancelarEvaluacion: accion((id) => api.cancelarEvaluacion(id), "Evaluación cancelada"),
      eliminarEvaluacion: accion((id) => api.eliminarEvaluacion(id), "Evaluación eliminada"),
      marcarCorregido: accion((id, corregido) => api.marcarCorregido(id, corregido), null),
      crearReporte: accion((datos) => api.crearReporte(datos), "Reporte generado"),
      eliminarReporte: accion((id) => api.eliminarReporte(id), "Reporte eliminado"),
      cambiarRol: accion((id, rol) => api.cambiarRol(id, rol), "Rol actualizado"),
      alternarUsuario: accion((id, activar) => api.alternarUsuario(id, activar), "Cuenta actualizada"),
      invitarUsuario: accion((datos) => api.invitarUsuario(datos), "Cuenta creada"),
      guardarConfig: accion((configuracion) => api.guardarConfig(configuracion), "Configuración guardada"),
      restablecer: accion(() => api.restablecer(), "Datos de ejemplo restablecidos"),
    }),
    [accion]
  );

  const value = useMemo(() => ({ data, error, cargando: !snap && !error, refrescar, ...acciones }), [data, error, snap, refrescar, acciones]);
  return <DataCtx.Provider value={value}>{children}</DataCtx.Provider>;
}
