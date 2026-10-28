// Mapa de puertos: la pieza distintiva de SecureScan.
// Cada puerto de interés es una "puerta": abierta (coloreada por severidad) o cerrada.
// Con `progreso` se muestra el escaneo en curso; sin él, el resultado final.
import { useEffect, useMemo, useState } from "react";
import { PUERTOS_INTERES, SEV, ordenSev, puertoDeHallazgo } from "../lib/risk.js";
import { SevMark } from "./ui.jsx";
import { TipLayer, useTip } from "./charts.jsx";

export function construirPuertos(hallazgos = []) {
  const abiertos = new Map();
  [...hallazgos].sort((a, b) => ordenSev(a.severidad) - ordenSev(b.severidad)).forEach((h) => {
    const p = puertoDeHallazgo(h);
    if (!p) return;
    const previo = abiertos.get(p.puerto);
    // Si un puerto tiene varios hallazgos se conserva el más severo (el primero que llega ya viene ordenado por quien llama)
    if (!previo) abiertos.set(p.puerto, { ...p, hallazgo: h });
  });
  const lista = PUERTOS_INTERES.map(([puerto, servicio]) => {
    const a = abiertos.get(puerto);
    return a
      ? { puerto, servicio: a.servicio || servicio, severidad: a.hallazgo.severidad, hallazgo: a.hallazgo }
      : { puerto, servicio, severidad: null };
  });
  // Puertos abiertos fuera de la lista de interés
  abiertos.forEach((a, puerto) => {
    if (!PUERTOS_INTERES.some(([p]) => p === puerto)) lista.push({ puerto, servicio: a.servicio, severidad: a.hallazgo.severidad, hallazgo: a.hallazgo });
  });
  return lista.sort((a, b) => a.puerto - b.puerto);
}

export function PortMap({ hallazgos = [], puertos, progreso = null, compacto = false, alSeleccionar }) {
  const lista = useMemo(() => puertos || construirPuertos(hallazgos), [puertos, hallazgos]);
  const { tip, mover, enfocar, ocultar } = useTip();
  const enCurso = progreso != null;
  const resueltos = enCurso ? Math.floor((progreso / 100) * lista.length) : lista.length;
  const abiertos = lista.filter((p) => p.severidad).length;

  return (
    <div className={`portmap ${compacto ? "compacto" : ""}`}>
      <ul className="portmap-grid" aria-label={`Mapa de puertos: ${abiertos} abiertos de ${lista.length} revisados`}>
        {lista.map((p, i) => {
          const estado = !enCurso || i < resueltos ? (p.severidad ? "abierto" : "cerrado") : i === resueltos ? "probando" : "espera";
          const contenido = (
            <div>
              <strong className="num">Puerto {p.puerto}/tcp</strong>
              <div>
                {estado === "abierto" ? (
                  <>
                    <SevMark sev={p.severidad} size={10} /> {SEV[p.severidad].label} · {p.servicio}
                  </>
                ) : estado === "cerrado" ? (
                  "Cerrado o filtrado"
                ) : (
                  "Pendiente de revisar"
                )}
              </div>
            </div>
          );
          const interactivo = estado === "abierto" && alSeleccionar && p.hallazgo;
          const inner = (
            <>
              <span className="pm-n num">{p.puerto}</span>
              <span className="pm-s">{p.servicio}</span>
              {estado === "abierto" && <span className="pm-mark"><SevMark sev={p.severidad} size={11} /></span>}
            </>
          );
          const props = {
            className: `pm pm-${estado} ${estado === "abierto" ? `pm-sev-${p.severidad}` : ""}`,
            onPointerMove: mover(contenido),
            onPointerLeave: ocultar,
            onFocus: enfocar(contenido),
            onBlur: ocultar,
            style: !enCurso ? { animationDelay: `${Math.min(i, 24) * 22}ms` } : undefined,
          };
          return interactivo ? (
            <li key={p.puerto}>
              <button type="button" {...props} onClick={() => alSeleccionar(p.hallazgo)} aria-label={`Puerto ${p.puerto}, ${p.servicio}, severidad ${SEV[p.severidad].label}`}>
                {inner}
              </button>
            </li>
          ) : (
            <li key={p.puerto} {...props} tabIndex={0} aria-label={`Puerto ${p.puerto}, ${estado === "abierto" ? `abierto, severidad ${SEV[p.severidad].label}` : estado === "cerrado" ? "cerrado" : "pendiente"}`}>
              {inner}
            </li>
          );
        })}
      </ul>
      <TipLayer tip={tip} />
    </div>
  );
}

// Versión animada para la portada: repite un escaneo de ejemplo.
export function PortMapDemo({ hallazgos }) {
  const [p, setP] = useState(0);
  useEffect(() => {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setP(100);
      return;
    }
    let tick = 0;
    const t = setInterval(() => {
      tick = (tick + 1) % 70;
      setP(tick <= 46 ? Math.min(100, (tick / 46) * 100) : 100);
    }, 110);
    return () => clearInterval(t);
  }, []);
  return <PortMap hallazgos={hallazgos} progreso={p >= 100 ? null : p} />;
}
