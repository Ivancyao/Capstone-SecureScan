// Mapa de puertos: la pieza distintiva de SecureScan.
// Cada puerto de interés es una "puerta": abierta (coloreada por severidad) o cerrada.
// Con `progreso` se muestra el escaneo en curso; sin él, el resultado final.
import { useEffect, useMemo, useState } from "react";
import { PUERTOS_INTERES, SEV, ordenSev, puertoDeHallazgo } from "../lib/risk.js";
import { SevMark } from "./ui.jsx";
import { TipLayer, useTip } from "./charts.jsx";

export function construirPuertos(hallazgos = []) {
  const abiertos = new Map();
  [...hallazgos].sort((primero, segundo) => ordenSev(primero.severidad) - ordenSev(segundo.severidad)).forEach((hallazgo) => {
    const puertoDelHallazgo = puertoDeHallazgo(hallazgo);
    if (!puertoDelHallazgo) return;
    const previo = abiertos.get(puertoDelHallazgo.puerto);
    // Si un puerto tiene varios hallazgos se conserva el más severo (el primero que llega ya viene ordenado por quien llama)
    if (!previo) abiertos.set(puertoDelHallazgo.puerto, { ...puertoDelHallazgo, hallazgo });
  });
  const lista = PUERTOS_INTERES.map(([puerto, servicio]) => {
    const abierto = abiertos.get(puerto);
    return abierto
      ? { puerto, servicio: abierto.servicio || servicio, severidad: abierto.hallazgo.severidad, hallazgo: abierto.hallazgo }
      : { puerto, servicio, severidad: null };
  });
  // Puertos abiertos fuera de la lista de interés
  abiertos.forEach((abierto, puerto) => {
    if (!PUERTOS_INTERES.some(([puertoDeInteres]) => puertoDeInteres === puerto)) lista.push({ puerto, servicio: abierto.servicio, severidad: abierto.hallazgo.severidad, hallazgo: abierto.hallazgo });
  });
  return lista.sort((primero, segundo) => primero.puerto - segundo.puerto);
}

export function PortMap({ hallazgos = [], puertos, progreso = null, compacto = false, alSeleccionar }) {
  const lista = useMemo(() => puertos || construirPuertos(hallazgos), [puertos, hallazgos]);
  const { tip, mover, enfocar, ocultar } = useTip();
  const enCurso = progreso != null;
  const resueltos = enCurso ? Math.floor((progreso / 100) * lista.length) : lista.length;
  const abiertos = lista.filter((entrada) => entrada.severidad).length;

  return (
    <div className={`portmap ${compacto ? "compacto" : ""}`}>
      <ul className="portmap-grid" aria-label={`Mapa de puertos: ${abiertos} abiertos de ${lista.length} revisados`}>
        {lista.map((entrada, indice) => {
          const estado = !enCurso || indice < resueltos ? (entrada.severidad ? "abierto" : "cerrado") : indice === resueltos ? "probando" : "espera";
          const contenido = (
            <div>
              <strong className="num">Puerto {entrada.puerto}/tcp</strong>
              <div>
                {estado === "abierto" ? (
                  <>
                    <SevMark sev={entrada.severidad} size={10} /> {SEV[entrada.severidad].label} · {entrada.servicio}
                  </>
                ) : estado === "cerrado" ? (
                  "Cerrado o filtrado"
                ) : (
                  "Pendiente de revisar"
                )}
              </div>
            </div>
          );
          const interactivo = estado === "abierto" && alSeleccionar && entrada.hallazgo;
          const inner = (
            <>
              <span className="pm-n num">{entrada.puerto}</span>
              <span className="pm-s">{entrada.servicio}</span>
              {estado === "abierto" && <span className="pm-mark"><SevMark sev={entrada.severidad} size={11} /></span>}
            </>
          );
          const props = {
            className: `pm pm-${estado} ${estado === "abierto" ? `pm-sev-${entrada.severidad}` : ""}`,
            onPointerMove: mover(contenido),
            onPointerLeave: ocultar,
            onFocus: enfocar(contenido),
            onBlur: ocultar,
            style: !enCurso ? { animationDelay: `${Math.min(indice, 24) * 22}ms` } : undefined,
          };
          return interactivo ? (
            <li key={entrada.puerto}>
              <button type="button" {...props} onClick={() => alSeleccionar(entrada.hallazgo)} aria-label={`Puerto ${entrada.puerto}, ${entrada.servicio}, severidad ${SEV[entrada.severidad].label}`}>
                {inner}
              </button>
            </li>
          ) : (
            <li key={entrada.puerto} {...props} tabIndex={0} aria-label={`Puerto ${entrada.puerto}, ${estado === "abierto" ? `abierto, severidad ${SEV[entrada.severidad].label}` : estado === "cerrado" ? "cerrado" : "pendiente"}`}>
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
  const [porcentaje, setPorcentaje] = useState(0);
  useEffect(() => {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setPorcentaje(100);
      return;
    }
    let tick = 0;
    const intervalo = setInterval(() => {
      tick = (tick + 1) % 70;
      setPorcentaje(tick <= 46 ? Math.min(100, (tick / 46) * 100) : 100);
    }, 110);
    return () => clearInterval(intervalo);
  }, []);
  return <PortMap hallazgos={hallazgos} progreso={porcentaje >= 100 ? null : porcentaje} />;
}
