// Gráficos hechos a mano en SVG/HTML, sin librerías.
// Barras de hasta 24 px con extremo redondeado, 2 px entre segmentos, texto en color neutro,
// tooltip al pasar el cursor y vista de tabla.
import { useState } from "react";
import { Icon } from "./Icon.jsx";
import { SevMark } from "./ui.jsx";
import { SEV, SEVERIDADES } from "../lib/risk.js";
import { fmtFechaCorta } from "../lib/format.js";

// ---------- Tooltip ----------
export function useTip() {
  const [tip, setTip] = useState(null);
  const mover = (contenido) => (evento) => setTip({ x: evento.clientX, y: evento.clientY, contenido });
  const enfocar = (contenido) => (evento) => {
    const rectangulo = evento.currentTarget.getBoundingClientRect();
    setTip({ x: rectangulo.left + rectangulo.width / 2, y: rectangulo.top, contenido });
  };
  return { tip, mover, enfocar, ocultar: () => setTip(null) };
}
export function TipLayer({ tip }) {
  if (!tip) return null;
  const izquierda = Math.min(tip.x + 14, window.innerWidth - 260);
  return (
    <div className="tip" style={{ left: izquierda, top: tip.y + 16 }} role="tooltip">
      {tip.contenido}
    </div>
  );
}

// ---------- Marco con vista de tabla ----------
export function ChartFrame({ titulo, descripcion, tabla, children, leyenda }) {
  const [verTabla, setVerTabla] = useState(false);
  return (
    <div className="cframe">
      <div className="cframe-head">
        <div>
          <h3 className="h-sub">{titulo}</h3>
          {descripcion && <p className="small muted">{descripcion}</p>}
        </div>
        {tabla && (
          <button className="btn btn-quiet btn-sm" onClick={() => setVerTabla((visible) => !visible)} aria-pressed={verTabla}>
            <Icon name={verTabla ? "chart" : "table"} size={15} />
            {verTabla ? "Ver gráfico" : "Ver tabla"}
          </button>
        )}
      </div>
      {leyenda}
      {verTabla && tabla ? (
        <div className="table-wrap">
          <table className="tabla tabla-compacta">
            <thead>
              <tr>
                {tabla.columnas.map((columna, indice) => (
                  <th key={indice} className={indice > 0 ? "right" : ""}>
                    {columna}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tabla.filas.map((fila, indice) => (
                <tr key={indice}>
                  {fila.map((valor, indice) => (
                    <td key={indice} className={indice > 0 ? "right num" : ""}>
                      {valor}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        children
      )}
    </div>
  );
}

export function LeyendaSev({ conteo }) {
  return (
    <ul className="leyenda">
      {SEVERIDADES.map((severidad) => (
        <li key={severidad}>
          <SevMark sev={severidad} />
          <span>{SEV[severidad].label}</span>
          {conteo && <strong className="num">{conteo[severidad]}</strong>}
        </li>
      ))}
    </ul>
  );
}

// ---------- Barra apilada de severidad ----------
export function SeverityBar({ conteo, alto = 14 }) {
  const total = SEVERIDADES.reduce((acumulado, severidad) => acumulado + conteo[severidad], 0);
  if (!total) return <div className="sevbar vacia" style={{ height: alto }} aria-label="Sin hallazgos" />;
  return (
    <div className="sevbar" style={{ height: alto }} role="img" aria-label={SEVERIDADES.filter((severidad) => conteo[severidad]).map((severidad) => `${conteo[severidad]} ${SEV[severidad].label}`).join(", ")}>
      {SEVERIDADES.filter((severidad) => conteo[severidad] > 0).map((severidad) => (
        <i key={severidad} style={{ flexGrow: conteo[severidad], background: `var(--sev-${severidad})` }} />
      ))}
    </div>
  );
}

// ---------- Columnas apiladas por semana ----------
export function WeeklyColumns({ semanas, alto = 190 }) {
  const { tip, mover, enfocar, ocultar } = useTip();
  const max = Math.max(4, ...semanas.map((semana) => semana.total));
  const techo = Math.ceil(max / 4) * 4;
  const ticks = [0, techo / 4, techo / 2, (techo * 3) / 4, techo];
  const anchoTotal = 640;
  const margen = { l: 30, r: 8, t: 8, b: 26 };
  const anchoUtil = anchoTotal - margen.l - margen.r;
  const altoUtil = alto - margen.t - margen.b;
  const paso = anchoUtil / semanas.length;
  const ancho = Math.min(24, paso * 0.5);
  const coordenadaY = (valor) => margen.t + altoUtil - (valor / techo) * altoUtil;

  return (
    <div className="chart-svg">
      <svg viewBox={`0 0 ${anchoTotal} ${alto}`} role="img" aria-label="Hallazgos detectados por semana, apilados por severidad">
        {ticks.map((marca) => (
          <g key={marca}>
            <line x1={margen.l} x2={anchoTotal - margen.r} y1={coordenadaY(marca)} y2={coordenadaY(marca)} className="grid" />
            <text x={margen.l - 8} y={coordenadaY(marca) + 4} textAnchor="end" className="axis">
              {marca}
            </text>
          </g>
        ))}
        {semanas.map((semana, indice) => {
          const centroX = margen.l + paso * indice + paso / 2;
          let acumulado = 0;
          const contenido = (
            <div>
              <strong>Semana del {fmtFechaCorta(semana.inicio)}</strong>
              <ul className="tip-list">
                {SEVERIDADES.filter((severidad) => semana[severidad] > 0).map((severidad) => (
                  <li key={severidad}>
                    <SevMark sev={severidad} size={10} /> {SEV[severidad].label} <b className="num">{semana[severidad]}</b>
                  </li>
                ))}
                {semana.total === 0 && <li className="muted">Sin evaluaciones</li>}
              </ul>
            </div>
          );
          const segs = SEVERIDADES.filter((severidad) => semana[severidad] > 0).reverse(); // informativa abajo, crítica arriba
          return (
            <g key={indice}>
              {segs.map((segmento, idx) => {
                const alturaBarra = (semana[segmento] / techo) * altoUtil;
                const arribaBarra = coordenadaY(acumulado + semana[segmento]);
                acumulado += semana[segmento];
                const tope = idx === segs.length - 1;
                return (
                  <path
                    key={segmento}
                    d={tope ? `M${centroX - ancho / 2},${arribaBarra + alturaBarra} V${arribaBarra + 4} a4,4 0 0 1 4,-4 H${centroX + ancho / 2 - 4} a4,4 0 0 1 4,4 V${arribaBarra + alturaBarra} Z` : `M${centroX - ancho / 2},${arribaBarra} h${ancho} v${alturaBarra} h${-ancho} Z`}
                    fill={`var(--sev-${segmento})`}
                    stroke="var(--surface)"
                    strokeWidth="1"
                  />
                );
              })}
              {/* Zona de interacción más grande que la barra */}
              <rect
                x={centroX - paso / 2}
                y={margen.t}
                width={paso}
                height={altoUtil + 4}
                fill="transparent"
                tabIndex={0}
                role="img"
                aria-label={`Semana del ${fmtFechaCorta(semana.inicio)}: ${semana.total} hallazgos`}
                onPointerMove={mover(contenido)}
                onPointerLeave={ocultar}
                onFocus={enfocar(contenido)}
                onBlur={ocultar}
                className="hit"
              />
              <text x={centroX} y={alto - 8} textAnchor="middle" className="axis">
                {fmtFechaCorta(semana.inicio)}
              </text>
            </g>
          );
        })}
      </svg>
      <TipLayer tip={tip} />
    </div>
  );
}

// ---------- Barras horizontales (una serie) ----------
export function HBars({ filas, color = "var(--accent)", vacio = "Sin datos" }) {
  const { tip, mover, enfocar, ocultar } = useTip();
  if (!filas.length) return <p className="small muted">{vacio}</p>;
  const max = Math.max(...filas.map((fila) => fila.valor));
  return (
    <ul className="hbars">
      {filas.map((fila) => {
        const contenido = (
          <div>
            <strong>{fila.etiqueta}</strong>
            <div className="num">{fila.valor} hallazgo{fila.valor === 1 ? "" : "s"}</div>
          </div>
        );
        return (
          <li key={fila.etiqueta} tabIndex={0} onPointerMove={mover(contenido)} onPointerLeave={ocultar} onFocus={enfocar(contenido)} onBlur={ocultar}>
            <span className="hbars-label">
              <b>{fila.codigo}</b> {fila.nombre}
            </span>
            <span className="hbars-track">
              <i style={{ width: `${(fila.valor / max) * 100}%`, background: color }} />
            </span>
            <span className="hbars-val num">{fila.valor}</span>
          </li>
        );
      })}
      <TipLayer tip={tip} />
    </ul>
  );
}

// ---------- Mini línea de evolución ----------
export function Sparkline({ valores, ancho = 84, alto = 26 }) {
  if (!valores || valores.length < 2) return <span className="muted xs">1 evaluación</span>;
  const max = Math.max(...valores, 1);
  const min = Math.min(...valores, 0);
  const coordenadaX = (indice) => 4 + (indice * (ancho - 8)) / (valores.length - 1);
  const coordenadaY = (valor) => alto - 4 - ((valor - min) / (max - min || 1)) * (alto - 8);
  const trazado = valores.map((valor, indice) => `${indice ? "L" : "M"}${coordenadaX(indice)},${coordenadaY(valor)}`).join(" ");
  const ult = valores.length - 1;
  const baja = valores[ult] < valores[0];
  return (
    <svg width={ancho} height={alto} viewBox={`0 0 ${ancho} ${alto}`} role="img" aria-label={`Hallazgos abiertos por evaluación: ${valores.join(", ")}`} className="spark">
      <path d={trazado} fill="none" stroke="var(--ink-3)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={coordenadaX(ult)} cy={coordenadaY(valores[ult])} r="4" fill={baja ? "var(--sev-baja)" : "var(--accent)"} stroke="var(--surface)" strokeWidth="2" />
    </svg>
  );
}

// ---------- Medidor CVSS con las bandas oficiales ----------
export function CvssMeter({ valor }) {
  const valorAcotado = Math.max(0, Math.min(10, valor ?? 0));
  const bandas = [
    ["informativa", 0, 0.1],
    ["baja", 0.1, 4],
    ["media", 4, 7],
    ["alta", 7, 9],
    ["critica", 9, 10],
  ];
  return (
    <div className="cvss">
      <div className="cvss-bar" role="img" aria-label={`CVSS estimado ${valorAcotado.toFixed(1)} de 10`}>
        {bandas.slice(1).map(([severidad, desde, hasta]) => (
          <i key={severidad} style={{ flexGrow: hasta - desde, background: `var(--sev-${severidad})` }} />
        ))}
        <span className="cvss-pin" style={{ left: `${valorAcotado * 10}%` }} />
      </div>
      <div className="cvss-scale xs muted">
        <span>0</span>
        <span>4</span>
        <span>7</span>
        <span>9</span>
        <span>10</span>
      </div>
    </div>
  );
}
