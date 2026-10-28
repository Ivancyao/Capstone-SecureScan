// Gráficos hechos a mano en SVG/HTML: sin librerías, así se pueden explicar en la defensa.
// Reglas: barras de hasta 24 px con extremo redondeado, 2 px de separación entre segmentos,
// texto en tinta (nunca del color de la serie), tooltip al pasar el cursor y vista de tabla.
import { useState } from "react";
import { Icon } from "./Icon.jsx";
import { SevMark } from "./ui.jsx";
import { SEV, SEVERIDADES } from "../lib/risk.js";
import { fmtFechaCorta } from "../lib/format.js";

// ---------- Tooltip ----------
export function useTip() {
  const [tip, setTip] = useState(null);
  const mover = (contenido) => (e) => setTip({ x: e.clientX, y: e.clientY, contenido });
  const enfocar = (contenido) => (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    setTip({ x: r.left + r.width / 2, y: r.top, contenido });
  };
  return { tip, mover, enfocar, ocultar: () => setTip(null) };
}
export function TipLayer({ tip }) {
  if (!tip) return null;
  const x = Math.min(tip.x + 14, window.innerWidth - 260);
  return (
    <div className="tip" style={{ left: x, top: tip.y + 16 }} role="tooltip">
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
          <button className="btn btn-quiet btn-sm" onClick={() => setVerTabla((v) => !v)} aria-pressed={verTabla}>
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
                {tabla.columnas.map((c, i) => (
                  <th key={i} className={i > 0 ? "right" : ""}>
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tabla.filas.map((f, i) => (
                <tr key={i}>
                  {f.map((v, j) => (
                    <td key={j} className={j > 0 ? "right num" : ""}>
                      {v}
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
      {SEVERIDADES.map((s) => (
        <li key={s}>
          <SevMark sev={s} />
          <span>{SEV[s].label}</span>
          {conteo && <strong className="num">{conteo[s]}</strong>}
        </li>
      ))}
    </ul>
  );
}

// ---------- Barra apilada de severidad ----------
export function SeverityBar({ conteo, alto = 14 }) {
  const total = SEVERIDADES.reduce((n, s) => n + conteo[s], 0);
  if (!total) return <div className="sevbar vacia" style={{ height: alto }} aria-label="Sin hallazgos" />;
  return (
    <div className="sevbar" style={{ height: alto }} role="img" aria-label={SEVERIDADES.filter((s) => conteo[s]).map((s) => `${conteo[s]} ${SEV[s].label}`).join(", ")}>
      {SEVERIDADES.filter((s) => conteo[s] > 0).map((s) => (
        <i key={s} style={{ flexGrow: conteo[s], background: `var(--sev-${s})` }} />
      ))}
    </div>
  );
}

// ---------- Columnas apiladas por semana ----------
export function WeeklyColumns({ semanas, alto = 190 }) {
  const { tip, mover, enfocar, ocultar } = useTip();
  const max = Math.max(4, ...semanas.map((s) => s.total));
  const techo = Math.ceil(max / 4) * 4;
  const ticks = [0, techo / 4, techo / 2, (techo * 3) / 4, techo];
  const W = 640;
  const m = { l: 30, r: 8, t: 8, b: 26 };
  const iw = W - m.l - m.r;
  const ih = alto - m.t - m.b;
  const paso = iw / semanas.length;
  const ancho = Math.min(24, paso * 0.5);
  const y = (v) => m.t + ih - (v / techo) * ih;

  return (
    <div className="chart-svg">
      <svg viewBox={`0 0 ${W} ${alto}`} role="img" aria-label="Hallazgos detectados por semana, apilados por severidad">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={m.l} x2={W - m.r} y1={y(t)} y2={y(t)} className="grid" />
            <text x={m.l - 8} y={y(t) + 4} textAnchor="end" className="axis">
              {t}
            </text>
          </g>
        ))}
        {semanas.map((s, i) => {
          const cx = m.l + paso * i + paso / 2;
          let acum = 0;
          const contenido = (
            <div>
              <strong>Semana del {fmtFechaCorta(s.inicio)}</strong>
              <ul className="tip-list">
                {SEVERIDADES.filter((k) => s[k] > 0).map((k) => (
                  <li key={k}>
                    <SevMark sev={k} size={10} /> {SEV[k].label} <b className="num">{s[k]}</b>
                  </li>
                ))}
                {s.total === 0 && <li className="muted">Sin evaluaciones</li>}
              </ul>
            </div>
          );
          const segs = SEVERIDADES.filter((k) => s[k] > 0).reverse(); // informativa abajo, crítica arriba
          return (
            <g key={i}>
              {segs.map((k, idx) => {
                const h = (s[k] / techo) * ih;
                const y0 = y(acum + s[k]);
                acum += s[k];
                const tope = idx === segs.length - 1;
                return (
                  <path
                    key={k}
                    d={tope ? `M${cx - ancho / 2},${y0 + h} V${y0 + 4} a4,4 0 0 1 4,-4 H${cx + ancho / 2 - 4} a4,4 0 0 1 4,4 V${y0 + h} Z` : `M${cx - ancho / 2},${y0} h${ancho} v${h} h${-ancho} Z`}
                    fill={`var(--sev-${k})`}
                    stroke="var(--surface)"
                    strokeWidth="1"
                  />
                );
              })}
              {/* Zona de interacción más grande que la barra */}
              <rect
                x={cx - paso / 2}
                y={m.t}
                width={paso}
                height={ih + 4}
                fill="transparent"
                tabIndex={0}
                role="img"
                aria-label={`Semana del ${fmtFechaCorta(s.inicio)}: ${s.total} hallazgos`}
                onPointerMove={mover(contenido)}
                onPointerLeave={ocultar}
                onFocus={enfocar(contenido)}
                onBlur={ocultar}
                className="hit"
              />
              <text x={cx} y={alto - 8} textAnchor="middle" className="axis">
                {fmtFechaCorta(s.inicio)}
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
  const max = Math.max(...filas.map((f) => f.valor));
  return (
    <ul className="hbars">
      {filas.map((f) => {
        const contenido = (
          <div>
            <strong>{f.etiqueta}</strong>
            <div className="num">{f.valor} hallazgo{f.valor === 1 ? "" : "s"}</div>
          </div>
        );
        return (
          <li key={f.etiqueta} tabIndex={0} onPointerMove={mover(contenido)} onPointerLeave={ocultar} onFocus={enfocar(contenido)} onBlur={ocultar}>
            <span className="hbars-label">
              <b>{f.codigo}</b> {f.nombre}
            </span>
            <span className="hbars-track">
              <i style={{ width: `${(f.valor / max) * 100}%`, background: color }} />
            </span>
            <span className="hbars-val num">{f.valor}</span>
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
  const x = (i) => 4 + (i * (ancho - 8)) / (valores.length - 1);
  const y = (v) => alto - 4 - ((v - min) / (max - min || 1)) * (alto - 8);
  const d = valores.map((v, i) => `${i ? "L" : "M"}${x(i)},${y(v)}`).join(" ");
  const ult = valores.length - 1;
  const baja = valores[ult] < valores[0];
  return (
    <svg width={ancho} height={alto} viewBox={`0 0 ${ancho} ${alto}`} role="img" aria-label={`Hallazgos abiertos por evaluación: ${valores.join(", ")}`} className="spark">
      <path d={d} fill="none" stroke="var(--ink-3)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={x(ult)} cy={y(valores[ult])} r="4" fill={baja ? "var(--sev-baja)" : "var(--accent)"} stroke="var(--surface)" strokeWidth="2" />
    </svg>
  );
}

// ---------- Medidor CVSS con las bandas oficiales ----------
export function CvssMeter({ valor }) {
  const v = Math.max(0, Math.min(10, valor ?? 0));
  const bandas = [
    ["informativa", 0, 0.1],
    ["baja", 0.1, 4],
    ["media", 4, 7],
    ["alta", 7, 9],
    ["critica", 9, 10],
  ];
  return (
    <div className="cvss">
      <div className="cvss-bar" role="img" aria-label={`CVSS estimado ${v.toFixed(1)} de 10`}>
        {bandas.slice(1).map(([s, a, b]) => (
          <i key={s} style={{ flexGrow: b - a, background: `var(--sev-${s})` }} />
        ))}
        <span className="cvss-pin" style={{ left: `${v * 10}%` }} />
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
