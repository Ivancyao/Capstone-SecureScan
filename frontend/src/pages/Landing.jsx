import { Link } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Logo, SevMark, useTitulo } from "../components/ui.jsx";
import { PortMapDemo } from "../components/PortMap.jsx";
import { SEV, SEVERIDADES, hallazgoDesdePuerto } from "../lib/risk.js";
import { useAuth } from "../context/AuthContext.jsx";
import { useTheme } from "../context/ThemeContext.jsx";

// Servidor de ejemplo para la portada: se clasifica con las mismas reglas del motor de riesgo.
const EJEMPLO = [
  [21, "ftp", "vsftpd", "2.3.4"], [22, "ssh", "OpenSSH", "7.4"], [23, "telnet"], [80, "http", "Apache httpd", "2.4.7"],
  [443, "https", "nginx", "1.24.0"], [445, "microsoft-ds", "Samba smbd"], [3306, "mysql", "MySQL", "5.5.62"], [3389, "ms-wbt-server"], [6379, "redis", "Redis"],
].map(([puerto, servicio, producto = "", version = ""], i) => ({ ...hallazgoDesdePuerto({ puerto, servicio, producto, version }), id: `ej-${i}` }));

const PASOS = [
  { t: "Registra un activo", d: "Indica la aplicación o servidor que quieres revisar. Debe ser tuyo o contar con autorización." },
  { t: "Lanza la evaluación", d: "SecureScan revisa los puertos y servicios expuestos en segundo plano. Tú sigues trabajando." },
  { t: "Clasifica el riesgo", d: "Cada hallazgo recibe una severidad, un puntaje CVSS estimado y su categoría OWASP Top 10." },
  { t: "Corrige y reporta", d: "Marca lo corregido, vuelve a evaluar para confirmarlo y descarga un informe para tu equipo." },
];

const PRINCIPIOS = [
  { i: "lock", t: "Solo redes privadas", d: "El escáner rechaza direcciones públicas. Evaluar sistemas ajenos sin permiso no es una opción." },
  { i: "users", t: "Cada rol ve lo suyo", d: "Administrador, analista y usuario. Nadie accede a proyectos que no son suyos." },
  { i: "shield", t: "Sin comandos del usuario", d: "Las herramientas se ejecutan con parámetros controlados, nunca con texto escrito por el usuario." },
  { i: "info", t: "El puntaje es una estimación", d: "El CVSS se calcula por reglas según el servicio expuesto, y la plataforma lo indica en cada reporte." },
];

export default function Landing() {
  useTitulo("Evalúa y prioriza vulnerabilidades web");
  const { user } = useAuth();
  const { oscuro, alternar } = useTheme();
  return (
    <div className="landing">
      <header className="l-nav">
        <Link to="/" aria-label="SecureScan, inicio"><Logo /></Link>
        <nav className="l-links" aria-label="Secciones">
          <a href="#como-funciona">Cómo funciona</a>
          <a href="#prioridad">Prioridades</a>
          <a href="#alcance">Alcance</a>
        </nav>
        <div className="row">
          <button className="btn btn-quiet btn-icon" onClick={alternar} aria-label="Cambiar tema">
            <Icon name={oscuro ? "sun" : "moon"} size={18} />
          </button>
          {user ? (
            <Link to="/panel" className="btn btn-primary">Ir al panel</Link>
          ) : (
            <>
              <Link to="/registro" className="btn btn-quiet l-hide-sm">Crear cuenta</Link>
              <Link to="/login" className="btn btn-primary">Ingresar</Link>
            </>
          )}
        </div>
      </header>

      <section className="l-hero">
        <div className="l-hero-text">
          <h1 className="l-h1">Encuentra qué corregir primero.</h1>
          <p className="l-lead">
            SecureScan revisa tus aplicaciones en entornos autorizados, ordena cada hallazgo por nivel de riesgo y entrega un reporte que un equipo de TI puede usar desde el primer día.
          </p>
          <div className="row">
            <Link to={user ? "/panel" : "/login"} className="btn btn-primary btn-lg">{user ? "Ir al panel" : "Ingresar a la plataforma"}</Link>
            <a href="#como-funciona" className="btn btn-lg">Ver cómo funciona</a>
          </div>
          <p className="small muted l-note">Proyecto Capstone de Ingeniería en Informática, Duoc UC.</p>
        </div>

        <figure className="l-hero-card scope-dark" aria-label="Ejemplo de un escaneo de puertos">
          <figcaption>
            <strong>Servidor de laboratorio</strong>
            <span className="small muted">Ejemplo de escaneo, 20 puertos revisados</span>
          </figcaption>
          <PortMapDemo hallazgos={EJEMPLO} />
          <ul className="leyenda">
            {SEVERIDADES.map((s) => (
              <li key={s}><SevMark sev={s} /> {SEV[s].label}</li>
            ))}
            <li><span className="dash-swatch" aria-hidden="true" /> Cerrado</li>
          </ul>
        </figure>
      </section>

      <section className="l-sec" id="como-funciona">
        <h2 className="l-h2">De un activo registrado a un informe, en cuatro pasos</h2>
        <ol className="l-pasos">
          {PASOS.map((p, i) => (
            <li key={p.t}>
              <span className="l-paso-n" aria-hidden="true">{i + 1}</span>
              <h3 className="h-sub">{p.t}</h3>
              <p className="small soft">{p.d}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="l-sec l-split" id="prioridad">
        <div>
          <h2 className="l-h2">Cualquiera puede ejecutar Nmap. Lo difícil es decidir qué hacer con el resultado.</h2>
          <div className="prose soft">
            <p>La salida de un escáner es una lista de puertos. SecureScan la convierte en una lista de decisiones: qué está expuesto, qué tan grave es y qué acción corresponde.</p>
            <p>La severidad sigue las bandas oficiales de CVSS v3.1, para que el criterio sea el mismo que usan los equipos de seguridad.</p>
          </div>
        </div>
        <table className="tabla l-bandas">
          <caption className="sr-only">Severidades, rangos de puntaje y acción recomendada</caption>
          <thead>
            <tr><th scope="col">Severidad</th><th scope="col">Puntaje</th><th scope="col">Qué hacer</th></tr>
          </thead>
          <tbody>
            {SEVERIDADES.map((s) => (
              <tr key={s}>
                <td><span className={`badge sevbg-${s}`}><SevMark sev={s} />{SEV[s].label}</span></td>
                <td className="num">{SEV[s].rango}</td>
                <td>{SEV[s].accion}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="l-sec" id="alcance">
        <h2 className="l-h2">Pensado para entornos autorizados</h2>
        <dl className="l-principios">
          {PRINCIPIOS.map((p) => (
            <div key={p.t}>
              <dt><Icon name={p.i} size={18} /> {p.t}</dt>
              <dd className="soft">{p.d}</dd>
            </div>
          ))}
        </dl>
      </section>

      <footer className="l-foot">
        <Logo size={24} />
        <p className="small muted">
          SecureScan · Capstone APT122 · Ingeniería en Informática, Sede San Joaquín, Duoc UC. Desarrollado por Ivan Escobar.
        </p>
      </footer>
    </div>
  );
}
