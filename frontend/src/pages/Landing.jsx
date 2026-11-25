// Portada pública de SecureScan (ruta "/"). Es lo primero que ve alguien que entra sin sesión.
// No llama a la API: todo es contenido fijo, así que se ve igual con backend apagado.
// Desde acá se va a /login, /registro o, si ya hay sesión, directo a /panel.
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Logo, SevMark, useTitulo } from "../components/ui.jsx";
import { PortMapDemo } from "../components/PortMap.jsx";
import { SEV, SEVERIDADES, hallazgoDesdePuerto } from "../lib/risk.js";
import { useAuth } from "../context/AuthContext.jsx";
import { useTheme } from "../context/ThemeContext.jsx";

// Servidor de ejemplo para la portada: se clasifica con las mismas reglas del motor de riesgo.
// Ojo: estos datos no vienen del backend. Son puertos inventados para mostrar el mapa de la portada.
const EJEMPLO = [
  [21, "ftp", "vsftpd", "2.3.4"], [22, "ssh", "OpenSSH", "7.4"], [23, "telnet"], [80, "http", "Apache httpd", "2.4.7"],
  [443, "https", "nginx", "1.24.0"], [445, "microsoft-ds", "Samba smbd"], [3306, "mysql", "MySQL", "5.5.62"], [3389, "ms-wbt-server"], [6379, "redis", "Redis"],
].map(([puerto, servicio, producto = "", version = ""], indice) => ({ ...hallazgoDesdePuerto({ puerto, servicio, producto, version }), id: `ej-${indice}` }));

// Los cuatro pasos de la sección "Cómo funciona". t = título del paso, d = descripción.
const PASOS = [
  { t: "Registra un activo", d: "Indica la aplicación o servidor que quieres revisar. Debe ser tuyo o contar con autorización." },
  { t: "Lanza la evaluación", d: "SecureScan revisa los puertos y servicios expuestos en segundo plano. Tú sigues trabajando." },
  { t: "Clasifica el riesgo", d: "Cada hallazgo recibe una severidad, un puntaje CVSS estimado y su categoría OWASP Top 10." },
  { t: "Corrige y reporta", d: "Marca lo corregido, vuelve a evaluar para confirmarlo y descarga un informe para tu equipo." },
];

// Las reglas de seguridad que quise destacar en la portada. i = nombre del ícono, t = título, d = descripción.
const PRINCIPIOS = [
  { i: "lock", t: "Solo redes privadas", d: "El escáner rechaza direcciones públicas. Evaluar sistemas ajenos sin permiso no es una opción." },
  { i: "users", t: "Cada rol ve lo suyo", d: "Cada usuario ve solo sus proyectos. El administrador, además, gestiona cuentas y configuración." },
  { i: "shield", t: "Sin comandos del usuario", d: "Las herramientas se ejecutan con parámetros controlados, nunca con texto escrito por el usuario." },
  { i: "info", t: "El puntaje es una estimación", d: "El CVSS se calcula por reglas según el servicio expuesto, y la plataforma lo indica en cada reporte." },
];

// Componente de la portada. Usa el contexto de sesión (para cambiar los botones) y el de tema (claro u oscuro).
export default function Landing() {
  useTitulo("Evalúa y prioriza vulnerabilidades web");
  // Si ya hay usuario logueado, los botones dicen "Ir al panel" en vez de "Ingresar".
  const { user } = useAuth();
  const { oscuro, alternar } = useTheme();
  return (
    <div className="landing">
      {/* Barra superior: logo, enlaces internos a cada sección, botón de tema y botones de sesión. */}
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

      {/* Zona principal: mensaje, botones y una tarjeta con un escaneo de ejemplo. */}
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

        {/* Tarjeta con el mapa de puertos de ejemplo (EJEMPLO) y su leyenda de severidades. */}
        <figure className="l-hero-card scope-dark" aria-label="Ejemplo de un escaneo de puertos">
          <figcaption>
            <span className="l-card-top">
              <strong>Servidor de laboratorio</strong>
              <span className="l-live"><i aria-hidden="true" /> Ejemplo</span>
            </span>
            <span className="small muted">192.168.1.20 · 20 puertos revisados</span>
          </figcaption>
          <PortMapDemo hallazgos={EJEMPLO} />
          <ul className="leyenda">
            {SEVERIDADES.map((severidad) => (
              <li key={severidad}><SevMark sev={severidad} /> {SEV[severidad].label}</li>
            ))}
            <li><span className="dash-swatch" aria-hidden="true" /> Cerrado</li>
          </ul>
        </figure>
      </section>

      {/* Los cuatro pasos, recorriendo PASOS. El número sale del índice del arreglo. */}
      <section className="l-sec" id="como-funciona">
        <h2 className="l-h2">De un activo registrado a un informe, en cuatro pasos</h2>
        <ol className="l-pasos">
          {PASOS.map((paso, indice) => (
            <li key={paso.t}>
              <span className="l-paso-n" aria-hidden="true">{String(indice + 1).padStart(2, "0")}</span>
              <h3 className="h-sub">{paso.t}</h3>
              <p className="small soft">{paso.d}</p>
            </li>
          ))}
        </ol>
      </section>

      {/*
        Explica cómo clasifico el riesgo. La tabla se arma con las mismas bandas CVSS v3.1 que usa el backend (SEV en
        lib/risk.js).
      */}
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
            {SEVERIDADES.map((severidad) => (
              <tr key={severidad}>
                <td><span className={`badge sevbg-${severidad}`}><SevMark sev={severidad} />{SEV[severidad].label}</span></td>
                <td className="num">{SEV[severidad].rango}</td>
                <td>{SEV[severidad].accion}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/*
        Principios de seguridad. Si me preguntan: la plataforma solo escanea redes privadas y nunca ejecuta texto
        escrito por el usuario como comando.
      */}
      <section className="l-sec" id="alcance">
        <h2 className="l-h2">Pensado para entornos autorizados</h2>
        <dl className="l-principios">
          {PRINCIPIOS.map((principio) => (
            <div key={principio.t}>
              <dt><Icon name={principio.i} size={18} /> {principio.t}</dt>
              <dd className="soft">{principio.d}</dd>
            </div>
          ))}
        </dl>
      </section>

      {/* Pie con los créditos del proyecto. */}
      <footer className="l-foot">
        <Logo size={24} />
        <p className="small muted">
          SecureScan · Capstone APT122 · Ingeniería en Informática, Sede San Joaquín, Duoc UC. Desarrollado por Ivan Escobar.
        </p>
      </footer>
    </div>
  );
}
