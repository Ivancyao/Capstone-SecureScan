import { useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { ErrorNote, Logo, SevMark, useTitulo } from "../components/ui.jsx";
import { PortMap } from "../components/PortMap.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useToast } from "../context/ToastContext.jsx";
import { USE_MOCK } from "../services/index.js";
import { SEV, SEVERIDADES, hallazgoDesdePuerto } from "../lib/risk.js";

// Puertos de ejemplo que se muestran en el panel decorativo de la izquierda (es solo visual).
const MUESTRA = [[22, "ssh"], [80, "http"], [445, "microsoft-ds"], [3306, "mysql"], [5432, "postgresql"], [8080, "http-proxy"]].map(([puerto, servicio], indice) => ({
  ...hallazgoDesdePuerto({ puerto, servicio, producto: "", version: "" }),
  id: `m${indice}`,
}));

// Marco común de las pantallas de login y registro: panel de marca a un lado y el formulario al otro.
function Marco({ children, lado }) {
  return (
    <div className="auth">
      <aside className="auth-lado scope-dark">
        <Link to="/" aria-label="SecureScan, inicio"><Logo claro /></Link>
        <div className="auth-lado-medio">
          <h2 className="auth-claim">{lado.titulo}</h2>
          <p className="soft">{lado.texto}</p>
          <div className="auth-mapa" aria-hidden="true">
            <PortMap hallazgos={MUESTRA} compacto />
          </div>
          <ul className="leyenda">
            {SEVERIDADES.slice(0, 4).map((severidad) => (
              <li key={severidad}><SevMark sev={severidad} /> {SEV[severidad].label}</li>
            ))}
          </ul>
        </div>
        <p className="xs muted">Capstone APT122 · Duoc UC</p>
      </aside>
      <main className="auth-form-wrap">
        <div className="auth-form">{children}</div>
      </main>
    </div>
  );
}

// Campo de contraseña con botón para mostrar u ocultar lo que escribo.
function CampoPassword({ id, valor, onChange, autoComplete, etiqueta = "Contraseña", invalido }) {
  const [ver, setVer] = useState(false);
  return (
    <div className="field">
      <label htmlFor={id}>{etiqueta}</label>
      <div className="input-icon">
        <input id={id} className={`input ${invalido ? "is-invalid" : ""}`} type={ver ? "text" : "password"} value={valor} onChange={onChange} autoComplete={autoComplete} required />
        <button type="button" className="btn btn-quiet btn-icon btn-sm" onClick={() => setVer((visible) => !visible)} aria-label={ver ? "Ocultar contraseña" : "Mostrar contraseña"} aria-pressed={ver}>
          <Icon name="eye" size={16} />
        </button>
      </div>
    </div>
  );
}

// Cuentas de ejemplo que solo aparecen en el modo demostración (USE_MOCK). Con el backend real no existen.
const DEMO = [
  { email: "admin@securescan.local", rotulo: "Administrador", nota: "Ve todo y gestiona usuarios" },
  { email: "analista@securescan.local", rotulo: "Analista", nota: "Solo sus proyectos" },
  { email: "usuario@securescan.local", rotulo: "Usuario nuevo", nota: "Sin datos, para ver estados vacíos" },
];

// Pantalla de ingreso. Si ya hay sesión, redirige directo; si venía de otra página, vuelve a ella después de entrar (destino).
export function Login() {
  useTitulo("Ingresar");
  const { user, login } = useAuth();
  const navegar = useNavigate();
  const ubicacion = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [cargando, setCargando] = useState(false);
  const destino = ubicacion.state?.desde || "/panel";

  if (user) return <Navigate to={destino} replace />;

  // Llama al login y, si el backend responde error (por ejemplo 401 o 429 de intentos fallidos), muestro ese mismo mensaje.
  const entrar = async (correo, clave) => {
    setError("");
    setCargando(true);
    try {
      await login(correo, clave);
      navegar(destino, { replace: true });
    } catch (problema) {
      setError(problema.message);
    } finally {
      setCargando(false);
    }
  };

  return (
    <Marco lado={{ titulo: "Cada puerto abierto es una decisión pendiente.", texto: "Ingresa para ver el estado de tus activos y qué corregir primero." }}>
      <h1 className="h-title">Ingresar a SecureScan</h1>
      <p className="soft auth-sub">Usa la cuenta con la que te registraste.</p>
      {ubicacion.state?.registrado && <div className="notice notice-ok" role="status"><Icon name="check-circle" size={18} /><div>Cuenta creada. Ya puedes ingresar.</div></div>}
      <form
        className="form-grid"
        onSubmit={(evento) => {
          evento.preventDefault();
          entrar(email, password);
        }}
      >
        <div className="field">
          <label htmlFor="email">Correo</label>
          <input id="email" className="input" type="email" value={email} onChange={(evento) => setEmail(evento.target.value)} autoComplete="username" placeholder="nombre@institucion.cl" required />
        </div>
        <CampoPassword id="password" valor={password} onChange={(evento) => setPassword(evento.target.value)} autoComplete="current-password" />
        {error && <ErrorNote>{error}</ErrorNote>}
        <button className="btn btn-primary btn-lg" disabled={cargando}>{cargando ? "Ingresando…" : "Ingresar"}</button>
      </form>
      <p className="small soft auth-alt">
        ¿Aún no tienes cuenta? <Link to="/registro">Crear cuenta</Link>
      </p>

      {USE_MOCK && (
        <div className="demo-box">
          <p className="small"><strong>Modo demostración.</strong> Entra con una cuenta de ejemplo para ver cómo cambia la plataforma según el rol.</p>
          <div className="demo-btns">
            {DEMO.map((cuenta) => (
              <button key={cuenta.email} type="button" className="demo-btn" onClick={() => entrar(cuenta.email, "Demo1234!")} disabled={cargando}>
                <strong>{cuenta.rotulo}</strong>
                <span>{cuenta.nota}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </Marco>
  );
}

// Pantalla de registro. Valido en el navegador (mínimo 8 caracteres y que las contraseñas coincidan), pero igual el backend vuelve a validar.
export function Registro() {
  useTitulo("Crear cuenta");
  const { user, registrar } = useAuth();
  const navegar = useNavigate();
  const toast = useToast();
  const [formulario, setFormulario] = useState({ nombre: "", email: "", password: "", repetir: "" });
  const [error, setError] = useState("");
  const [cargando, setCargando] = useState(false);
  if (user) return <Navigate to="/panel" replace />;

  const set = (campo) => (evento) => setFormulario((anterior) => ({ ...anterior, [campo]: evento.target.value }));
  const largo = formulario.password.length >= 8;
  const coincide = formulario.password.length > 0 && formulario.password === formulario.repetir;

  // Si todo sale bien, aviso y mando al login con un mensaje de cuenta creada.
  const enviar = async (evento) => {
    evento.preventDefault();
    setError("");
    if (!largo) return setError("La contraseña debe tener al menos 8 caracteres.");
    if (!coincide) return setError("Las contraseñas no coinciden.");
    setCargando(true);
    try {
      await registrar({ nombre: formulario.nombre, email: formulario.email, password: formulario.password });
      toast.ok("Cuenta creada");
      navegar("/login", { state: { registrado: true } });
    } catch (err) {
      setError(err.message);
    } finally {
      setCargando(false);
    }
  };

  return (
    <Marco lado={{ titulo: "Empieza por registrar un activo y evalúalo.", texto: "Crea tu cuenta y organiza tus aplicaciones en proyectos." }}>
      <h1 className="h-title">Crear cuenta</h1>
      <p className="soft auth-sub">La primera cuenta del sistema es administradora. Las demás empiezan como usuario.</p>
      <form className="form-grid" onSubmit={enviar}>
        <div className="field">
          <label htmlFor="nombre">Nombre completo</label>
          <input id="nombre" className="input" value={formulario.nombre} onChange={set("nombre")} minLength={2} autoComplete="name" required />
        </div>
        <div className="field">
          <label htmlFor="email">Correo</label>
          <input id="email" className="input" type="email" value={formulario.email} onChange={set("email")} autoComplete="email" required />
        </div>
        <CampoPassword id="pw" valor={formulario.password} onChange={set("password")} autoComplete="new-password" />
        <ul className="reglas small">
          <li className={largo ? "ok" : ""}><Icon name={largo ? "check-circle" : "info"} size={15} /> Al menos 8 caracteres</li>
        </ul>
        <CampoPassword id="pw2" etiqueta="Repite la contraseña" valor={formulario.repetir} onChange={set("repetir")} autoComplete="new-password" invalido={formulario.repetir && !coincide} />
        {error && <ErrorNote>{error}</ErrorNote>}
        <button className="btn btn-primary btn-lg" disabled={cargando}>{cargando ? "Creando cuenta…" : "Crear cuenta"}</button>
      </form>
      <p className="small soft auth-alt">
        ¿Ya tienes cuenta? <Link to="/login">Ingresar</Link>
      </p>
    </Marco>
  );
}
