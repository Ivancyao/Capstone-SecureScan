import { useEffect, useState } from "react";
import { useLocation, Link } from "react-router-dom";
import { Icon } from "../components/Icon.jsx";
import { Aviso, Avatar, Campo, PageHeader, Panel, RolBadge, Segmented, SevBadge, useTitulo } from "../components/ui.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useTheme } from "../context/ThemeContext.jsx";
import { useToast } from "../context/ToastContext.jsx";
import { api } from "../services/index.js";
import { OWASP, SEV, SEVERIDADES } from "../lib/risk.js";

export function Perfil() {
  useTitulo("Mi perfil");
  const { user, setUser, salir } = useAuth();
  const { preferencia, elegir } = useTheme();
  const toast = useToast();
  const [nombre, setNombre] = useState(user.nombre);
  const [contrasenas, setContrasenas] = useState({ actual: "", nueva: "", repetir: "" });
  const [errPw, setErrPw] = useState("");
  const [guardando, setGuardando] = useState(false);

  const guardarNombre = async (evento) => {
    evento.preventDefault();
    setGuardando(true);
    try {
      const usuarioActualizado = await api.actualizarPerfil({ nombre });
      setUser(usuarioActualizado);
      toast.ok("Perfil actualizado");
    } catch (err) {
      toast.error("No se pudo actualizar", err.message);
    } finally {
      setGuardando(false);
    }
  };

  const cambiarPw = async (evento) => {
    evento.preventDefault();
    setErrPw("");
    if (contrasenas.nueva.length < 8) return setErrPw("La nueva contraseña debe tener al menos 8 caracteres.");
    if (contrasenas.nueva !== contrasenas.repetir) return setErrPw("Las contraseñas nuevas no coinciden.");
    try {
      await api.cambiarPassword({ actual: contrasenas.actual, nueva: contrasenas.nueva });
      setContrasenas({ actual: "", nueva: "", repetir: "" });
      toast.ok("Contraseña actualizada");
    } catch (err) {
      setErrPw(err.message);
    }
  };

  return (
    <>
      <PageHeader titulo="Mi perfil" descripcion="Tus datos, tu contraseña y cómo prefieres ver la plataforma." />
      <div className="perfil-grid">
        <div className="stack">
          <Panel titulo="Datos personales">
            <form className="form-grid" onSubmit={guardarNombre}>
              <div className="row perfil-cab">
                <Avatar nombre={user.nombre} size={52} />
                <div><strong>{user.nombre}</strong><div><RolBadge rol={user.rol} /></div></div>
              </div>
              <Campo etiqueta="Nombre">{(id) => <input id={id} className="input" value={nombre} onChange={(evento) => setNombre(evento.target.value)} minLength={2} required />}</Campo>
              <Campo etiqueta="Correo" ayuda="El correo no se puede cambiar.">{(id) => <input id={id} className="input" value={user.email} readOnly disabled />}</Campo>
              <div><button className="btn btn-primary" disabled={guardando || nombre.trim() === user.nombre}>Guardar cambios</button></div>
            </form>
          </Panel>

          <Panel titulo="Cambiar contraseña">
            <form className="form-grid" onSubmit={cambiarPw}>
              <Campo etiqueta="Contraseña actual">{(id) => <input id={id} className="input" type="password" autoComplete="current-password" value={contrasenas.actual} onChange={(evento) => setContrasenas({ ...contrasenas, actual: evento.target.value })} required />}</Campo>
              <div className="form-2">
                <Campo etiqueta="Nueva contraseña" ayuda="Al menos 8 caracteres.">{(id) => <input id={id} className="input" type="password" autoComplete="new-password" value={contrasenas.nueva} onChange={(evento) => setContrasenas({ ...contrasenas, nueva: evento.target.value })} required />}</Campo>
                <Campo etiqueta="Repite la nueva">{(id) => <input id={id} className="input" type="password" autoComplete="new-password" value={contrasenas.repetir} onChange={(evento) => setContrasenas({ ...contrasenas, repetir: evento.target.value })} required />}</Campo>
              </div>
              {errPw && <p className="field-error" role="alert">{errPw}</p>}
              <div><button className="btn btn-primary">Actualizar contraseña</button></div>
            </form>
          </Panel>
        </div>

        <div className="stack">
          <Panel titulo="Apariencia">
            <div className="stack-sm">
              <p className="small muted">El tema “Sistema” sigue el modo claro u oscuro de tu equipo.</p>
              <Segmented etiqueta="Tema" valor={preferencia} onChange={elegir} opciones={[{ valor: "claro", etiqueta: "Claro" }, { valor: "oscuro", etiqueta: "Oscuro" }, { valor: "sistema", etiqueta: "Sistema" }]} />
            </div>
          </Panel>
          <Panel titulo="Sesión">
            <div className="stack-sm">
              <p className="small muted">Cierra la sesión si compartes este equipo.</p>
              <div><button className="btn" onClick={salir}><Icon name="logout" size={16} /> Cerrar sesión</button></div>
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

// ---------- Ayuda ----------
const IMPLEMENTADAS = { A02: "Hoy lo detecta Nmap (FTP, Telnet sin cifrar).", A05: "Hoy lo detecta Nmap (servicios y puertos expuestos)." };

const GLOSARIO = [
  ["Activo", "La aplicación o el servidor que se registra para evaluarlo."],
  ["Evaluación", "Una ejecución del escáner sobre un activo, con su fecha, estado y resultados."],
  ["Hallazgo", "Un puerto, servicio o configuración expuesta que se detectó en una evaluación."],
  ["Puerto abierto", "Una “puerta” de red por la que un servicio acepta conexiones. Cuantas más abiertas, mayor superficie de ataque."],
  ["CVSS", "Puntaje de 0 a 10 que mide la gravedad de una vulnerabilidad. En SecureScan es una estimación por reglas."],
  ["OWASP Top 10", "Lista de las diez categorías de fallas más comunes y graves en aplicaciones web."],
  ["Falso positivo", "Un hallazgo que parece un problema pero no lo es en tu contexto. Revísalo antes de descartarlo."],
];

const FAQ = [
  ["¿Puedo evaluar cualquier sitio web?", "No. Solo activos propios o con autorización escrita, y por política solo en redes privadas. Evaluar sistemas ajenos sin permiso puede ser ilegal."],
  ["¿Por qué una evaluación puede fallar?", "Porque el objetivo no responde, porque se superó el tiempo máximo o porque la dirección no está en un rango permitido. El detalle aparece en la evaluación."],
  ["¿El puntaje CVSS es exacto?", "No. Se estima según el tipo de servicio expuesto. Sirve para ordenar qué corregir primero, no para certificar un riesgo."],
  ["¿Quién puede ver mis proyectos?", "Solo tú y los administradores. Si intentas abrir el proyecto de otra persona, la plataforma responde como si no existiera."],
  ["¿Cómo confirmo que corregí algo?", "Marca el hallazgo como corregido y vuelve a evaluar el activo. Si ya no aparece, quedó resuelto."],
];

export function Ayuda() {
  useTitulo("Ayuda y glosario");
  const { hash } = useLocation();
  useEffect(() => {
    if (hash) document.getElementById(hash.slice(1))?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [hash]);

  return (
    <>
      <PageHeader titulo="Ayuda y glosario" descripcion="Cómo usar SecureScan, cómo se calcula la severidad y qué significan los términos." />
      <div className="stack">
        <Panel titulo="Cómo usar SecureScan">
          <ol className="pasos pasos-sep">
            {[
              ["Crea un proyecto", "Agrupa los activos de una organización o de un contexto de trabajo.", "/proyectos?nuevo=1", "Crear proyecto"],
              ["Registra un activo", "Indica el nombre y la dirección de la aplicación o servidor, que debe ser tuyo o estar autorizado.", "/activos", "Ver activos"],
              ["Lanza una evaluación", "Corre en segundo plano. Puedes ver el avance en vivo o volver más tarde.", "/evaluaciones/nueva", "Nueva evaluación"],
              ["Corrige y vuelve a evaluar", "Empieza por lo más grave, marca lo corregido y confirma con otra evaluación.", "/hallazgos", "Ver hallazgos"],
              ["Genera el reporte", "Reúne los resultados en un informe para tu equipo o tu cliente.", "/reportes", "Ver reportes"],
            ].map(([titulo, descripcion, to, textoEnlace], indice) => (
              <li key={titulo} className="paso">
                <span className="paso-dot">{indice + 1}</span>
                <div><strong>{titulo}</strong><p className="small muted">{descripcion}</p> <Link className="small" to={to}>{textoEnlace}</Link></div>
              </li>
            ))}
          </ol>
        </Panel>

        <Panel titulo="Cómo se calcula la severidad" id="severidad" descripcion="Bandas oficiales de CVSS v3.1">
          <div className="table-wrap">
            <table className="tabla tabla-compacta">
              <thead><tr><th>Severidad</th><th>Puntaje CVSS</th><th>Qué hacer</th></tr></thead>
              <tbody>
                {SEVERIDADES.map((severidad) => <tr key={severidad}><td><SevBadge sev={severidad} /></td><td className="num">{SEV[severidad].rango}</td><td>{SEV[severidad].accion}</td></tr>)}
              </tbody>
            </table>
          </div>
          <div className="panel-actions-top"><Aviso>El puntaje de SecureScan se estima por reglas según el servicio expuesto (por ejemplo, Telnet 7,5 o SSH 3,7). No es un cálculo vectorial completo.</Aviso></div>
        </Panel>

        <Panel titulo="OWASP Top 10 (2021)" id="owasp" descripcion="Las diez categorías, y cuáles detecta hoy la plataforma">
          <ul className="owasp-lista">
            {Object.entries(OWASP).map(([codigo, nombre]) => (
              <li key={codigo}>
                <b>{codigo}</b>
                <span>{nombre}</span>
                <span className="small muted">{IMPLEMENTADAS[codigo] || ""}</span>
              </li>
            ))}
          </ul>
        </Panel>

        <div className="grid-2">
          <Panel titulo="Glosario">
            <dl className="glosario">
              {GLOSARIO.map(([termino, definicion]) => <div key={termino}><dt>{termino}</dt><dd className="soft">{definicion}</dd></div>)}
            </dl>
          </Panel>
          <Panel titulo="Preguntas frecuentes">
            <div className="faq">
              {FAQ.map(([pregunta, respuesta]) => (
                <details key={pregunta}>
                  <summary>{pregunta}<Icon name="chevron-down" size={16} /></summary>
                  <p className="small soft">{respuesta}</p>
                </details>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
