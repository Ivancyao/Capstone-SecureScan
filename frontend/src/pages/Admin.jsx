import { useEffect, useState } from "react";
import { Icon } from "../components/Icon.jsx";
import { Aviso, Avatar, Campo, Modal, PageHeader, Panel, RolBadge, Tag, useTitulo } from "../components/ui.jsx";
import { CopiarBoton, SoloAdmin } from "../components/shared.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useData } from "../context/DataContext.jsx";
import { useToast } from "../context/ToastContext.jsx";
import { fmtFecha } from "../lib/format.js";
import { ROLES } from "../lib/risk.js";
import { USE_MOCK } from "../services/index.js";

const PERMISOS = [
  ["Ver y gestionar sus propios proyectos, activos y evaluaciones", true, true, true],
  ["Generar reportes de sus proyectos", true, true, true],
  ["Ver los proyectos de otros usuarios", true, false, false],
  ["Crear cuentas y cambiar roles", true, false, false],
  ["Cambiar la configuración de escaneo y de alcance", true, false, false],
];

function CrearUsuarioModal({ abierto, onClose }) {
  const { invitarUsuario } = useData();
  const [f, setF] = useState({ nombre: "", email: "", rol: "usuario" });
  const [cargando, setCargando] = useState(false);
  const [creada, setCreada] = useState(null); // cuenta recién creada, con su contraseña temporal
  const cerrar = () => {
    setCreada(null);
    onClose();
  };
  const enviar = async (e) => {
    e.preventDefault();
    setCargando(true);
    try {
      const r = await invitarUsuario(f);
      setF({ nombre: "", email: "", rol: "usuario" });
      if (r?.password_temporal) setCreada(r);
      else onClose();
    } catch {
      /* aviso mostrado */
    } finally {
      setCargando(false);
    }
  };

  if (creada) {
    return (
      <Modal
        abierto={abierto}
        onClose={cerrar}
        titulo="Cuenta creada"
        descripcion={`Entrégale estos datos a ${creada.nombre}. La contraseña temporal solo se muestra ahora.`}
        pie={<button className="btn btn-primary" type="button" onClick={cerrar}>Listo</button>}
      >
        <div className="stack-sm">
          <div><p className="label">Correo</p><p className="mono">{creada.email}</p></div>
          <div>
            <p className="label">Contraseña temporal</p>
            <p className="mono">{creada.password_temporal} <CopiarBoton texto={creada.password_temporal} /></p>
          </div>
          <Aviso tipo="info">Pídele que la cambie al entrar, desde Perfil → Contraseña.</Aviso>
        </div>
      </Modal>
    );
  }

  return (
    <Modal
      abierto={abierto}
      onClose={cerrar}
      titulo="Crear cuenta"
      descripcion="Se generará una contraseña temporal que verás una sola vez."
      pie={
        <>
          <button className="btn" type="button" onClick={cerrar}>Cancelar</button>
          <button className="btn btn-primary" form="form-usuario" disabled={cargando}>{cargando ? "Creando…" : "Crear cuenta"}</button>
        </>
      }
    >
      <form id="form-usuario" className="form-grid" onSubmit={enviar}>
        <Campo etiqueta="Nombre completo">{(id) => <input id={id} className="input" value={f.nombre} onChange={(e) => setF({ ...f, nombre: e.target.value })} minLength={2} required />}</Campo>
        <Campo etiqueta="Correo">{(id) => <input id={id} className="input" type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required />}</Campo>
        <Campo etiqueta="Rol">
          {(id) => (
            <select id={id} className="select" value={f.rol} onChange={(e) => setF({ ...f, rol: e.target.value })}>
              {Object.entries(ROLES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          )}
        </Campo>
      </form>
    </Modal>
  );
}

export function Usuarios() {
  useTitulo("Usuarios y roles");
  const { user } = useAuth();
  const { data, cambiarRol, alternarUsuario } = useData();
  const [modal, setModal] = useState(false);

  return (
    <SoloAdmin>
      <PageHeader
        titulo="Usuarios y roles"
        descripcion="Quién puede entrar a la plataforma y qué puede hacer. Cada rol ve solo lo que le corresponde."
        acciones={<button className="btn btn-primary" onClick={() => setModal(true)}><Icon name="plus" size={16} /> Crear cuenta</button>}
      />
      {!data.capacidades.usuarios && (
        <div className="panel-gap"><Aviso tipo="warn">La gestión de usuarios aún no está disponible en el backend. Esta pantalla ya está lista para conectarse.</Aviso></div>
      )}
      <div className="panel panel-gap">
        <div className="table-wrap">
          <table className="tabla">
            <thead><tr><th>Persona</th><th>Rol</th><th>Estado</th><th>Creada</th><th /></tr></thead>
            <tbody>
              {data.usuarios.map((u) => {
                const yo = u.id === user.id;
                return (
                  <tr key={u.id}>
                    <td>
                      <div className="persona">
                        <Avatar nombre={u.nombre} size={34} />
                        <div className="celda-titulo"><span className="row-inline">{u.nombre} {yo && <Tag>Tú</Tag>}</span><span className="sub">{u.email}</span></div>
                      </div>
                    </td>
                    <td>
                      {yo ? (
                        <RolBadge rol={u.rol} />
                      ) : (
                        <select className="select select-inline" value={u.rol} onChange={(e) => cambiarRol(u.id, e.target.value).catch(() => {})} aria-label={`Rol de ${u.nombre}`}>
                          {Object.entries(ROLES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                        </select>
                      )}
                    </td>
                    <td>{u.activo === false ? <Tag tono="danger">Desactivada</Tag> : <Tag tono="ok">Activa</Tag>}</td>
                    <td className="nowrap">{fmtFecha(u.creado_en)}</td>
                    <td className="right">
                      {!yo && (
                        <button className="btn btn-sm" onClick={() => alternarUsuario(u.id, u.activo === false).catch(() => {})}>
                          {u.activo === false ? "Reactivar" : "Desactivar"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <Panel titulo="Qué puede hacer cada rol" descripcion="Los permisos se comprueban en el servidor; ocultar un botón en pantalla no basta.">
        <div className="table-wrap">
          <table className="tabla tabla-compacta matriz">
            <thead><tr><th>Permiso</th><th className="centro">Administrador</th><th className="centro">Analista</th><th className="centro">Usuario</th></tr></thead>
            <tbody>
              {PERMISOS.map(([t, ...v]) => (
                <tr key={t}>
                  <td>{t}</td>
                  {v.map((ok, i) => (
                    <td key={i} className="centro">
                      {ok ? <Icon name="check-circle" size={18} className="si" title="Permitido" /> : <span className="no" aria-label="No permitido">—</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="xs muted tabla-nota">Hoy el analista y el usuario comparten los mismos permisos. Se separarán cuando el backend distinga lectura de escritura.</p>
      </Panel>
      <CrearUsuarioModal abierto={modal} onClose={() => setModal(false)} />
    </SoloAdmin>
  );
}

const PERFILES_PUERTOS = [
  ["predeterminado", "Predeterminado: puertos 1 a 1024 y servicios comunes"],
  ["rapido", "Rápido: los 100 puertos más comunes"],
  ["completo", "Completo: puertos 1 a 65535 (lento)"],
];

export function Configuracion() {
  useTitulo("Configuración");
  const { data, guardarConfig, restablecer } = useData();
  const toast = useToast();
  const [cfg, setCfg] = useState(data.config);
  const [guardando, setGuardando] = useState(false);
  useEffect(() => setCfg(data.config), [data.config]);

  if (!cfg) {
    return (
      <SoloAdmin>
        <PageHeader titulo="Configuración" descripcion="Motores de escaneo y reglas de alcance." />
        <Aviso tipo="warn">No se pudo cargar la configuración. Verifica que el backend esté encendido y vuelve a intentar.</Aviso>
      </SoloAdmin>
    );
  }

  const sucio = JSON.stringify(cfg) !== JSON.stringify(data.config);
  const servidorPermitePublicas = cfg.alcance.publicas_permitidas_por_servidor !== false; // en el modo de ejemplo no hay candado
  const nmap = cfg.motores.nmap;
  const zap = cfg.motores.zap;
  const setZap = (k, v) => setCfg({ ...cfg, motores: { ...cfg.motores, zap: { ...zap, [k]: v } } });
  const setNmap = (k, v) => setCfg({ ...cfg, motores: { ...cfg.motores, nmap: { ...nmap, [k]: v } } });

  const guardar = async () => {
    setGuardando(true);
    try {
      await guardarConfig(cfg);
    } catch {
      /* aviso mostrado */
    } finally {
      setGuardando(false);
    }
  };

  return (
    <SoloAdmin>
      <PageHeader
        titulo="Configuración"
        descripcion="Qué herramientas se usan para evaluar y a qué direcciones se les permite escanear."
        acciones={
          <>
            <button className="btn" onClick={() => setCfg(data.config)} disabled={!sucio}>Descartar</button>
            <button className="btn btn-primary" onClick={guardar} disabled={!sucio || guardando}>{guardando ? "Guardando…" : "Guardar cambios"}</button>
          </>
        }
      />
      <div className="stack">
        <Panel titulo="Motores de escaneo">
          <ul className="motor-lista">
            <li>
              <div className="motor-cab">
                <div><strong>Nmap</strong> <Tag tono="ok">Integrado</Tag><p className="small muted">Descubre puertos abiertos y detecta el servicio y la versión de cada uno.</p></div>
                <label className="switch" aria-label="Activar Nmap"><input type="checkbox" checked={nmap.activo} onChange={(e) => setNmap("activo", e.target.checked)} /><i /></label>
              </div>
              <div className="form-2 motor-opts">
                <Campo etiqueta="Perfil de puertos">
                  {(id) => (
                    <select id={id} className="select" value={nmap.puertos} onChange={(e) => setNmap("puertos", e.target.value)}>
                      {PERFILES_PUERTOS.map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  )}
                </Campo>
                <Campo etiqueta="Tiempo máximo por escaneo (segundos)" ayuda="Si se supera, la evaluación termina como fallida.">
                  {(id) => <input id={id} className="input" type="number" min={30} max={3600} value={nmap.timeout_s} onChange={(e) => setNmap("timeout_s", Number(e.target.value))} />}
                </Campo>
                <label className="check"><input type="checkbox" checked={nmap.detectar_versiones} onChange={(e) => setNmap("detectar_versiones", e.target.checked)} /> <span>Detectar versiones de servicio (más lento, más información)</span></label>
              </div>
            </li>
            <li>
              <div className="motor-cab">
                <div>
                  <strong>OWASP ZAP</strong>{" "}
                  {zap.disponible === true ? <Tag tono="ok">Integrado</Tag> : zap.disponible === false ? <Tag tono="warn">No configurado</Tag> : <Tag tono="warn">Planificado</Tag>}
                  <p className="small muted">Analiza la aplicación web en busca de vulnerabilidades del OWASP Top 10: explora el sitio y revisa cabeceras, cookies y fallos comunes.</p>
                  {zap.disponible === false && <p className="small muted">El servidor no tiene ZAP conectado (falta <span className="mono">ZAP_URL</span>). Levanta el servicio <span className="mono">zap</span> del docker-compose.</p>}
                </div>
                <label className="switch" aria-label="Activar OWASP ZAP"><input type="checkbox" disabled={zap.disponible !== true} checked={!!zap.activo} onChange={(e) => setZap("activo", e.target.checked)} /><i /></label>
              </div>
              {zap.disponible === true && zap.activo && (
                <div className="form-2 motor-opts">
                  <Campo etiqueta="Tiempo máximo del análisis web (segundos)" ayuda="Si se supera, la evaluación termina igual con los resultados de Nmap y una advertencia.">
                    {(id) => <input id={id} className="input" type="number" min={60} max={7200} value={zap.timeout_s} onChange={(e) => setZap("timeout_s", Number(e.target.value))} />}
                  </Campo>
                  <label className="check"><input type="checkbox" checked={!!zap.escaneo_activo} onChange={(e) => setZap("escaneo_activo", e.target.checked)} /> <span>Escaneo activo (más profundo, pero envía ataques de prueba al objetivo y tarda más)</span></label>
                  {zap.escaneo_activo && <Aviso tipo="warn">El escaneo activo puede alterar datos del sistema evaluado. Úsalo solo en entornos de laboratorio o con autorización escrita.</Aviso>}
                </div>
              )}
            </li>
            <li>
              <div className="motor-cab">
                <div><strong>Nikto</strong> <Tag>Fuera de alcance</Tag><p className="small muted">Queda como posible extensión futura por limitaciones de tiempo.</p></div>
                <label className="switch" aria-label="Activar Nikto"><input type="checkbox" disabled /><i /></label>
              </div>
            </li>
          </ul>
        </Panel>

        <Panel titulo="Alcance de los escaneos" descripcion="Evita que la plataforma se use contra sistemas ajenos.">
          <div className="stack-sm">
            <div className="motor-cab">
              <div>
                <strong>Permitir direcciones públicas</strong>
                <p className="small muted">Desactivado por defecto. Actívalo solo si tienes autorización escrita para evaluar esos sistemas.</p>
                {!servidorPermitePublicas && (
                  <p className="small muted">El servidor lo mantiene bloqueado (<span className="mono">ALLOW_PUBLIC_SCANS=false</span>). Quien administra el servidor debe habilitarlo primero.</p>
                )}
              </div>
              <label className="switch" aria-label="Permitir direcciones públicas">
                <input type="checkbox" disabled={!servidorPermitePublicas} checked={cfg.alcance.permitir_publicas} onChange={(e) => setCfg({ ...cfg, alcance: { ...cfg.alcance, permitir_publicas: e.target.checked } })} /><i />
              </label>
            </div>
            {cfg.alcance.permitir_publicas && <Aviso tipo="warn">Escanear sistemas sin autorización puede ser ilegal. Asegúrate de contar con permiso por escrito.</Aviso>}
            <div>
              <p className="label">Rangos permitidos</p>
              <ul className="chips chips-rangos">
                {cfg.alcance.rangos.map((r) => <li key={r} className="tag mono">{r}</li>)}
              </ul>
              <p className="hint">Redes privadas, loopback y link-local. La dirección del objetivo se resuelve una sola vez y se valida antes de escanear.</p>
            </div>
          </div>
        </Panel>

        <Panel titulo="Datos">
          <div className="stack-sm">
            <Campo etiqueta="Conservar el historial de evaluaciones">
              {(id) => (
                <select id={id} className="select select-corto" value={cfg.retencion_dias} onChange={(e) => setCfg({ ...cfg, retencion_dias: Number(e.target.value) })}>
                  <option value={90}>90 días</option><option value={180}>180 días</option><option value={365}>1 año</option><option value={0}>Sin límite</option>
                </select>
              )}
            </Campo>
            {USE_MOCK && (
              <div className="row-between zona-demo">
                <div><strong>Datos de ejemplo</strong><p className="small muted">Vuelve al estado inicial de la demostración y borra lo que hayas creado.</p></div>
                <button className="btn" onClick={() => { if (window.confirm("¿Restablecer los datos de ejemplo?")) restablecer().then(() => toast.info("Datos restablecidos")).catch(() => {}); }}>Restablecer</button>
              </div>
            )}
          </div>
        </Panel>
      </div>
    </SoloAdmin>
  );
}
