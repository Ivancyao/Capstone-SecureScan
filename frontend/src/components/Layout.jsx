import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { Icon } from "./Icon.jsx";
import { Avatar, ErrorNote, Logo, RolBadge, Spinner } from "./ui.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useData } from "../context/DataContext.jsx";
import { useTheme } from "../context/ThemeContext.jsx";
import { USE_MOCK } from "../services/index.js";

function Item({ to, icono, texto, badge, tono, fin }) {
  return (
    <NavLink to={to} end={fin} className={({ isActive }) => `nav-item ${isActive ? "on" : ""}`}>
      <Icon name={icono} size={18} />
      <span>{texto}</span>
      {badge ? <b className={`nav-badge ${tono || ""} num`}>{badge}</b> : null}
    </NavLink>
  );
}

export function Layout() {
  const { user, salir } = useAuth();
  const { data, error, cargando, refrescar } = useData();
  const { oscuro, alternar } = useTheme();
  const [abierto, setAbierto] = useState(false);
  const [q, setQ] = useState("");
  const loc = useLocation();
  const nav = useNavigate();

  useEffect(() => {
    setAbierto(false);
    window.scrollTo(0, 0);
  }, [loc.pathname]);

  const buscar = (e) => {
    e.preventDefault();
    nav(`/hallazgos${q.trim() ? `?q=${encodeURIComponent(q.trim())}` : ""}`);
    setQ("");
  };

  const criticos = data?.conteoGlobal.critica || 0;
  const enCurso = data?.enCurso.length || 0;
  const esAdmin = user?.rol === "admin";

  return (
    <div className="shell">
      <a href="#contenido" className="skip">Saltar al contenido</a>
      <aside className={`sidebar ${abierto ? "abierto" : ""}`} aria-label="Navegación principal">
        <div className="sidebar-top">
          <NavLink to="/panel" className="sidebar-logo" aria-label="SecureScan, ir al panel">
            <Logo claro />
          </NavLink>
          <button className="btn btn-quiet btn-icon btn-sm sidebar-x" onClick={() => setAbierto(false)} aria-label="Cerrar menú">
            <Icon name="x" size={18} />
          </button>
        </div>

        <nav className="nav">
          <Item to="/panel" icono="dashboard" texto="Panel" />
          <p className="nav-group">Análisis</p>
          <Item to="/proyectos" icono="folder" texto="Proyectos" />
          <Item to="/activos" icono="server" texto="Activos" />
          <Item to="/evaluaciones" icono="radar" texto="Evaluaciones" badge={enCurso || null} tono="vivo" />
          <Item to="/hallazgos" icono="alert" texto="Hallazgos" badge={criticos || null} tono="crit" />
          <p className="nav-group">Salida</p>
          <Item to="/reportes" icono="file" texto="Reportes" />
          {esAdmin && (
            <>
              <p className="nav-group">Administración</p>
              <Item to="/usuarios" icono="users" texto="Usuarios y roles" />
              <Item to="/configuracion" icono="sliders" texto="Configuración" />
            </>
          )}
        </nav>

        <div className="sidebar-bottom">
          <Item to="/ayuda" icono="help" texto="Ayuda y glosario" />
          <div className="usercard">
            <NavLink to="/perfil" className="usercard-main" aria-label="Mi perfil">
              <Avatar nombre={user?.nombre} size={34} />
              <span>
                <strong>{user?.nombre}</strong>
                <RolBadge rol={user?.rol} />
              </span>
            </NavLink>
            <button className="btn btn-quiet btn-icon btn-sm" onClick={salir} aria-label="Cerrar sesión" title="Cerrar sesión">
              <Icon name="logout" size={17} />
            </button>
          </div>
        </div>
      </aside>
      {abierto && <div className="scrim" onClick={() => setAbierto(false)} />}

      <div className="main">
        <header className="topbar">
          <button className="btn btn-quiet btn-icon menu-btn" onClick={() => setAbierto(true)} aria-label="Abrir menú">
            <Icon name="menu" size={20} />
          </button>
          <form className="search" onSubmit={buscar} role="search">
            <Icon name="search" size={16} />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar hallazgos, puertos o servicios" aria-label="Buscar hallazgos" />
          </form>
          <div className="topbar-right">
            {USE_MOCK && (
              <span className="demo-chip" title="Los datos son de ejemplo y se guardan solo en este navegador.">
                <i aria-hidden="true" /> Modo demostración
              </span>
            )}
            <button className="btn btn-quiet btn-icon" onClick={alternar} aria-label={oscuro ? "Cambiar a tema claro" : "Cambiar a tema oscuro"} title="Cambiar tema">
              <Icon name={oscuro ? "sun" : "moon"} size={18} />
            </button>
          </div>
        </header>

        <main id="contenido" className="page" tabIndex={-1}>
          {error && !data ? (
            <ErrorNote accion={<button className="btn btn-sm" onClick={refrescar}>Reintentar</button>}>
              <strong>No se pudieron cargar los datos.</strong> {error}
            </ErrorNote>
          ) : cargando || !data ? (
            <Spinner texto="Cargando tus datos…" />
          ) : (
            <Outlet />
          )}
        </main>
      </div>
    </div>
  );
}
