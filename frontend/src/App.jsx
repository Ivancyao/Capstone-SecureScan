import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./context/AuthContext.jsx";
import { DataProvider } from "./context/DataContext.jsx";
import { Layout } from "./components/Layout.jsx";
import { Logo, Spinner, useTitulo } from "./components/ui.jsx";

import Landing from "./pages/Landing.jsx";
import { Login, Registro } from "./pages/Auth.jsx";
import Panel from "./pages/Panel.jsx";
import { Proyectos, ProyectoDetalle } from "./pages/Proyectos.jsx";
import { Activos, ActivoDetalle } from "./pages/Activos.jsx";
import { Evaluaciones, NuevaEvaluacion, EvaluacionDetalle } from "./pages/Evaluaciones.jsx";
import { Hallazgos, HallazgoDetalle } from "./pages/Hallazgos.jsx";
import { Reportes, ReporteVista } from "./pages/Reportes.jsx";
import { Usuarios, Configuracion } from "./pages/Admin.jsx";
import { Perfil, Ayuda } from "./pages/Cuenta.jsx";

function RequireAuth({ children }) {
  const { user, cargando, salidaManual } = useAuth();
  const loc = useLocation();
  if (cargando) return <Spinner texto="Cargando…" />;
  if (!user) return <Navigate to="/login" state={salidaManual() ? undefined : { desde: loc.pathname + loc.search }} replace />;
  return children;
}

function NotFound() {
  useTitulo("Página no encontrada");
  const { user } = useAuth();
  return (
    <div className="notfound">
      <Logo />
      <h1 className="h-title">No encontramos esta página</h1>
      <p className="soft">La dirección no existe o el recurso pertenece a otro proyecto. Revisa el enlace o vuelve al inicio.</p>
      <Link to={user ? "/panel" : "/"} className="btn btn-primary">{user ? "Ir al panel" : "Volver al inicio"}</Link>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/registro" element={<Registro />} />

      <Route
        element={
          <RequireAuth>
            <DataProvider>
              <Layout />
            </DataProvider>
          </RequireAuth>
        }
      >
        <Route path="/panel" element={<Panel />} />
        <Route path="/proyectos" element={<Proyectos />} />
        <Route path="/proyectos/:id" element={<ProyectoDetalle />} />
        <Route path="/activos" element={<Activos />} />
        <Route path="/activos/:id" element={<ActivoDetalle />} />
        <Route path="/evaluaciones" element={<Evaluaciones />} />
        <Route path="/evaluaciones/nueva" element={<NuevaEvaluacion />} />
        <Route path="/evaluaciones/:id" element={<EvaluacionDetalle />} />
        <Route path="/hallazgos" element={<Hallazgos />} />
        <Route path="/hallazgos/:id" element={<HallazgoDetalle />} />
        <Route path="/reportes" element={<Reportes />} />
        <Route path="/reportes/:id" element={<ReporteVista />} />
        <Route path="/usuarios" element={<Usuarios />} />
        <Route path="/configuracion" element={<Configuracion />} />
        <Route path="/perfil" element={<Perfil />} />
        <Route path="/ayuda" element={<Ayuda />} />
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
