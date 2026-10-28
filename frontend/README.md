# SecureScan · Frontend

Interfaz web de la plataforma SecureScan (React 18 + Vite). Incluye **todas las pantallas del proyecto** y trabaja contra la API de FastAPI. También puede correr sola, con datos de ejemplo, para diseñar o grabar sin backend.

## Cómo ejecutarlo

```bash
npm install
npm run dev          # abre http://localhost:5173
```

Requiere Node 18 o superior. Sin internet también funciona: las fuentes se instalan con el proyecto.

### Cuentas de ejemplo (solo con `VITE_USE_MOCK=true`)

La pantalla de ingreso trae tres botones para entrar sin escribir nada:

| Cuenta | Qué muestra |
|---|---|
| Administrador | Todo: usuarios, configuración, todos los proyectos |
| Analista | Solo sus proyectos; no ve Usuarios ni Configuración |
| Usuario nuevo | Sin datos, para mostrar los estados vacíos |

Las tres usan la contraseña `Demo1234!`. Los datos de ejemplo se guardan en el navegador (localStorage). Para volver al estado inicial: **Configuración → Restablecer**.

## API real o datos de ejemplo

Se elige con `VITE_USE_MOCK` (ver `.env.example`):

| Valor | Qué hace |
|---|---|
| `false` (por defecto) | **Usa la API real** en `VITE_API_URL` (por defecto `http://localhost:8000`). |
| `true` | Usa datos de ejemplo guardados en el navegador. No necesita backend. |

Todas las páginas leen los datos desde un único punto, `src/services/index.js`; `http.js` habla con la API y `mock.js` simula lo mismo en el navegador.

### Sin Docker
```bash
# terminal 1: backend  (necesita Nmap instalado para escanear de verdad)
cd backend && pip install -r requirements.txt
DATABASE_URL=sqlite:///./local.db uvicorn app.main:app --port 8000
# terminal 2: frontend
cd frontend && npm run dev
```

## Pantallas

| Ruta | Pantalla | Endpoints que usa |
|---|---|---|
| `/` | Portada pública | — |
| `/login`, `/registro` | Ingreso y creación de cuenta | `/auth/login`, `/auth/register` |
| `/panel` | Resumen: mapa del activo más expuesto, severidades, gráficos | `/metricas` (SQL) y los listados |
| `/proyectos`, `/proyectos/:id` | Lista y detalle con pestañas | `/proyectos` |
| `/activos`, `/activos/:id` | Lista y detalle, mapa de puertos, historial | `/activos`, `/proyectos/{id}/activos` |
| `/evaluaciones`, `/evaluaciones/nueva`, `/evaluaciones/:id` | Lista, formulario con confirmación de autorización, avance en vivo y resultados | `/evaluaciones?ultimas=10`, `/activos/{id}/evaluaciones` |
| `/hallazgos`, `/hallazgos/:id` | Filtros, búsqueda, detalle con CVSS y recomendación, marcar como corregido | `PATCH /hallazgos/{id}` |
| `/reportes`, `/reportes/:id` | Lista, generación y descarga del PDF | `/reportes`, `/proyectos/{id}/reportes`, `/reportes/{id}/descargar` |
| `/usuarios` | Usuarios, roles, contraseña temporal (solo admin) | `/usuarios` |
| `/configuracion` | Motores de escaneo y alcance (solo admin) | `/configuracion` |
| `/perfil` | Nombre, contraseña y tema | `PATCH /auth/me`, `/auth/password` |
| `/ayuda` | Guía, severidad, OWASP, glosario y preguntas frecuentes | — |

Los totales del panel (por severidad, por categoría OWASP y por semana) los calcula la base de datos con `GET /metricas`. `src/services/derive.js` conserva el mismo cálculo en JavaScript solo para el modo de ejemplo. La interfaz pide las 10 evaluaciones más recientes de cada activo; las más antiguas siguen en la base de datos y en la API (`GET /evaluaciones/{id}`), pero **la interfaz todavía no las muestra**.

## Qué es real y qué es una estimación

- **Los puertos abiertos** y su servicio vienen de Nmap, y las reglas de severidad son las del motor de riesgo del backend (`risk.py`).
- **El CVSS es una estimación por reglas**, y la interfaz lo indica en cada tabla, hallazgo e informe.
- **OWASP ZAP es opcional** y lo activa un administrador en *Configuración* si el servidor lo tiene conectado. Con la API real, los hallazgos web vienen de ZAP (agrupados por tipo de alerta); los de XSS, SQLi o CSRF del modo `VITE_USE_MOCK=true` son de ejemplo.
- **El bloqueo de IP públicas** lo hace el servidor; la interfaz solo avisa de antemano. El interruptor de *Configuración* queda desactivado mientras el servidor tenga `ALLOW_PUBLIC_SCANS=false`.

## Estructura

```
src/
  pages/        Una pantalla por archivo (Panel, Proyectos, Activos, Evaluaciones, Hallazgos, Reportes, Admin, Cuenta, Ayuda, Landing, Auth)
  components/   Layout, ui (insignias, diálogos, avisos), charts (gráficos en SVG), PortMap (mapa de puertos), shared
  context/      Sesión, datos con actualización automática, tema, avisos
  services/     index.js (elige demo o API), mock.js, http.js, seed.js (datos de ejemplo), derive.js (cálculos)
  lib/          risk.js (reglas y bandas CVSS), format.js (fechas y utilidades)
  styles/       tokens.css (todos los colores y medidas), base, layout, components, pages
```

## Diseño

- **Idea central:** cada activo se muestra como un **mapa de puertos**, una cuadrícula de "puertas" abiertas o cerradas, coloreadas por severidad. Es la pieza distintiva y se repite en la portada, el panel, el activo y la evaluación.
- **Severidad sin depender del color:** cada nivel tiene color, forma (rombo, triángulo, cuadrado, círculo, aro) y texto.
- **Paleta validada:** los colores de severidad pasan la prueba de separación para daltonismo y visión normal en tema claro y oscuro.
- **Tipografía:** Source Serif 4 para títulos y Schibsted Grotesk para la interfaz, instaladas localmente.
- **Gráficos hechos a mano en SVG**, sin librerías, con tooltip y vista de tabla. Así se pueden explicar en la defensa.
- **Accesibilidad:** foco visible, navegación por teclado, diálogos con foco atrapado, `prefers-reduced-motion` y tema claro, oscuro o del sistema.
- **Adaptable:** se probó desde 390 px de ancho (teléfono), con menú lateral en cajón.

## Verificado

Compila sin errores. Se recorrió en un navegador real contra el backend real (con una base SQLite): registro, ingreso, proyecto, activos, evaluación en vivo, bloqueo de IP pública, marcar corregido (persiste al recargar), generación y descarga del PDF, creación de cuenta con contraseña temporal, permisos por rol, desactivación de una cuenta con sesión abierta, configuración persistente y cambio de contraseña. Sin errores de consola.

Limitaciones de esa verificación: el escaneo usó un sustituto de Nmap (no había Nmap instalado en ese equipo) y no se probó dentro de Docker ni contra PostgreSQL.
