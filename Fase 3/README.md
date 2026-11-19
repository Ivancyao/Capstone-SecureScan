# SecureScan – Plataforma de Evaluación y Gestión de Vulnerabilidades Web

## Descripción
SecureScan permite a una organización registrar sus aplicaciones web, ejecutar evaluaciones de seguridad
automatizadas en ambientes controlados y autorizados, y obtener hallazgos priorizados por riesgo (CVSS / OWASP Top 10).
Está dirigida a pymes y equipos de TI sin presupuesto para herramientas comerciales de seguridad.

## Integrantes y roles
- **Ivan Escobar** – Proyecto individual. Todos los roles: arquitectura, backend, frontend, motor de escaneo, pruebas, despliegue y documentación.
- **Docente:** Profesora Karla Marilyn Roco Ramirez.

## Tecnologías
- **Backend:** Python 3.12, FastAPI, SQLAlchemy, JWT (PyJWT), bcrypt
- **Frontend:** React 18 + Vite (React Router, gráficos SVG propios, sin librerías de gráficos)
- **Reportes:** ReportLab (PDF generado en el servidor)
- **Base de datos:** PostgreSQL 16
- **Escaneo:** Nmap (puertos y servicios) y OWASP ZAP (aplicación web, opcional)
- **Despliegue:** Docker + Docker Compose

## Arquitectura
Frontend (React) → API REST (FastAPI + JWT/RBAC) → Motor de Escaneo / Riesgo / Reportes → PostgreSQL.

![Arquitectura de SecureScan](Fase%202/Evidencias%20Proyecto/Evidencias%20de%20documentacion/diagramas/01_arquitectura.png)

Más diagramas (componentes, ER, clases, secuencias, estados y despliegue) en [`diagramas`](Fase%202/Evidencias%20Proyecto/Evidencias%20de%20documentacion/diagramas).

Estructura del repositorio:
```
backend/    API FastAPI (models, security, routers/, scanner, risk, scan_service, analisis_service, reportes_pdf, tests/)
frontend/   Interfaz React: 21 pantallas (ver frontend/README.md)
docker-compose.yml, .env.example   Despliegue con Docker Compose y variables de entorno
Fase 1/     Entregables de la Fase 1 (Grupales e Individuales)
Fase 2/     Entregables de la Fase 2
  Grupales/                   Guía 2.4 e Informe 2.6
  Individuales/               Diario de reflexión
  Evidencias Proyecto/
    Evidencias de documentacion/    Documentos de requerimientos, diseño, plan de pruebas y manual técnico (Word),
                                    diagramas UML y docs/ (diseno.md, manual_tecnico.md, resultados de rendimiento)
    Evidencias de sistema aplicacion/   Capturas de la aplicación en funcionamiento
```

## Cómo ejecutar el proyecto
### Con Docker (recomendado)
```bash
cp .env.example .env        # ajusta las claves
docker compose up --build
```
- Frontend: http://localhost:5173
- API + documentación interactiva: http://localhost:8000/docs

### Variables de entorno (`.env`)
Copia `.env.example` a `.env` y ajusta los valores. **El `.env` real nunca se sube a GitHub** (está en `.gitignore`).

| Variable | Para qué sirve |
|---|---|
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | Credenciales de la base de datos PostgreSQL |
| `SECRET_KEY` | Clave con la que el backend firma los tokens JWT. Usa una cadena larga y aleatoria. Si falta, el backend genera una temporal (las sesiones se cierran al reiniciar) |
| `ZAP_API_KEY` | Clave compartida entre el backend y el contenedor de OWASP ZAP. ZAP no expone puertos fuera de Docker |
| `ALLOW_PUBLIC_SCANS` | Primer candado para escanear IP públicas. Déjala en `false` salvo autorización escrita |
| `LOGIN_MAX_INTENTOS`, `LOGIN_VENTANA_SEGUNDOS` | Opcionales. Intentos fallidos de inicio de sesión permitidos (5) y ventana de bloqueo en segundos (300) |
| `VIRUSTOTAL_API_KEY` | Opcional. Activa la reputación de VirusTotal en el *Análisis rápido* |

**Cómo activar VirusTotal (opcional):**
1. Crea una cuenta gratuita en https://www.virustotal.com y copia tu *API key* desde tu perfil.
2. Pégala en `.env` sin comillas ni espacios: `VIRUSTOTAL_API_KEY=tu_clave`.
3. Ejecuta `docker compose up -d` para que el backend lea la nueva clave.
4. En **Análisis rápido**, el aviso amarillo desaparece y el resultado muestra "0 de N motores". Sin clave, solo se muestran indicadores locales.

La cuenta gratuita permite 4 consultas por minuto y 500 al día.

### Primer uso
1. Abre http://localhost:5173 y crea una cuenta. **La primera cuenta queda como administradora**; las demás parten como *usuario*.
2. Crea un proyecto y registra un activo con la URL `http://juiceshop:3000` (aplicación vulnerable de laboratorio incluida en el compose).
3. Pulsa **Iniciar evaluación**. Verás el avance en vivo, el mapa de puertos y los hallazgos priorizados.
4. Desde **Reportes** genera el informe PDF; desde **Usuarios y roles** (admin) crea cuentas y cambia roles.

> **Los datos viven en tu equipo.** La base de datos (cuentas, proyectos y evaluaciones) se guarda en un volumen de Docker y no viaja con el repositorio de GitHub. Se conservan al reiniciar o reconstruir (`docker compose up -d --build`), pero se pierden con `docker compose down -v`, al limpiar los datos de Docker Desktop o al usar otra carpeta u otro equipo; en ese caso hay que crear de nuevo la cuenta.

> Si actualizas desde una versión anterior **no necesitas borrar la base**: al arrancar, el backend agrega solas las columnas nuevas (`app/migrar.py`).

### API
Documentación interactiva en http://localhost:8000/docs. Resumen:

| Área | Endpoints | Quién |
|---|---|---|
| Sesión | `POST /auth/register`, `POST /auth/login`, `GET /auth/me`, `PATCH /auth/me`, `POST /auth/password` | Todos |
| Proyectos y activos | `GET/POST /proyectos`, `GET/POST /proyectos/{id}/activos`, `GET /activos` | Dueño o admin |
| Evaluaciones | `POST/GET /activos/{id}/evaluaciones`, `GET /evaluaciones` (`?ultimas=N`, `?pagina=P&por_pagina=N` con total en la cabecera `X-Total-Count`), `GET /evaluaciones/{id}` | Dueño o admin |
| Cancelar y eliminar | `POST /evaluaciones/{id}/cancelar` (409 si ya terminó), `DELETE /evaluaciones/{id}` (409 si sigue en curso) | Dueño o admin |
| Análisis rápido | `POST /analisis/url`, `POST /analisis/archivo` (multipart, `subir=true` solo si se autoriza enviar el archivo a VirusTotal), `GET /analisis`, `GET /analisis/{id}`, `DELETE /analisis/{id}`, `GET /analisis/estado` | Cada usuario ve solo los suyos |
| Hallazgos | `PATCH /hallazgos/{id}` (marcar corregido o reabrir) | Dueño o admin |
| Métricas | `GET /metricas` (totales por severidad, OWASP y semana, calculados con SQL) | Lo que el usuario puede ver |
| Reportes | `GET /reportes`, `POST /proyectos/{id}/reportes`, `GET /reportes/{id}/descargar` (PDF), `DELETE /reportes/{id}` | Dueño o admin |
| Usuarios | `GET/POST /usuarios`, `PATCH /usuarios/{id}` (rol, activar/desactivar) | Solo admin |
| Configuración | `GET /configuracion` (todos), `PUT /configuracion` | Escribir: solo admin |

Detalles de diseño que conviene conocer:
- **Sin acceso a lo ajeno:** un recurso de otro usuario responde 404 (no 403), para no revelar que existe (OWASP A01).
- **Cuenta desactivada = acceso cortado al instante**, aunque su token siga vigente.
- **Un solo escaneo a la vez por activo** (409 si ya hay uno en curso). Si el servidor se reinicia a mitad de un escaneo, esa evaluación se marca como fallida en vez de quedar colgada.
- **Contraseña temporal:** al crear una cuenta, el servidor genera una contraseña aleatoria y la muestra una sola vez.
- **Avance de la evaluación por etapas** (validar, escanear, clasificar, guardar). Nmap es un único proceso, así que no hay porcentaje fino dentro del escaneo de puertos.
- **Retención:** `retencion_dias` borra evaluaciones antiguas tras cada escaneo, pero conserva siempre la última completada de cada activo.

### Límites de seguridad del escáner
- Solo escanea redes privadas/loopback (laboratorio). Un objetivo público se rechaza y la evaluación queda *fallida* sin ejecutar Nmap.
- **Dos candados para las IP públicas:** la variable de entorno `ALLOW_PUBLIC_SCANS` (la fija quien administra el servidor) y el interruptor en *Configuración*. Se necesitan ambos: si la variable es `false`, ninguna configuración hecha desde la web puede abrirlas.
- El perfil de puertos, el tiempo máximo y la detección de versiones se eligen en *Configuración* y se validan en el servidor (lista cerrada de perfiles, sin texto libre que llegue a Nmap).
- **OWASP ZAP** es opcional: se activa en *Configuración* si el servidor tiene `ZAP_URL`. Analiza la misma IP ya validada. Su **escaneo activo** (que envía ataques de prueba) está apagado por defecto. Si ZAP falla, la evaluación termina igual con los resultados de Nmap y una advertencia. Nikto no está integrado.
- ZAP se validó con el contenedor real evaluando Juice Shop (06-11-2026), además de las pruebas automáticas con un simulacro de su API. Sus descripciones y soluciones se muestran en español para las alertas más frecuentes (catálogo de 35); las demás conservan el texto original con un aviso.
- Se resuelve el host a IP una sola vez y se escanea esa IP (evita cambios de DNS entre la validación y el escaneo). Nmap se invoca sin shell.
- El puntaje **CVSS es una estimación basada en reglas** según el servicio expuesto, no un cálculo vectorial completo de CVSS v3.1.

### Pruebas automatizadas del backend
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
```

## Metodología
Enfoque tradicional (cascada, opción 1 del instructivo de Capstone) para la planificación y la documentación, con desarrollo incremental:
producto mínimo funcional primero y luego Nmap, ZAP, reportes y métricas. Los artefactos están en [`Evidencias de documentacion`](Fase%202/Evidencias%20Proyecto/Evidencias%20de%20documentacion):
documento de requerimientos, documento de diseño, plan de pruebas y evidencias, y manual técnico.
Todo el avance queda registrado en commits de este repositorio.

## Estado del desarrollo
- [x] Modelo de datos (Usuario, Proyecto, Activo, Evaluación, Hallazgo, Reporte)
- [x] Autenticación JWT + control de acceso por roles (RBAC)
- [x] CRUD de proyectos, activos y evaluaciones con control de propiedad
- [x] Dashboard base (login, proyectos, activos, iniciar evaluación)
- [x] Pruebas funcionales y de seguridad (138 pruebas automáticas aprobadas: 129 de la versión evaluada el 10-11-2026 y 9 de endurecimiento de seguridad posteriores; más 1 que usa Nmap real y se omite si no está instalado)
- [x] Motor de escaneo Nmap en segundo plano + validación de objetivo
- [x] Motor de riesgo por reglas (CVSS estimado / OWASP Top 10)
- [x] Dashboard con hallazgos, resumen por severidad y actualización automática
- [x] Interfaz completa de 21 pantallas conectada a la API real
- [x] Reportes PDF generados en el servidor
- [x] Gestión de usuarios y roles, perfil, configuración de escaneo
- [x] Avance de la evaluación en vivo y marcado de hallazgos corregidos
- [x] Migración automática de columnas para bases creadas con versiones anteriores
- [x] Integración OWASP ZAP (validada con ZAP real y Juice Shop el 06-11-2026; textos en español)
- [x] Consultas SQL de agregación en el servidor (`/metricas`), verificadas contra un cálculo independiente
- [x] Pruebas de rendimiento (hallazgo y corrección de un problema N+1) y manual técnico
- [x] Validación completa con `docker compose up` (PostgreSQL, ZAP real y Juice Shop) en un equipo con Windows y Docker Desktop
- [x] Rendimiento medido también sobre PostgreSQL 16 (equivalente a SQLite; ver [`rendimiento_postgresql.md`](Fase%202/Evidencias%20Proyecto/Evidencias%20de%20documentacion/docs/rendimiento_postgresql.md))
- [x] Paginación de `GET /evaluaciones` (API y tabla de la interfaz)
- [x] Comparación entre dos evaluaciones de un activo (qué cambió: nuevos, resueltos, persisten, cambiaron de severidad)
- [x] Cancelar evaluaciones en curso (detiene Nmap y ZAP) y eliminar evaluaciones terminadas
- [x] Análisis rápido de URL o archivo (huella SHA-256, indicadores locales, cabeceras de seguridad y VirusTotal opcional); VirusTotal verificado con el servicio real el 12-11-2026 (`https://example.com`: 0 de 93 motores lo marcan)
