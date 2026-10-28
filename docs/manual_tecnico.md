# SecureScan · Manual técnico

Para quien instala, opera o mantiene la plataforma. El diseño y las decisiones están en [`diseno.md`](diseno.md).

## 1. Requisitos

| Componente | Versión | Para qué |
|---|---|---|
| Docker + Docker Compose | recientes | Forma recomendada de ejecutar todo |
| Python | 3.12 | Backend (solo si se ejecuta sin Docker) |
| Node.js | 18 o superior | Frontend (solo si se ejecuta sin Docker) |
| Nmap | 7.x | Lo usa el backend para escanear (ya viene en la imagen Docker) |
| PostgreSQL | 16 | Base de datos (SQLite sirve para desarrollo y pruebas) |

## 2. Instalación con Docker (recomendada)

```bash
cp .env.example .env     # edita SECRET_KEY, POSTGRES_PASSWORD y ZAP_API_KEY
docker compose up --build
```

| Servicio | Dirección | Notas |
|---|---|---|
| Interfaz | http://localhost:5173 | |
| API y documentación interactiva | http://localhost:8000/docs | |
| Juice Shop (objetivo de laboratorio) | http://localhost:3001 | Dentro de Docker se registra como `http://juiceshop:3000` |
| OWASP ZAP | solo red interna | No publica puertos. Tarda cerca de un minuto en estar listo. |

La primera cuenta que se registra queda como **administradora**.

Para apagar: `docker compose down` (conserva los datos). Para empezar de cero: `docker compose down -v`.

## 3. Instalación sin Docker

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
DATABASE_URL=sqlite:///./local.db SECRET_KEY=una-clave-larga-y-aleatoria \
  uvicorn app.main:app --reload --port 8000

# Frontend (otra terminal)
cd frontend
npm install
npm run dev          # http://localhost:5173
```

Instala Nmap con el gestor de tu sistema (`apt install nmap`, `brew install nmap`). Sin Nmap, las evaluaciones terminan como *fallidas* con el mensaje "Nmap no está instalado en el servidor".

## 4. Variables de entorno

### Backend
| Variable | Por defecto | Qué hace |
|---|---|---|
| `DATABASE_URL` | `postgresql://securescan:securescan@localhost:5432/securescan` | Conexión a la base. Acepta `sqlite:///...` |
| `SECRET_KEY` | `cambia-esta-clave-en-produccion` | Firma de los tokens. **Cámbiala**: con la de ejemplo, cualquiera podría fabricar tokens válidos. Usa 32 caracteres o más. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Duración de la sesión |
| `CORS_ORIGINS` | `http://localhost:5173` | Orígenes del frontend permitidos, separados por coma |
| `ALLOW_PUBLIC_SCANS` | `false` | Candado del servidor para escanear IP públicas. Con `false`, ninguna configuración web puede habilitarlas. |
| `NMAP_PORTS` | puertos 1-1024 y comunes | Lista de puertos del perfil "predeterminado" |
| `NMAP_TIMEOUT` | `300` | Segundos máximos por escaneo (valor inicial; luego se cambia en Configuración) |
| `REPORTS_DIR` | `./reportes_generados` | Dónde se guardan los PDF. En Docker es un volumen. |
| `ZAP_URL` | vacío | Dirección de ZAP. Sin ella, ZAP queda "no configurado" y la plataforma funciona solo con Nmap. |
| `ZAP_API_KEY` | vacío | Clave de la API de ZAP (debe coincidir con la del contenedor) |

### Frontend
| Variable | Por defecto | Qué hace |
|---|---|---|
| `VITE_API_URL` | `http://localhost:8000` | Dirección de la API |
| `VITE_USE_MOCK` | `false` | `true` usa datos de ejemplo en el navegador, sin API |

## 5. Estructura del código

```
backend/app/
  main.py            Arranque, rutas, migración y cierre de evaluaciones huérfanas
  models.py          Tablas (SQLAlchemy)
  schemas.py         Validación de entrada y forma de las respuestas (Pydantic)
  security.py        bcrypt, JWT y control de roles
  scanner.py         Nmap: validación del objetivo y lectura del XML
  zap_client.py      OWASP ZAP: cliente de su API y traducción de alertas
  risk.py            Reglas: puerto o servicio -> hallazgo (CVSS estimado, OWASP)
  scan_service.py    Orquesta una evaluación en segundo plano
  config_service.py  Configuración guardada y retención de datos
  reportes_pdf.py    Diseño del PDF
  migrar.py          Agrega columnas nuevas a bases antiguas
  routers/           auth, proyectos (activos, evaluaciones, hallazgos), reportes,
                     usuarios, configuracion, metricas
backend/tests/       Pruebas automáticas
backend/tools/       rendimiento.py
frontend/src/        pages/, components/, context/, services/ (http.js, mock.js), lib/, styles/
docs/                Este manual, el diseño, los diagramas y los resultados de rendimiento
```

## 6. API

Documentación completa y probable en `/docs`. Resumen:

| Área | Endpoints | Permiso |
|---|---|---|
| Sesión | `POST /auth/register`, `POST /auth/login`, `GET/PATCH /auth/me`, `POST /auth/password` | Públicos los dos primeros |
| Proyectos y activos | `GET/POST /proyectos`, `GET/POST /proyectos/{id}/activos`, `GET /activos` | Dueño o admin |
| Evaluaciones | `POST/GET /activos/{id}/evaluaciones`, `GET /evaluaciones[?ultimas=N]`, `GET /evaluaciones/{id}` | Dueño o admin |
| Hallazgos | `PATCH /hallazgos/{id}` con `{"corregido":"si"\|"no"}` | Dueño o admin |
| Métricas | `GET /metricas` | Lo que el usuario puede ver |
| Reportes | `GET /reportes`, `POST /proyectos/{id}/reportes`, `GET /reportes/{id}/descargar`, `DELETE /reportes/{id}` | Dueño o admin |
| Usuarios | `GET/POST /usuarios`, `PATCH /usuarios/{id}` | Solo admin |
| Configuración | `GET /configuracion`, `PUT /configuracion` | Leer: todos. Escribir: admin |
| Sistema | `GET /health` | Público |

Códigos que conviene reconocer: `401` sin sesión o sesión vencida; `403` rol insuficiente o cuenta desactivada; `404` no existe **o no es tuyo**; `409` ya hay una evaluación en curso para ese activo; `422` datos inválidos.

## 7. Operación

### Configuración desde la interfaz (administrador)
- **Nmap:** perfil de puertos (predeterminado, rápido 100 puertos, completo 1–65535), tiempo máximo y detección de versiones.
- **OWASP ZAP:** activar o no, tiempo máximo del análisis y escaneo activo. El **escaneo activo envía ataques de prueba** al objetivo: úsalo solo en laboratorio o con autorización escrita.
- **Alcance:** direcciones públicas (requiere además `ALLOW_PUBLIC_SCANS=true` en el servidor) y retención del historial.

### Retención de datos
Tras cada evaluación se borran las anteriores a `retencion_dias`, **excepto la última completada de cada activo**. `0` significa sin límite. Los PDF ya generados no se borran por esta vía.

### Respaldo
- Base de datos: `docker compose exec db pg_dump -U securescan securescan > respaldo.sql`
- Reportes: el volumen `reportes_data` (o la carpeta de `REPORTS_DIR`).

### Actualizar desde una versión anterior
Al arrancar, el backend agrega las columnas que falten (`app/migrar.py`); no hace falta borrar la base. Respalda antes de actualizar.

## 8. Pruebas

```bash
cd backend && pytest                       # 93 pruebas; 1 se omite si no hay Nmap
DATABASE_URL=sqlite:///./rendimiento.db python tools/rendimiento.py
```

| Archivo | Qué cubre |
|---|---|
| `test_api.py` | Registro, login, contraseñas hasheadas, acceso sin token, aislamiento entre usuarios |
| `test_scanner.py` | Validación del objetivo, bloqueo de IP públicas, anti-inyección, lectura del XML de Nmap, bandas CVSS, evaluación completa. Incluye una prueba con **Nmap real** (se omite si no está instalado). |
| `test_endpoints_nuevos.py` | Hallazgos, usuarios y roles, perfil, configuración, progreso, concurrencia, retención, reportes PDF, migración |
| `test_metricas.py` | Las consultas SQL contra un cálculo independiente en Python, con datos aleatorios |
| `test_zap.py` | Cliente de ZAP y su integración, **con un simulacro del API de ZAP** (ver límites) |

**Límites de las pruebas:** ZAP real no se ejecutó; el rendimiento se midió en SQLite y con un solo usuario; la interfaz se verificó a mano en un navegador real, sin pruebas automáticas de interfaz en el repositorio.

## 9. Solución de problemas

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| "No se pudo conectar con el servidor" en la interfaz | La API no está encendida o `VITE_API_URL` apunta mal | Abre `http://localhost:8000/health`; revisa `CORS_ORIGINS` |
| La evaluación falla con "Nmap no está instalado" | Se ejecuta sin Docker y falta Nmap | Instálalo |
| "Objetivo bloqueado: … no pertenece a una red privada" | El activo apunta a una IP pública | Es lo esperado. Usa un objetivo de laboratorio. |
| "No se pudo resolver el host" | El nombre no existe desde el servidor | Dentro de Docker usa el nombre del servicio (`juiceshop`), no `localhost` |
| "Ya hay una evaluación en curso" (409) | Hay un escaneo corriendo para ese activo | Espera a que termine |
| La evaluación termina con una advertencia de ZAP | ZAP no respondió o superó el tiempo | Se conservan los resultados de Nmap. Revisa que el contenedor `zap` esté arriba y que `ZAP_API_KEY` coincida |
| "OWASP ZAP no está configurado" al activarlo | Falta `ZAP_URL` | Define la variable o levanta el servicio `zap` |
| Evaluación fallida con "El servidor se reinició…" | El backend se reinició a mitad del escaneo | Vuelve a lanzarla |
| "El servidor bloquea las direcciones públicas" al guardar | `ALLOW_PUBLIC_SCANS=false` | Solo cámbialo con autorización escrita del dueño del sistema |
| El panel tarda con mucho historial | Muchas evaluaciones por activo | Ver `rendimiento_resultados.md`; la interfaz ya pide solo las 10 más recientes por activo |

## 10. Seguridad operativa

- Cambia `SECRET_KEY`, `POSTGRES_PASSWORD` y `ZAP_API_KEY` antes de exponer la plataforma fuera de tu equipo.
- No subas `.env` al repositorio (ya está en `.gitignore`).
- Sirve la interfaz y la API detrás de HTTPS si salen de una red local.
- Usa SecureScan **solo** contra sistemas propios o con autorización escrita.
