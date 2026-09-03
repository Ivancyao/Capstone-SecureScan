SecureScan – Plataforma de Evaluación y Gestión de Vulnerabilidades Web
📌 Descripción del Proyecto

SecureScan es una plataforma web que permite a una organización registrar sus aplicaciones, ejecutar evaluaciones de seguridad automatizadas sobre ambientes controlados y autorizados, almacenar los hallazgos y generar reportes de vulnerabilidades priorizados por nivel de riesgo. Está dirigida a equipos de TI/desarrollo y organizaciones (pymes u organizaciones educacionales) que necesitan evaluar periódicamente la seguridad de sus aplicaciones web sin depender de herramientas comerciales costosas. Busca resolver la falta de visibilidad y priorización clara frente a vulnerabilidades comunes (OWASP Top 10) en aplicaciones web.

👥 Integrantes y Roles
Ivan Escobar – Proyecto individual (autorizado por la docente a cargo). A cargo de arquitectura, backend, frontend, integración del motor de escaneo y pruebas.
🛠️ Tecnologías Utilizadas
Backend: Python + FastAPI
Frontend: React
Base de Datos: PostgreSQL
Seguridad: JWT + RBAC (control de acceso por roles)
Motor de escaneo: Nmap, OWASP ZAP (Nikto como extensión posible)
Infraestructura / Despliegue: Docker + Docker Compose
📐 Arquitectura de la Solución

Arquitectura por capas: Frontend (Dashboard) → Backend/API (REST + Auth) → Motor de Escaneo / Motor de Riesgo / Motor de Reportes → Base de datos PostgreSQL.

(Se adjuntará el diagrama de componentes y el modelo entidad-relación en la carpeta /docs a medida que avance el desarrollo).

🔄 Metodología de Trabajo

Kanban personal, con ciclos de trabajo alineados a las fases de la asignatura Capstone (Fase 1: definición, Fase 2: desarrollo, Fase 3: presentación). El avance se registra mediante commits regulares en este repositorio y un tablero Kanban de seguimiento personal.

🚀 Instrucciones de Ejecución

(Se agregarán los pasos para clonar y levantar el proyecto con docker-compose up una vez esté disponible el primer prototipo funcional).
