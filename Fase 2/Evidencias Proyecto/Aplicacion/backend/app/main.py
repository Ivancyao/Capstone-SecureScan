"""
Punto de entrada de la API de SecureScan.

Ejecutar localmente:  uvicorn app.main:app --reload
Documentación interactiva automática:  http://localhost:8000/docs
"""
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app import models  # noqa: F401  (registra los modelos en Base.metadata)
from app.database import Base, SessionLocal, engine
from app.migrar import agregar_columnas_faltantes
from app.models import EstadoEvaluacion, Evaluacion
from app.routers import analisis, auth, configuracion, metricas, proyectos, reportes, usuarios

# Crea las tablas si no existen (suficiente para el MVP; luego se puede migrar a Alembic).
# Al arrancar creo las tablas que falten. Para el MVP basta; migrar.py completa las columnas nuevas.
Base.metadata.create_all(bind=engine)
agregar_columnas_faltantes(engine)  # bases creadas con versiones anteriores reciben las columnas nuevas


# Si apago el servidor mientras había un escaneo corriendo, esa evaluación quedaría "en progreso" para siempre.
# Por eso al arrancar las marco como fallidas con un mensaje claro.
def _cerrar_evaluaciones_huerfanas() -> None:
    """Si el servidor se reinició a mitad de un escaneo, esa evaluación no terminará nunca: se marca fallida."""
    db = SessionLocal()
    try:
        for evaluacion in db.query(Evaluacion).filter(
            Evaluacion.estado.in_([EstadoEvaluacion.PENDIENTE, EstadoEvaluacion.EN_PROGRESO])
        ):
            evaluacion.estado = EstadoEvaluacion.FALLIDA
            evaluacion.detalle_error = "El servidor se reinició mientras se ejecutaba la evaluación. Vuelve a lanzarla."
            evaluacion.etapa = "Falló"
        db.commit()
    finally:
        db.close()


_cerrar_evaluaciones_huerfanas()

app = FastAPI(
    title="SecureScan API",
    description="Plataforma de Evaluación y Gestión de Vulnerabilidades Web",
    version="0.2.0",
)

# CORS: solo el frontend configurado puede llamar a la API desde el navegador. Por defecto es el de desarrollo (localhost:5173).
origins = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # Hay que exponer esta cabecera para que el frontend pueda leer el total de resultados al paginar.
    expose_headers=["X-Total-Count"],  # total de la paginación (GET /evaluaciones?pagina=...)
)



# Cabeceras de seguridad en todas las respuestas: no adivinar el tipo de contenido, no permitir iframes (clickjacking), no enviar el referer y no cachear las respuestas.
@app.middleware("http")
async def cabeceras_de_seguridad(request: Request, call_next):
    respuesta = await call_next(request)
    respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
    respuesta.headers.setdefault("X-Frame-Options", "DENY")
    respuesta.headers.setdefault("Referrer-Policy", "no-referrer")
    respuesta.headers.setdefault("Cache-Control", "no-store")
    return respuesta


# Acá se conectan todos los grupos de rutas (routers). En total la API tiene 34 endpoints.
app.include_router(auth.router)
app.include_router(proyectos.router)
app.include_router(reportes.router)
app.include_router(usuarios.router)
app.include_router(configuracion.router)
app.include_router(metricas.router)
app.include_router(analisis.router)


# Ruta simple para comprobar rápido que el backend está vivo (sin login).
@app.get("/health", tags=["Sistema"])
def health():
    return {"status": "ok"}
