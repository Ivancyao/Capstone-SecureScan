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
Base.metadata.create_all(bind=engine)
agregar_columnas_faltantes(engine)  # bases creadas con versiones anteriores reciben las columnas nuevas


def _cerrar_evaluaciones_huerfanas() -> None:
    """Si el servidor se reinició a mitad de un escaneo, esa evaluación no terminará nunca: se marca fallida."""
    db = SessionLocal()
    try:
        for ev in db.query(Evaluacion).filter(
            Evaluacion.estado.in_([EstadoEvaluacion.PENDIENTE, EstadoEvaluacion.EN_PROGRESO])
        ):
            ev.estado = EstadoEvaluacion.FALLIDA
            ev.detalle_error = "El servidor se reinició mientras se ejecutaba la evaluación. Vuelve a lanzarla."
            ev.etapa = "Falló"
        db.commit()
    finally:
        db.close()


_cerrar_evaluaciones_huerfanas()

app = FastAPI(
    title="SecureScan API",
    description="Plataforma de Evaluación y Gestión de Vulnerabilidades Web",
    version="0.2.0",
)

origins = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count"],  # total de la paginación (GET /evaluaciones?pagina=...)
)



@app.middleware("http")
async def cabeceras_de_seguridad(request: Request, call_next):
    respuesta = await call_next(request)
    respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
    respuesta.headers.setdefault("X-Frame-Options", "DENY")
    respuesta.headers.setdefault("Referrer-Policy", "no-referrer")
    respuesta.headers.setdefault("Cache-Control", "no-store")
    return respuesta


app.include_router(auth.router)
app.include_router(proyectos.router)
app.include_router(reportes.router)
app.include_router(usuarios.router)
app.include_router(configuracion.router)
app.include_router(metricas.router)
app.include_router(analisis.router)


@app.get("/health", tags=["Sistema"])
def health():
    return {"status": "ok"}
