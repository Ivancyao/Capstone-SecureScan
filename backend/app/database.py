"""
Configuración de la conexión a PostgreSQL usando SQLAlchemy.

En Docker, DATABASE_URL apunta al servicio "db" definido en docker-compose.yml.
Localmente (sin Docker), puedes apuntar a un Postgres instalado en tu máquina.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://securescan:securescan@localhost:5432/securescan",
)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependencia de FastAPI: entrega una sesión de BD y la cierra al terminar."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
