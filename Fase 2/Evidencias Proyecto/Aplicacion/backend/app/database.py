"""
Configuración de la conexión a PostgreSQL usando SQLAlchemy.

En Docker, DATABASE_URL apunta al servicio "db" definido en docker-compose.yml.
Localmente (sin Docker), puedes apuntar a un Postgres instalado en tu máquina.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# La URL de la base viene del .env. En Docker apunta al contenedor "db"; en los tests uso SQLite en memoria para que corran rápido.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://securescan:securescan@localhost:5432/securescan",
)

# SQLite necesita este parámetro para usarlo desde varios hilos (los escaneos corren en segundo plano). Con PostgreSQL no hace falta.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
# autoflush=False: yo decido cuándo se hace commit, para no guardar cosas a medias.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Cada petición recibe su propia sesión y se cierra sola al terminar (aunque haya error).
def get_db():
    """Dependencia de FastAPI: entrega una sesión de BD y la cierra al terminar."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
