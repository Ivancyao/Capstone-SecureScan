import os

# Debe fijarse ANTES de importar la app: todas las pruebas usan SQLite temporal, nunca PostgreSQL.
os.environ["DATABASE_URL"] = "sqlite:///./test_securescan.db"
