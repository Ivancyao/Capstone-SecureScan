# Este archivo se carga antes que todos los tests de pytest. Solo sirve para apuntar la base a SQLite y que las pruebas nunca toquen PostgreSQL.

import os

# Debe fijarse ANTES de importar la app: todas las pruebas usan SQLite temporal, nunca PostgreSQL.
os.environ["DATABASE_URL"] = "sqlite:///./test_securescan.db"
