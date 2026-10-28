"""
Migración ligera: agrega las columnas nuevas a tablas que ya existen.

`Base.metadata.create_all` crea tablas que faltan, pero NO agrega columnas a una tabla
existente. Para que quien ya tenga datos no pierda su base, este módulo revisa cada columna
declarada en los modelos y, si falta en la base real, la agrega con ALTER TABLE.
Es suficiente para este MVP; a futuro se puede reemplazar por Alembic.
"""
from sqlalchemy import inspect, text

from app.database import Base


def agregar_columnas_faltantes(engine) -> list:
    agregadas = []
    insp = inspect(engine)
    tablas = set(insp.get_table_names())
    with engine.begin() as conn:
        for tabla in Base.metadata.sorted_tables:
            if tabla.name not in tablas:
                continue  # create_all la crea completa
            existentes = {c["name"] for c in insp.get_columns(tabla.name)}
            for col in tabla.columns:
                if col.name in existentes:
                    continue
                tipo = col.type.compile(dialect=engine.dialect)
                sql = f'ALTER TABLE "{tabla.name}" ADD COLUMN "{col.name}" {tipo}'
                if col.default is not None and getattr(col.default, "is_scalar", False):
                    valor = col.default.arg
                    if isinstance(valor, bool):
                        sql += f" DEFAULT {'TRUE' if valor else 'FALSE'}"
                    elif isinstance(valor, (int, float)):
                        sql += f" DEFAULT {valor}"
                    elif isinstance(valor, str):
                        sql += " DEFAULT '" + valor.replace("'", "''") + "'"
                conn.execute(text(sql))
                agregadas.append(f"{tabla.name}.{col.name}")
    return agregadas
