"""Migración simple: agrega las columnas nuevas a tablas que ya existen.

`Base.metadata.create_all` crea las tablas que faltan, pero no agrega columnas a una tabla existente.
Este módulo compara las columnas de los modelos con las de la base y, si falta alguna, la agrega con
ALTER TABLE. Alcanza para este proyecto; a futuro se puede cambiar por Alembic.
"""
from sqlalchemy import inspect, text

from app.database import Base


# Para el prototipo preferí esto en vez de Alembic: si actualizo el modelo y la base ya existe, agrega las columnas que faltan sin perder datos.
# Si me preguntan por qué no Alembic: es lo correcto para producción, pero para este alcance era demasiado.
def agregar_columnas_faltantes(engine) -> list:
    agregadas = []
    insp = inspect(engine)
    tablas = set(insp.get_table_names())
    with engine.begin() as conn:
        # Recorro cada tabla del modelo y comparo sus columnas con las que realmente existen en la base.
        for tabla in Base.metadata.sorted_tables:
            if tabla.name not in tablas:
                continue  # create_all la crea completa
            existentes = {columna["name"] for columna in insp.get_columns(tabla.name)}
            for col in tabla.columns:
                if col.name in existentes:
                    continue
                # El tipo se traduce al dialecto de la base (PostgreSQL o SQLite) para que el ALTER TABLE funcione en ambas.
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
