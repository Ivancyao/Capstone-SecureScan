"""Hora actual en UTC.

En la base guardo todas las fechas en UTC y sin zona horaria. Antes usaba
datetime.utcnow(), que Python marca como obsoleto, así que lo dejé en un solo
lugar para que el valor sea exactamente el mismo.
"""
from datetime import datetime, timezone


# Todas las fechas de la BD pasan por esta función, así queda todo en UTC y el frontend las muestra en la hora local.
def ahora_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
