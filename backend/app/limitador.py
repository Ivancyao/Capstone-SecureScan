"""Límite de intentos fallidos de inicio de sesión (contra fuerza bruta, OWASP A07).

Guarda en memoria los fallos recientes por cuenta y origen. Al pasar el máximo, esa cuenta queda
bloqueada unos minutos para ese origen. Un inicio de sesión correcto borra el contador.
Sirve para un solo proceso de API; con varias réplicas habría que usar Redis o la base de datos.
"""
import os
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

MAX_INTENTOS = int(os.getenv("LOGIN_MAX_INTENTOS", "5"))
VENTANA_SEGUNDOS = int(os.getenv("LOGIN_VENTANA_SEGUNDOS", "300"))

_fallos: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)


def _limpiar(clave: Tuple[str, str], ahora: float) -> Deque[float]:
    cola = _fallos[clave]
    while cola and ahora - cola[0] > VENTANA_SEGUNDOS:
        cola.popleft()
    return cola


def segundos_de_espera(email: str, origen: str) -> int:
    """0 si puede intentar; si no, los segundos que faltan para que se libere."""
    ahora = time.monotonic()
    cola = _limpiar((email.lower(), origen), ahora)
    if len(cola) < MAX_INTENTOS:
        return 0
    return max(1, int(VENTANA_SEGUNDOS - (ahora - cola[0])))


def registrar_fallo(email: str, origen: str) -> None:
    ahora = time.monotonic()
    _limpiar((email.lower(), origen), ahora).append(ahora)


def limpiar(email: str, origen: str) -> None:
    _fallos.pop((email.lower(), origen), None)


def reiniciar() -> None:
    """Vacía todo el estado (se usa en las pruebas)."""
    _fallos.clear()
