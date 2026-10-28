"""
Configuración de la plataforma (qué motores se usan y a qué se permite escanear).

Se guarda en la tabla `configuracion`. Las variables de entorno siguen siendo el
candado de más alto nivel: aunque un administrador active "direcciones públicas"
en la pantalla, el servidor solo las permite si ALLOW_PUBLIC_SCANS=true. Así un
cambio hecho desde la web no puede, por sí solo, abrir el escáner hacia internet.
"""
import copy
import os
from datetime import datetime, timedelta
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.models import Configuracion

CLAVE = "escaneo"
PERFILES_PUERTOS = ("predeterminado", "rapido", "completo")
RANGOS_PERMITIDOS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
]

POR_DEFECTO: Dict[str, Any] = {
    "motores": {
        "nmap": {
            "activo": True,
            "puertos": "predeterminado",
            "timeout_s": int(os.getenv("NMAP_TIMEOUT", "300")),
            "detectar_versiones": True,
        },
        "zap": {"activo": False, "escaneo_activo": False, "timeout_s": 600},
        "nikto": {"activo": False},
    },
    "alcance": {"permitir_publicas": False},
    "retencion_dias": 365,
}


def servidor_permite_publicas() -> bool:
    """Candado del servidor (variable de entorno)."""
    return os.getenv("ALLOW_PUBLIC_SCANS", "false").lower() == "true"


def _completar(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Valores calculados que se muestran en la web pero no se guardan."""
    out = copy.deepcopy(cfg)
    from app import zap_client

    out["motores"]["zap"]["disponible"] = zap_client.disponible()  # ¿el operador configuró ZAP_URL?
    out["alcance"]["rangos"] = list(RANGOS_PERMITIDOS)
    out["alcance"]["publicas_permitidas_por_servidor"] = servidor_permite_publicas()
    return out


def _fusionar(base: Dict[str, Any], cambios: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in cambios.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _fusionar(out[k], v)
        else:
            out[k] = v
    return out


def obtener(db: Session) -> Dict[str, Any]:
    fila = db.get(Configuracion, CLAVE)
    guardada = fila.valor if fila else {}
    return _completar(_fusionar(POR_DEFECTO, guardada))


def guardar(db: Session, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Guarda solo lo que se puede cambiar (lo calculado se descarta)."""
    limpio = {
        "motores": {
            "nmap": cfg["motores"]["nmap"],
            "zap": {k: cfg["motores"]["zap"][k] for k in ("activo", "escaneo_activo", "timeout_s")},
            "nikto": {"activo": False},
        },
        "alcance": {"permitir_publicas": bool(cfg["alcance"]["permitir_publicas"])},
        "retencion_dias": cfg["retencion_dias"],
    }
    fila = db.get(Configuracion, CLAVE)
    if fila is None:
        fila = Configuracion(clave=CLAVE, valor=limpio)
        db.add(fila)
    else:
        fila.valor = limpio
        fila.actualizado_en = datetime.utcnow()
    db.commit()
    return obtener(db)


def publicas_efectivas(cfg: Dict[str, Any]) -> bool:
    """Se escanean IP públicas solo si el servidor Y la configuración lo permiten."""
    return servidor_permite_publicas() and bool(cfg["alcance"]["permitir_publicas"])


def aplicar_retencion(db: Session) -> int:
    """
    Borra evaluaciones más antiguas que `retencion_dias`. Nunca borra la evaluación
    completada más reciente de cada activo (es el "estado vigente" del activo).
    Devuelve cuántas borró. 0 días = sin límite.
    """
    from app.models import EstadoEvaluacion, Evaluacion

    dias = obtener(db)["retencion_dias"]
    if not dias:
        return 0
    limite = datetime.utcnow() - timedelta(days=dias)
    vigentes = {}  # activo_id -> id de su evaluación completada más reciente
    for ev in (
        db.query(Evaluacion)
        .filter(Evaluacion.estado == EstadoEvaluacion.COMPLETADA)
        .order_by(Evaluacion.iniciada_en.desc())
        .all()
    ):
        vigentes.setdefault(ev.activo_id, ev.id)
    ids_vigentes = set(vigentes.values())
    borradas = 0
    for ev in db.query(Evaluacion).filter(Evaluacion.iniciada_en < limite).all():
        if ev.id in ids_vigentes or ev.estado in (EstadoEvaluacion.PENDIENTE, EstadoEvaluacion.EN_PROGRESO):
            continue
        db.delete(ev)
        borradas += 1
    if borradas:
        db.commit()
    return borradas
