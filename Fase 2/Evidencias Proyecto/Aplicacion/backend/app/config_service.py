"""
Configuración de la plataforma (qué motores se usan y a qué se permite escanear).

Se guarda en la tabla `configuracion`. Las variables de entorno siguen siendo el
candado de más alto nivel: aunque un administrador active "direcciones públicas"
en la pantalla, el servidor solo las permite si ALLOW_PUBLIC_SCANS=true. Así un
cambio hecho desde la web no puede, por sí solo, abrir el escáner hacia internet.
"""
import copy
import os
from datetime import timedelta
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.models import Configuracion
from app.tiempo import ahora_utc

CLAVE = "escaneo"
# Estos son los rangos de red que considero "de laboratorio": las redes privadas clásicas y el loopback.
# Se muestran en la pantalla de Configuración; la validación real la hace scanner.py con el módulo ipaddress.
RANGOS_PERMITIDOS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
]

# Configuración que se usa mientras nadie la haya cambiado. Por seguridad parte con ZAP apagado y sin permitir IPs públicas.
# Nikto aparece en la estructura, pero no está implementado: queda siempre apagado.
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


# Este es el candado del servidor: sale de la variable de entorno y no se puede cambiar desde la web.
def servidor_permite_publicas() -> bool:
    """Candado del servidor (variable de entorno)."""
    return os.getenv("ALLOW_PUBLIC_SCANS", "false").lower() == "true"


# Estos datos se calculan al momento (¿hay ZAP configurado?, rangos, candado del servidor). Se muestran en la web pero no se guardan en la BD.
def _completar(configuracion: Dict[str, Any]) -> Dict[str, Any]:
    """Valores calculados que se muestran en la web pero no se guardan."""
    resultado = copy.deepcopy(configuracion)
    from app import zap_client

    resultado["motores"]["zap"]["disponible"] = zap_client.disponible()  # ¿el operador configuró ZAP_URL?
    resultado["alcance"]["rangos"] = list(RANGOS_PERMITIDOS)
    resultado["alcance"]["publicas_permitidas_por_servidor"] = servidor_permite_publicas()
    return resultado


# Mezcla la configuración por defecto con lo que haya guardado, así si agrego una opción nueva, las instalaciones antiguas igual la tienen.
def _fusionar(base: Dict[str, Any], cambios: Dict[str, Any]) -> Dict[str, Any]:
    resultado = copy.deepcopy(base)
    for clave, valor in cambios.items():
        if isinstance(valor, dict) and isinstance(resultado.get(clave), dict):
            resultado[clave] = _fusionar(resultado[clave], valor)
        else:
            resultado[clave] = valor
    return resultado


def obtener(db: Session) -> Dict[str, Any]:
    fila = db.get(Configuracion, CLAVE)
    guardada = fila.valor if fila else {}
    return _completar(_fusionar(POR_DEFECTO, guardada))


# Guardo solo los campos que se pueden editar; si alguien manda datos de más (por ejemplo los calculados), se descartan.
def guardar(db: Session, configuracion: Dict[str, Any]) -> Dict[str, Any]:
    """Guarda solo lo que se puede cambiar (lo calculado se descarta)."""
    limpio = {
        "motores": {
            "nmap": configuracion["motores"]["nmap"],
            "zap": {clave: configuracion["motores"]["zap"][clave] for clave in ("activo", "escaneo_activo", "timeout_s")},
            "nikto": {"activo": False},
        },
        "alcance": {"permitir_publicas": bool(configuracion["alcance"]["permitir_publicas"])},
        "retencion_dias": configuracion["retencion_dias"],
    }
    fila = db.get(Configuracion, CLAVE)
    if fila is None:
        fila = Configuracion(clave=CLAVE, valor=limpio)
        db.add(fila)
    else:
        fila.valor = limpio
        fila.actualizado_en = ahora_utc()
    db.commit()
    return obtener(db)


# Las IPs públicas solo se escanean si el servidor lo permite Y el administrador lo activó. Los dos candados tienen que estar abiertos.
def publicas_efectivas(configuracion: Dict[str, Any]) -> bool:
    """Se escanean IP públicas solo si el servidor Y la configuración lo permiten."""
    return servidor_permite_publicas() and bool(configuracion["alcance"]["permitir_publicas"])


# Política de retención: borra evaluaciones viejas. Nunca borra la última completada de cada activo, porque es su estado actual,
# ni las que están corriendo. Con 0 días no borra nada.
def aplicar_retencion(db: Session) -> int:
    """Borra las evaluaciones más antiguas que `retencion_dias`, pero nunca la última evaluación
    completada de cada activo (es su estado actual). Devuelve cuántas borró. 0 días = sin límite.
    """
    from app.models import EstadoEvaluacion, Evaluacion

    dias = obtener(db)["retencion_dias"]
    if not dias:
        return 0
    limite = ahora_utc() - timedelta(days=dias)
    # Como las ordené de la más nueva a la más antigua, la primera que aparece por activo es la vigente.
    vigentes = {}  # activo_id -> id de su evaluación completada más reciente
    for evaluacion in (
        db.query(Evaluacion)
        .filter(Evaluacion.estado == EstadoEvaluacion.COMPLETADA)
        .order_by(Evaluacion.iniciada_en.desc())
        .all()
    ):
        vigentes.setdefault(evaluacion.activo_id, evaluacion.id)
    ids_vigentes = set(vigentes.values())
    borradas = 0
    for evaluacion in db.query(Evaluacion).filter(Evaluacion.iniciada_en < limite).all():
        if evaluacion.id in ids_vigentes or evaluacion.estado in (EstadoEvaluacion.PENDIENTE, EstadoEvaluacion.EN_PROGRESO):
            continue
        db.delete(evaluacion)
        borradas += 1
    if borradas:
        db.commit()
    return borradas
