"""Evaluación completa: escaneo -> clasificación de riesgo -> guardado en la base.

Corre en segundo plano (BackgroundTasks de FastAPI) con su propia sesión de BD, porque la sesión
de la petición ya se cerró cuando esta tarea se ejecuta. Así el usuario recibe respuesta de inmediato
y después consulta el estado.

Mientras corre se guardan `progreso` (0-100) y `etapa` para mostrar el avance en la web. El avance es
por etapas, no hay porcentaje dentro del escaneo de puertos.
"""
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app import config_service, risk, scanner, zap_client
from app.cancelacion import ETAPA_CANCELADA, EvaluacionCancelada
from app.database import SessionLocal
from app.models import EstadoEvaluacion, Evaluacion, Hallazgo
from app.tiempo import ahora_utc


# A ZAP no le paso el nombre del activo sino la IP que ya validé, para que analice exactamente lo que se autorizó.
# Si el activo es una URL con http/https la uso; si solo puse un host, busco algún puerto web entre los que encontró Nmap.
def url_para_zap(url_objetivo: str, ip: str, puertos: List[Dict]) -> Optional[str]:
    """Dirección web que se le pasa a ZAP, o None si el objetivo no es una aplicación web.

    Se usa la IP ya validada (no el nombre) para que ZAP analice lo mismo que se autorizó, igual que Nmap.
    Limitación: si la aplicación depende del nombre de host (hosts virtuales), puede no responder por IP.
    """
    texto = url_objetivo.strip()
    url_analizada = urlparse(texto if "://" in texto else f"//{texto}")
    host = f"[{ip}]" if ":" in ip else ip
    if "://" in texto:
        if url_analizada.scheme not in ("http", "https"):
            return None
        puerto = f":{url_analizada.port}" if url_analizada.port else ""
        return f"{url_analizada.scheme}://{host}{puerto}{url_analizada.path or '/'}"
    web = [puerto_web for puerto_web in puertos if puerto_web["servicio"].lower().startswith("http") or "ssl" in puerto_web["servicio"].lower()]
    if not web:
        return None
    elegido = next((puerto_web for puerto_web in web if "https" in puerto_web["servicio"].lower() or "ssl" in puerto_web["servicio"].lower()), web[0])
    esquema = "https" if ("https" in elegido["servicio"].lower() or "ssl" in elegido["servicio"].lower()) else "http"
    return f"{esquema}://{host}:{elegido['puerto']}/"


# Abro una sesión nueva cada vez porque así leo el dato real de la BD, no uno en caché (si el usuario canceló desde la web, lo veo al instante).
# También cuenta como cancelada si la evaluación ya no existe.
def esta_cancelada(evaluacion_id: str) -> bool:
    """True si el usuario canceló la evaluación o la eliminó. Usa una sesión propia para ver siempre el dato vigente."""
    with SessionLocal() as sesion:
        fila = sesion.query(Evaluacion.etapa).filter(Evaluacion.id == evaluacion_id).first()
    return fila is None or fila[0] == ETAPA_CANCELADA


# Cada vez que avanzo de etapa guardo el progreso (para la barra de la web) y de paso reviso si cancelaron.
def _avance(db, evaluacion, progreso: int, etapa: str) -> None:
    if esta_cancelada(evaluacion.id):
        raise EvaluacionCancelada()
    evaluacion.progreso = progreso
    evaluacion.etapa = etapa
    db.commit()


# Este es el corazón del sistema. Orden: validar el objetivo -> Nmap -> clasificar riesgo -> ZAP (opcional) -> guardar.
# Si me preguntan por qué corre en segundo plano: un escaneo puede tardar minutos y no quiero dejar la petición colgada, así que respondo al tiro y la web consulta el avance.
def ejecutar_evaluacion(evaluacion_id: str) -> None:
    db = SessionLocal()
    try:
        # Uso una sesión propia (SessionLocal) porque la de la petición ya se cerró cuando esto se ejecuta.
        evaluacion = db.get(Evaluacion, evaluacion_id)
        if evaluacion is None or esta_cancelada(evaluacion_id):
            return  # se canceló o eliminó mientras esperaba en la cola
        cancelada = lambda: esta_cancelada(evaluacion_id)  # noqa: E731
        evaluacion.estado = EstadoEvaluacion.EN_PROGRESO
        _avance(db, evaluacion, 5, "Validando el objetivo")

        try:
            configuracion = config_service.obtener(db)
            nmap = configuracion["motores"]["nmap"]
            if not nmap["activo"]:
                raise scanner.ScanError("El motor Nmap está desactivado en la configuración de la plataforma")

            # Primero saco el host, lo resuelvo a IP y verifico que sea un objetivo permitido. Si no lo es, se lanza ScanError y la evaluación queda fallida con el motivo.
            host = scanner.extraer_host(evaluacion.activo.url_objetivo)
            ip = scanner.resolver_y_validar(host, permitir_publicos=config_service.publicas_efectivas(configuracion))

            _avance(db, evaluacion, 15, "Escaneando puertos y servicios")
            # Acá corre Nmap con lo que dice la configuración (perfil de puertos, timeout y detección de versiones).
            puertos = scanner.escanear_puertos(
                ip,
                perfil=nmap["puertos"],
                timeout=nmap["timeout_s"],
                versiones=nmap["detectar_versiones"],
                cancelar=cancelada,
            )

            # ZAP solo corre si está activado en la configuración Y el servidor tiene configurada su URL.
            zap = configuracion["motores"]["zap"]
            con_zap = zap["activo"] and zap_client.disponible()
            _avance(db, evaluacion, 40 if con_zap else 85, "Clasificando el riesgo")
            # Cada puerto abierto pasa por el motor de riesgo (risk.py) y se guarda como hallazgo.
            for puerto in puertos:
                db.add(Hallazgo(evaluacion_id=evaluacion.id, **risk.clasificar_puerto(puerto)))

            if con_zap:
                # Un fallo de ZAP no debe perder lo que Nmap ya encontró: la evaluación termina
                # igual y deja una advertencia visible.
                _avance(db, evaluacion, 50, "Analizando la aplicación web (OWASP ZAP)")
                try:
                    url_zap = url_para_zap(evaluacion.activo.url_objetivo, ip, puertos)
                    if url_zap is None:
                        evaluacion.detalle_error = "No se ejecutó OWASP ZAP: no se detectó una aplicación web en el objetivo."
                    else:
                        cliente_zap = zap_client.ZapClient()
                        cliente_zap.cancelar = cancelada
                        for hallazgo_zap in cliente_zap.analizar(url_zap, zap["timeout_s"], zap["escaneo_activo"]):
                            db.add(Hallazgo(evaluacion_id=evaluacion.id, **hallazgo_zap))
                except EvaluacionCancelada:
                    raise
                # Decisión importante: si ZAP falla, no pierdo lo que Nmap ya encontró. La evaluación termina como completada y deja una advertencia visible.
                except zap_client.ZapError as exc:
                    evaluacion.detalle_error = f"OWASP ZAP no pudo completar el análisis: {exc}. Se conservan los resultados de Nmap."
                except Exception as exc:  # noqa: BLE001
                    evaluacion.detalle_error = f"OWASP ZAP falló de forma inesperada ({type(exc).__name__}). Se conservan los resultados de Nmap."
                _avance(db, evaluacion, 95, "Guardando resultados")

            if esta_cancelada(evaluacion_id):
                raise EvaluacionCancelada()
            evaluacion.estado = EstadoEvaluacion.COMPLETADA
            evaluacion.progreso = 100
            evaluacion.etapa = "Completada"
        except EvaluacionCancelada:
            # La API ya dejó la evaluación como cancelada: aquí solo se descarta lo parcial.
            db.rollback()
            db.query(Hallazgo).filter(Hallazgo.evaluacion_id == evaluacion_id).delete()
            db.commit()
            return
        # Errores esperados (objetivo bloqueado, Nmap no instalado, timeout): la evaluación queda fallida con un mensaje entendible.
        except scanner.ScanError as exc:
            evaluacion.estado = EstadoEvaluacion.FALLIDA
            evaluacion.detalle_error = str(exc)
            evaluacion.etapa = "Falló"
        # Cualquier otro error inesperado: la dejo fallida igual, para que nunca quede "en progreso" para siempre.
        # El mensaje solo incluye el tipo de error, no el detalle, para no filtrar información interna.
        except Exception as exc:  # error inesperado: nunca dejar la evaluación "colgada"
            db.rollback()  # la sesión pudo quedar en estado fallido
            evaluacion = db.get(Evaluacion, evaluacion_id)
            evaluacion.estado = EstadoEvaluacion.FALLIDA
            evaluacion.detalle_error = f"Error inesperado: {type(exc).__name__}"
            evaluacion.etapa = "Falló"

        evaluacion.finalizada_en = ahora_utc()
        db.commit()
        # Al terminar cada evaluación aprovecho de aplicar la política de retención (borrar las muy antiguas).
        config_service.aplicar_retencion(db)
    finally:
        db.close()
