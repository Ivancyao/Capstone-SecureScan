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


def esta_cancelada(evaluacion_id: str) -> bool:
    """True si el usuario canceló la evaluación o la eliminó. Usa una sesión propia para ver siempre el dato vigente."""
    with SessionLocal() as sesion:
        fila = sesion.query(Evaluacion.etapa).filter(Evaluacion.id == evaluacion_id).first()
    return fila is None or fila[0] == ETAPA_CANCELADA


def _avance(db, evaluacion, progreso: int, etapa: str) -> None:
    if esta_cancelada(evaluacion.id):
        raise EvaluacionCancelada()
    evaluacion.progreso = progreso
    evaluacion.etapa = etapa
    db.commit()


def ejecutar_evaluacion(evaluacion_id: str) -> None:
    db = SessionLocal()
    try:
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

            host = scanner.extraer_host(evaluacion.activo.url_objetivo)
            ip = scanner.resolver_y_validar(host, permitir_publicos=config_service.publicas_efectivas(configuracion))

            _avance(db, evaluacion, 15, "Escaneando puertos y servicios")
            puertos = scanner.escanear_puertos(
                ip,
                perfil=nmap["puertos"],
                timeout=nmap["timeout_s"],
                versiones=nmap["detectar_versiones"],
                cancelar=cancelada,
            )

            zap = configuracion["motores"]["zap"]
            con_zap = zap["activo"] and zap_client.disponible()
            _avance(db, evaluacion, 40 if con_zap else 85, "Clasificando el riesgo")
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
        except scanner.ScanError as exc:
            evaluacion.estado = EstadoEvaluacion.FALLIDA
            evaluacion.detalle_error = str(exc)
            evaluacion.etapa = "Falló"
        except Exception as exc:  # error inesperado: nunca dejar la evaluación "colgada"
            db.rollback()  # la sesión pudo quedar en estado fallido
            evaluacion = db.get(Evaluacion, evaluacion_id)
            evaluacion.estado = EstadoEvaluacion.FALLIDA
            evaluacion.detalle_error = f"Error inesperado: {type(exc).__name__}"
            evaluacion.etapa = "Falló"

        evaluacion.finalizada_en = ahora_utc()
        db.commit()
        config_service.aplicar_retencion(db)
    finally:
        db.close()
