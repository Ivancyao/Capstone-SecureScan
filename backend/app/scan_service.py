"""
Orquestación de una evaluación: escaneo -> clasificación de riesgo -> persistencia.

Se ejecuta en segundo plano (FastAPI BackgroundTasks) con su PROPIA sesión de BD,
porque la sesión de la petición HTTP ya se cerró cuando esta tarea corre.
Así el usuario recibe respuesta inmediata y consulta el estado después.

Mientras corre, la evaluación guarda `progreso` (0-100) y `etapa`, para que la web
muestre el avance en vivo. Nmap es un único proceso, así que el avance es por etapas
(no hay porcentaje fino dentro del escaneo de puertos).
"""
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app import config_service, risk, scanner, zap_client
from app.database import SessionLocal
from app.models import EstadoEvaluacion, Evaluacion, Hallazgo


def url_para_zap(url_objetivo: str, ip: str, puertos: List[Dict]) -> Optional[str]:
    """
    Dirección web que se le entrega a ZAP, o None si el objetivo no es una aplicación web.

    Se usa la IP YA VALIDADA (no el nombre) para que ZAP analice exactamente lo que se autorizó,
    igual que con Nmap. Limitación: una aplicación que depende del nombre de host (hosts virtuales)
    puede no responder por IP.
    """
    texto = url_objetivo.strip()
    p = urlparse(texto if "://" in texto else f"//{texto}")
    host = f"[{ip}]" if ":" in ip else ip
    if "://" in texto:
        if p.scheme not in ("http", "https"):
            return None
        puerto = f":{p.port}" if p.port else ""
        return f"{p.scheme}://{host}{puerto}{p.path or '/'}"
    web = [x for x in puertos if x["servicio"].lower().startswith("http") or "ssl" in x["servicio"].lower()]
    if not web:
        return None
    elegido = next((x for x in web if "https" in x["servicio"].lower() or "ssl" in x["servicio"].lower()), web[0])
    esquema = "https" if ("https" in elegido["servicio"].lower() or "ssl" in elegido["servicio"].lower()) else "http"
    return f"{esquema}://{host}:{elegido['puerto']}/"


def _avance(db, evaluacion, progreso: int, etapa: str) -> None:
    evaluacion.progreso = progreso
    evaluacion.etapa = etapa
    db.commit()


def ejecutar_evaluacion(evaluacion_id: str) -> None:
    db = SessionLocal()
    try:
        evaluacion = db.get(Evaluacion, evaluacion_id)
        if evaluacion is None:
            return
        evaluacion.estado = EstadoEvaluacion.EN_PROGRESO
        _avance(db, evaluacion, 5, "Validando el objetivo")

        try:
            cfg = config_service.obtener(db)
            nmap = cfg["motores"]["nmap"]
            if not nmap["activo"]:
                raise scanner.ScanError("El motor Nmap está desactivado en la configuración de la plataforma")

            host = scanner.extraer_host(evaluacion.activo.url_objetivo)
            ip = scanner.resolver_y_validar(host, permitir_publicos=config_service.publicas_efectivas(cfg))

            _avance(db, evaluacion, 15, "Escaneando puertos y servicios")
            puertos = scanner.escanear_puertos(
                ip,
                perfil=nmap["puertos"],
                timeout=nmap["timeout_s"],
                versiones=nmap["detectar_versiones"],
            )

            zap = cfg["motores"]["zap"]
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
                        for h in zap_client.ZapClient().analizar(url_zap, zap["timeout_s"], zap["escaneo_activo"]):
                            db.add(Hallazgo(evaluacion_id=evaluacion.id, **h))
                except zap_client.ZapError as exc:
                    evaluacion.detalle_error = f"OWASP ZAP no pudo completar el análisis: {exc}. Se conservan los resultados de Nmap."
                except Exception as exc:  # noqa: BLE001
                    evaluacion.detalle_error = f"OWASP ZAP falló de forma inesperada ({type(exc).__name__}). Se conservan los resultados de Nmap."
                _avance(db, evaluacion, 95, "Guardando resultados")

            evaluacion.estado = EstadoEvaluacion.COMPLETADA
            evaluacion.progreso = 100
            evaluacion.etapa = "Completada"
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

        evaluacion.finalizada_en = datetime.utcnow()
        db.commit()
        config_service.aplicar_retencion(db)
    finally:
        db.close()
