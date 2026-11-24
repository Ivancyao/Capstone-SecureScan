"""Cliente de OWASP ZAP (API REST) para analizar aplicaciones web.

Flujo: spider (descubre las páginas) -> espera el análisis pasivo -> escaneo activo (opcional) -> lectura
de alertas. ZAP corre en un contenedor aparte y aquí solo se le hacen peticiones.

Seguridad:
- El objetivo pasa por la misma validación que Nmap (solo redes privadas) antes de llegar aquí.
- El escaneo activo manda ataques de prueba al objetivo, por eso viene apagado y solo un administrador
  puede activarlo.
- Todo espera con un tiempo máximo, así una evaluación no queda colgada esperando a ZAP.

La severidad sale del nivel de riesgo de ZAP (High/Medium/Low/Info) y se traduce a un CVSS estimado por
nivel, no es un cálculo completo. ZAP no entrega nivel "crítica".
"""
import os
import re
import time
from collections import OrderedDict
from typing import Callable, Dict, List, Optional

import httpx

from app import risk
from app.cancelacion import EvaluacionCancelada
from app.zap_es import traducir


class ZapError(Exception):
    """Error controlado al hablar con ZAP (no disponible, tiempo agotado, respuesta inesperada)."""


def disponible() -> bool:
    """ZAP está 'disponible' solo si el operador configuró su dirección (variable ZAP_URL)."""
    return bool(os.getenv("ZAP_URL"))


class ZapClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        transport: Optional[httpx.BaseTransport] = None,
        dormir: Callable[[float], None] = time.sleep,
        intervalo: float = 2.0,
    ):
        self.base_url = (base_url or os.getenv("ZAP_URL", "")).rstrip("/")
        if not self.base_url:
            raise ZapError("OWASP ZAP no está configurado en el servidor (falta ZAP_URL)")
        self.api_key = api_key if api_key is not None else os.getenv("ZAP_API_KEY", "")
        self._http = httpx.Client(base_url=self.base_url, timeout=30, transport=transport)
        self._dormir = dormir
        self._intervalo = intervalo
        self.cancelar: Optional[Callable[[], bool]] = None  # si devuelve True, se detiene el análisis

    # ---------- bajo nivel ----------
    def _get(self, ruta: str, **params) -> Dict:
        if self.api_key:
            params["apikey"] = self.api_key
        try:
            respuesta = self._http.get(ruta, params=params)
        except httpx.HTTPError:
            raise ZapError(f"No se pudo conectar con OWASP ZAP en {self.base_url}") from None
        if respuesta.status_code in (401, 403):
            raise ZapError("OWASP ZAP rechazó la clave de API (revisa ZAP_API_KEY)")
        if respuesta.status_code >= 400:
            try:
                detalle = respuesta.json().get("message") or respuesta.json().get("code") or respuesta.text[:100]
            except ValueError:
                detalle = respuesta.text[:100]
            raise ZapError(f"OWASP ZAP respondió con error {respuesta.status_code}: {detalle}")
        try:
            return respuesta.json()
        except ValueError:
            raise ZapError("Respuesta inesperada de OWASP ZAP") from None

    def version(self) -> str:
        return str(self._get("/JSON/core/view/version/").get("version", "desconocida"))

    def _esperar(self, estado: Callable[[], bool], limite: float, que: str) -> None:
        inicio = time.monotonic()
        while not estado():
            if self.cancelar is not None and self.cancelar():
                self._detener()
                raise EvaluacionCancelada()
            if time.monotonic() - inicio > limite:
                raise ZapError(f"OWASP ZAP superó el tiempo máximo mientras {que}")
            self._dormir(self._intervalo)

    def _detener(self) -> None:
        """Pide a ZAP que pare lo que esté haciendo (mejor esfuerzo: un fallo aquí no importa)."""
        for componente in ("spider", "ascan"):
            try:
                self._get(f"/JSON/{componente}/action/stopAllScans/")
            except ZapError:
                pass

    # ---------- escaneo ----------
    def _lanzar_y_esperar(self, componente: str, url: str, limite: float, que: str, **extra) -> None:
        respuesta = self._get(f"/JSON/{componente}/action/scan/", url=url, **extra)
        scan_id = respuesta.get("scan")
        if scan_id is None:
            raise ZapError(f"OWASP ZAP no inició el análisis ({componente}): {respuesta}")

        def terminado() -> bool:
            estado = self._get(f"/JSON/{componente}/view/status/", scanId=scan_id).get("status")
            try:
                return int(estado) >= 100
            except (TypeError, ValueError):
                raise ZapError(f"Estado inesperado de ZAP ({componente}): {estado!r}") from None

        self._esperar(terminado, limite, que)

    def alertas(self, url: str) -> List[Dict]:
        """Todas las alertas de ZAP para el objetivo, leídas por páginas."""
        todas, inicio, lote = [], 0, 500
        while True:
            pagina = self._get("/JSON/core/view/alerts/", baseurl=url, start=inicio, count=lote).get("alerts", [])
            todas += pagina
            if len(pagina) < lote:
                return todas
            inicio += lote

    def analizar(self, url: str, limite_s: int = 600, activo: bool = False) -> List[Dict]:
        """Ejecuta el análisis y devuelve los hallazgos ya agrupados (ver `agrupar_alertas`)."""
        self._lanzar_y_esperar("spider", url, limite_s, "exploraba el sitio", recurse="true")
        self._esperar(
            lambda: int(self._get("/JSON/pscan/view/recordsToScan/").get("recordsToScan", 0)) == 0,
            limite_s,
            "terminaba el análisis pasivo",
        )
        if activo:
            self._lanzar_y_esperar("ascan", url, limite_s, "ejecutaba el escaneo activo", recurse="true")
        return agrupar_alertas(self.alertas(url))


# ---------- traducción de alertas a hallazgos ----------
_RIESGO = {"3": "alta", "2": "media", "1": "baja", "0": "informativa"}
# El API real de ZAP (core/view/alerts) entrega el nivel como texto en "risk" ("High", "Medium", ...);
# algunos formatos de reporte traen además el código numérico en "riskcode". Se aceptan ambos.
_RIESGO_TEXTO = {"high": "alta", "medium": "media", "low": "baja", "informational": "informativa", "info": "informativa"}


def severidad_zap(alerta: Dict) -> str:
    """Nivel de riesgo de una alerta de ZAP (alta, media, baja o informativa). Nunca devuelve crítica."""
    codigo = alerta.get("riskcode")
    if codigo is not None and str(codigo) in _RIESGO:
        return _RIESGO[str(codigo)]
    texto = str(alerta.get("risk") or "").strip().lower()
    # ZAP a veces anota la confianza: "Medium (High)"; se usa solo el primer término
    return _RIESGO_TEXTO.get(texto.split(" ")[0], "informativa")
_CVSS_ESTIMADO = {"alta": 7.5, "media": 5.3, "baja": 3.1, "informativa": 0.0}
OWASP_2021 = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery",
}
_ETIQUETA = re.compile(r"<[^>]+>")


def _limpio(texto: Optional[str], maximo: int) -> str:
    """ZAP entrega HTML en descripción y solución; se deja texto plano y acotado."""
    texto_limpio = _ETIQUETA.sub(" ", (texto or "").replace("</p>", "\n"))
    texto_limpio = re.sub(r"[ \t]+", " ", texto_limpio)
    texto_limpio = re.sub(r"\s*\n\s*", " ", texto_limpio).strip()
    return texto_limpio if len(texto_limpio) <= maximo else texto_limpio[: maximo - 1].rstrip() + "…"


def categoria_owasp(alerta: Dict) -> Optional[str]:
    """Busca etiquetas como 'OWASP_2021_A03' en la alerta (ZAP 2.11 en adelante)."""
    for etiqueta in (alerta.get("tags") or {}):
        coincidencia = re.fullmatch(r"OWASP_2021_(A\d{2})", str(etiqueta))
        if coincidencia and coincidencia.group(1) in OWASP_2021:
            return OWASP_2021[coincidencia.group(1)]
    return None


def agrupar_alertas(alertas: List[Dict]) -> List[Dict]:
    """
    ZAP devuelve una alerta por cada URL afectada (pueden ser cientos del mismo tipo). Se agrupan
    por tipo de alerta: un hallazgo por tipo, con el número de instancias y algunos ejemplos.
    Devuelve dicts listos para crear un Hallazgo.
    """
    grupos: "OrderedDict[str, List[Dict]]" = OrderedDict()
    for alerta in alertas:
        grupos.setdefault(f"{alerta.get('pluginId', '')}|{alerta.get('alert') or alerta.get('name', '')}", []).append(alerta)

    hallazgos = []
    for items in grupos.values():
        alerta = items[0]
        severidad = severidad_zap(alerta)
        cvss = _CVSS_ESTIMADO[severidad]
        ejemplos = []
        for instancia in items[:3]:
            descripcion_de_ejemplo = instancia.get("url", "")
            if instancia.get("param"):
                descripcion_de_ejemplo += f" (parámetro: {instancia['param']})"
            ejemplos.append(descripcion_de_ejemplo)
        evidencia = f"{len(items)} instancia(s). Ejemplos: " + "; ".join(ejemplos)
        if alerta.get("evidence"):
            evidencia += f". Evidencia: {_limpio(alerta['evidence'], 160)}"
        original = (alerta.get("alert") or alerta.get("name") or "Alerta de ZAP")
        traduccion = traducir(alerta)
        if traduccion:
            nombre, desc, recomendacion = traduccion
            evidencia += f". {desc} (Alerta original de ZAP: {original}.)"
        else:
            # Alerta fuera del catálogo: se conserva el texto original de ZAP (en inglés) y se avisa
            nombre = original
            desc = _limpio(alerta.get("description"), 280)
            if desc:
                evidencia += f". Descripción original de ZAP (en inglés): {desc}"
            recomendacion = _limpio(alerta.get("solution"), 600) or "Revisar la alerta en OWASP ZAP y corregir según su guía."
        hallazgos.append(
            {
                "nombre_vulnerabilidad": nombre[:200],
                "categoria_owasp": categoria_owasp(alerta),
                "cvss_score": cvss,
                "severidad": risk.severidad_desde_cvss(cvss),
                "evidencia": evidencia[:1500],
                "recomendacion": recomendacion,
                "herramienta_origen": "owasp_zap",
            }
        )
    orden = {"alta": 0, "media": 1, "baja": 2, "informativa": 3}
    return sorted(hallazgos, key=lambda hallazgo: (orden[hallazgo["severidad"].value], hallazgo["nombre_vulnerabilidad"]))
