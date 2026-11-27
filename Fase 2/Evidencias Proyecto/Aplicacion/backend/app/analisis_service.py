"""Análisis rápido de una URL o de un archivo.

Usa tres fuentes:
1. VirusTotal: reputación de la URL o del archivo según varios motores antivirus. Necesita VIRUSTOTAL_API_KEY
   en el servidor; si no está, se omite y el resultado lo indica.
2. Señales locales: huella SHA-256, firma de ejecutable, doble extensión, prueba EICAR y, en las URL,
   IP literal, "@", punycode, muchos subdominios. Son pistas, no un veredicto.
3. Revisión de cabeceras de seguridad (HSTS, CSP, X-Frame-Options...). Esta sí contacta el sitio, así que
   sigue las mismas reglas de objetivos que los escaneos.

El archivo no se guarda en disco ni en la base de datos, y solo se sube a VirusTotal si el usuario lo
autoriza. La clave de API nunca llega al navegador.
"""
import base64
import hashlib
import ipaddress
import os
import re
import time
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app import config_service, scanner
from app.database import SessionLocal
from app.models import Analisis
from app.tiempo import ahora_utc

# Dirección de la API v3 de VirusTotal. La clave (VIRUSTOTAL_API_KEY) vive solo en el servidor: el navegador nunca la ve.
VT_BASE = "https://www.virustotal.com/api/v3"
# Límite de tamaño de archivo: 20 MB por defecto, configurable en el .env.
MAX_ARCHIVO_BYTES = int(os.getenv("ANALISIS_MAX_MB", "20")) * 1024 * 1024  # VirusTotal acepta hasta 32 MB
# EICAR es un texto de prueba estándar que todos los antivirus detectan a propósito, pero es inofensivo. Lo uso para demostrar que el análisis funciona sin usar malware real.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"  # archivo de prueba estándar, inofensivo

# Listas que uso para detectar trucos como "factura.pdf.exe" (un ejecutable disfrazado de documento).
EXTENSIONES_EJECUTABLES = {".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".msi", ".ps1", ".vbs", ".js", ".jar", ".sh", ".apk", ".lnk"}
EXTENSIONES_DOCUMENTO = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar"}
# Acortadores de enlaces conocidos: ocultan el destino real, por eso los marco como señal.
ACORTADORES = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}


# Errores esperables (sin clave, límite de la API, sin internet). El mensaje se le muestra tal cual al usuario.
class AnalisisError(Exception):
    """Fallo esperable (clave ausente, límite de la API, red); el mensaje se muestra al usuario."""


# ---------------- VirusTotal ----------------
def clave_virustotal() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "").strip()


def virustotal_configurado() -> bool:
    return bool(clave_virustotal())


# Cliente de VirusTotal. Igual que con ZAP, recibe transporte y función de espera por parámetro para poder probarlo sin llamar a internet.
class VirusTotal:
    def __init__(self, api_key: Optional[str] = None, transport: Optional[httpx.BaseTransport] = None,
                 dormir: Callable[[float], None] = time.sleep, espera_max: float = 90.0):
        self.api_key = api_key if api_key is not None else clave_virustotal()
        if not self.api_key:
            raise AnalisisError("VirusTotal no está configurado en el servidor (falta VIRUSTOTAL_API_KEY).")
        self._http = httpx.Client(base_url=VT_BASE, headers={"x-apikey": self.api_key}, timeout=30, transport=transport)
        self._dormir = dormir
        self._espera_max = espera_max

    # Todas las llamadas pasan por acá. Un 404 significa "VirusTotal no conoce esto" (no es un error); el 429 es el límite del plan gratis (4 consultas por minuto).
    def _pedir(self, metodo: str, ruta: str, **opciones) -> Optional[Dict]:
        try:
            respuesta = self._http.request(metodo, ruta, **opciones)
        except httpx.HTTPError:
            raise AnalisisError("No se pudo conectar con VirusTotal. Revisa la conexión a internet del servidor.") from None
        if respuesta.status_code == 404:
            return None
        if respuesta.status_code in (401, 403):
            raise AnalisisError("VirusTotal rechazó la clave de API (revisa VIRUSTOTAL_API_KEY).")
        if respuesta.status_code == 429:
            raise AnalisisError("Se alcanzó el límite de consultas de VirusTotal (la cuenta gratuita permite 4 por minuto). Intenta de nuevo en un minuto.")
        if respuesta.status_code >= 400:
            raise AnalisisError(f"VirusTotal respondió con error {respuesta.status_code}.")
        try:
            return respuesta.json()
        except ValueError:
            raise AnalisisError("Respuesta inesperada de VirusTotal.") from None

    # VirusTotal identifica las URL por su base64 sin los "=" del final.
    @staticmethod
    def _id_url(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    # Primero pregunto si VirusTotal ya conoce la URL o el archivo (gratis y rápido). Solo si no lo conoce, lo envío a analizar.
    def informe_url(self, url: str) -> Optional[Dict]:
        respuesta_json = self._pedir("GET", f"/urls/{self._id_url(url)}")
        return resumir_informe(respuesta_json) if respuesta_json else None

    def informe_archivo(self, sha256: str) -> Optional[Dict]:
        respuesta_json = self._pedir("GET", f"/files/{sha256}")
        return resumir_informe(respuesta_json) if respuesta_json else None

    # El análisis de VirusTotal no es instantáneo: consulto cada 5 segundos hasta 90 segundos como máximo.
    def _esperar_analisis(self, analisis_id: str) -> Dict:
        inicio = time.monotonic()
        while True:
            respuesta_json = self._pedir("GET", f"/analyses/{analisis_id}") or {}
            atributos = (respuesta_json.get("data") or {}).get("attributes") or {}
            if atributos.get("status") == "completed":
                return resumir_informe({"data": {"attributes": {
                    "last_analysis_stats": atributos.get("stats") or {},
                    "last_analysis_results": atributos.get("results") or {},
                }}})
            if time.monotonic() - inicio > self._espera_max:
                raise AnalisisError("VirusTotal sigue analizando. Vuelve a consultar en unos minutos.")
            self._dormir(5)

    def enviar_url(self, url: str) -> Dict:
        respuesta_json = self._pedir("POST", "/urls", data={"url": url}) or {}
        analisis_id = (respuesta_json.get("data") or {}).get("id")
        if not analisis_id:
            raise AnalisisError("VirusTotal no aceptó la URL.")
        return self._esperar_analisis(analisis_id)

    def subir_archivo(self, nombre: str, contenido: bytes) -> Dict:
        respuesta_json = self._pedir("POST", "/files", files={"file": (nombre, contenido)}) or {}
        analisis_id = (respuesta_json.get("data") or {}).get("id")
        if not analisis_id:
            raise AnalisisError("VirusTotal no aceptó el archivo.")
        return self._esperar_analisis(analisis_id)


# La respuesta de VirusTotal es enorme. Me quedo solo con lo que muestro: cuántos motores dicen malicioso, sospechoso, inofensivo, y los 15 primeros que detectaron algo.
def resumir_informe(respuesta_json: Dict) -> Dict:
    """Reduce la respuesta de VirusTotal a lo que se muestra: conteos y los motores que detectaron algo."""
    atributos = (respuesta_json.get("data") or {}).get("attributes") or {}
    estadisticas = atributos.get("last_analysis_stats") or {}
    detecciones = [
        {"motor": motor, "resultado": (resultado_motor.get("result") or resultado_motor.get("category") or "")[:80], "categoria": resultado_motor.get("category")}
        for motor, resultado_motor in (atributos.get("last_analysis_results") or {}).items()
        if resultado_motor.get("category") in ("malicious", "suspicious")
    ]
    detecciones.sort(key=lambda deteccion: (deteccion["categoria"] != "malicious", deteccion["motor"].lower()))
    return {
        "malicioso": int(estadisticas.get("malicious", 0)),
        "sospechoso": int(estadisticas.get("suspicious", 0)),
        "inofensivo": int(estadisticas.get("harmless", 0)),
        "sin_deteccion": int(estadisticas.get("undetected", 0)),
        "motores": sum(int(cantidad) for clave, cantidad in estadisticas.items() if clave in ("malicious", "suspicious", "harmless", "undetected")),
        "detecciones": detecciones[:15],
        "tipo": atributos.get("type_description"),
        "nombre": atributos.get("meaningful_name"),
    }


# Así decido el veredicto: una señal local concluyente (EICAR) manda; si no, uso VirusTotal (3 o más motores = malicioso, 1 o 2 = sospechoso, 0 = limpio);
# si VirusTotal no sabe nada, me baso en las señales locales. Nunca digo "seguro" a secas: "limpio" significa solo sin detecciones.
def veredicto_de(informe_vt: Optional[Dict], senales: List[Dict]) -> str:
    """limpio | sospechoso | malicioso | sin_datos"""
    if any(senal["nivel"] == "alto" and senal.get("concluyente") for senal in senales):
        return "malicioso"  # p. ej. el archivo de prueba EICAR
    if informe_vt and informe_vt["motores"] > 0:
        if informe_vt["malicioso"] >= 3:
            return "malicioso"
        if informe_vt["malicioso"] >= 1 or informe_vt["sospechoso"] >= 1:
            return "sospechoso"
        return "limpio"
    if any(senal["nivel"] in ("alto", "medio") for senal in senales):
        return "sospechoso"
    return "sin_datos"


# ---------------- Señales locales ----------------
# Una "señal" es una pista local con su nivel de riesgo (bajo, medio, alto). No es un veredicto por sí sola.
def sena(codigo: str, nivel: str, texto: str, concluyente: bool = False) -> Dict:
    return {"codigo": codigo, "nivel": nivel, "texto": texto, "concluyente": concluyente}


# Reviso el archivo solo mirando su contenido en memoria: la firma EICAR, los primeros bytes (MZ = ejecutable de Windows, ELF = de Linux), la doble extensión y si la extensión no coincide con el contenido.
def senales_archivo(nombre: str, contenido: bytes) -> List[Dict]:
    senales: List[Dict] = []
    if EICAR in contenido[:1024]:
        senales.append(sena("eicar", "alto", "Contiene la firma de prueba EICAR: los antivirus la detectan a propósito. Es inofensiva, pero confirma que el análisis funciona.", True))
    cabecera = contenido[:4]
    if cabecera[:2] == b"MZ":
        senales.append(sena("ejecutable_windows", "medio", "Es un ejecutable de Windows (formato PE). Ábrelo solo si confías en el origen."))
    elif cabecera == b"\x7fELF":
        senales.append(sena("ejecutable_linux", "medio", "Es un ejecutable de Linux (formato ELF)."))
    elif contenido[:2] == b"#!":
        senales.append(sena("script", "bajo", "Es un script que se ejecuta con un intérprete."))
    partes = nombre.lower().split(".")
    if len(partes) >= 3 and f".{partes[-1]}" in EXTENSIONES_EJECUTABLES and f".{partes[-2]}" in EXTENSIONES_DOCUMENTO:
        senales.append(sena("doble_extension", "alto", f"Doble extensión «.{partes[-2]}.{partes[-1]}»: un ejecutable disfrazado de documento es una táctica común de malware."))
    elif f".{partes[-1]}" in EXTENSIONES_EJECUTABLES and len(partes) > 1:
        senales.append(sena("extension_ejecutable", "bajo", f"La extensión .{partes[-1]} puede ejecutar código."))
    if f".{partes[-1]}" in EXTENSIONES_DOCUMENTO and (cabecera[:2] == b"MZ" or cabecera == b"\x7fELF"):
        senales.append(sena("extension_no_coincide", "alto", "La extensión dice que es un documento, pero el contenido es un ejecutable."))
    return senales


# Pistas típicas de phishing: sin HTTPS, IP en vez de nombre, "@" en la URL, punycode, acortadores, muchos subdominios y URL muy larga.
def senales_url(url: str) -> List[Dict]:
    senales: List[Dict] = []
    url_analizada = urlparse(url)
    host = (url_analizada.hostname or "").lower()
    if url_analizada.scheme == "http":
        senales.append(sena("sin_https", "bajo", "No usa HTTPS: el tráfico viaja sin cifrar."))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or ":" in host:
        senales.append(sena("ip_literal", "medio", "La dirección es una IP en vez de un nombre: es habitual en sitios temporales o de phishing."))
    if "@" in (url_analizada.netloc or ""):
        senales.append(sena("arroba", "alto", "Contiene «@» antes del dominio: el navegador ignora lo que va antes, una técnica para engañar."))
    if "xn--" in host:
        senales.append(sena("punycode", "medio", "El dominio usa punycode (xn--): puede imitar letras de otro alfabeto para parecerse a un sitio conocido."))
    if host in ACORTADORES:
        senales.append(sena("acortador", "medio", "Es un acortador de enlaces: oculta el destino real."))
    if host.count(".") >= 4:
        senales.append(sena("muchos_subdominios", "bajo", "Tiene muchos subdominios, común en direcciones que aparentan ser de otro sitio."))
    if len(url) > 200:
        senales.append(sena("url_larga", "bajo", "La URL es muy larga."))
    return senales


# ---------------- Revisión pasiva de cabeceras ----------------
# Cabeceras de seguridad que reviso: si faltan, el sitio queda más expuesto a ciertos ataques.
CABECERAS = [
    ("content-security-policy", "Falta la política de seguridad de contenido (CSP)", "Reduce el impacto de ataques XSS."),
    ("x-content-type-options", "Falta X-Content-Type-Options: nosniff", "Evita que el navegador adivine tipos de archivo."),
    ("referrer-policy", "Falta Referrer-Policy", "Controla cuánta información de navegación se filtra a otros sitios."),
]


# Esta es la única parte que contacta el sitio. Por eso le apliqué las mismas reglas que a los escaneos: solo redes permitidas, y se bloquea el propio servidor y las direcciones locales (protección SSRF).
def revisar_cabeceras(url: str, cliente: Optional[httpx.Client] = None) -> Dict:
    """Hace una sola petición GET para leer las cabeceras de seguridad. Si el objetivo no está permitido
    por las reglas de la plataforma, no se contacta y se explica por qué.
    """
    url_analizada = urlparse(url)
    if url_analizada.scheme not in ("http", "https") or not url_analizada.hostname:
        return {"contactado": False, "motivo": "La URL debe empezar con http:// o https://."}
    db = SessionLocal()
    try:
        permitir = config_service.publicas_efectivas(config_service.obtener(db))
    finally:
        db.close()
    try:
        ip = scanner.resolver_y_validar(url_analizada.hostname, permitir_publicos=permitir)
    except scanner.ScanError as exc:
        causa = str(exc).rstrip(". ")
        return {"contactado": False, "motivo": f"No se contactó el sitio. {causa}. La reputación (VirusTotal) sí se consulta sin tocar el sitio."}

    # SSRF: si alguien pone una URL que apunta al propio servidor o al servicio de metadatos de la nube, no la contacto.
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified:
        # Evita que el análisis de una URL llegue al propio servidor o al servicio de metadatos de la nube (SSRF).
        return {"contactado": False, "motivo": "No se contactó el sitio: apunta al propio servidor o a una dirección local. La reputación (VirusTotal) sí se consulta sin tocar el sitio."}

    puerto = url_analizada.port or (443 if url_analizada.scheme == "https" else 80)
    # Me conecto a la IP que ya validé (no al nombre) para que un DNS no pueda cambiar la respuesta entre la validación y la conexión.
    destino = f"{url_analizada.scheme}://{f'[{ip}]' if ':' in ip else ip}:{puerto}{url_analizada.path or '/'}"
    if url_analizada.query:
        destino += f"?{url_analizada.query}"
    propio = cliente is None
    # Se conecta a la IP ya validada (no al nombre), por eso se valida la IP y no el certificado.
    # verify=False porque me conecto por IP y el certificado no coincidiría. No es un descuido: la validación que importa acá es la de la IP. Tampoco sigo redirecciones, para no saltar a otro destino.
    cliente = cliente or httpx.Client(timeout=8, verify=False, follow_redirects=False)  # nosec B501
    try:
        with cliente.stream("GET", destino, headers={"Host": url_analizada.netloc, "User-Agent": "SecureScan/1.2 (revision pasiva)"},
                            extensions={"sni_hostname": url_analizada.hostname}) as respuesta:
            cabeceras_respuesta = {nombre.lower(): valor for nombre, valor in respuesta.headers.items()}
            cookies = respuesta.headers.get_list("set-cookie")
            codigo = respuesta.status_code
    except httpx.HTTPError as exc:
        return {"contactado": False, "motivo": f"El sitio no respondió ({type(exc).__name__})."}
    finally:
        if propio:
            cliente.close()

    # Ahora reviso qué cabeceras faltan, si hay HSTS, si el servidor revela su versión y si las cookies tienen HttpOnly y Secure.
    hallazgos: List[Dict] = []
    for nombre, titulo, porque in CABECERAS:
        if nombre not in cabeceras_respuesta:
            hallazgos.append({"titulo": titulo, "detalle": porque, "severidad": "media" if nombre == "content-security-policy" else "baja"})
    if "x-frame-options" not in cabeceras_respuesta and "frame-ancestors" not in cabeceras_respuesta.get("content-security-policy", ""):
        hallazgos.append({"titulo": "Falta protección contra clickjacking", "detalle": "Sin X-Frame-Options ni frame-ancestors, otro sitio podría incrustar esta página.", "severidad": "media"})
    if url_analizada.scheme == "https" and "strict-transport-security" not in cabeceras_respuesta:
        hallazgos.append({"titulo": "Falta HSTS (Strict-Transport-Security)", "detalle": "Sin HSTS, el navegador puede ser degradado a HTTP.", "severidad": "baja"})
    if url_analizada.scheme == "http":
        hallazgos.append({"titulo": "El sitio responde por HTTP sin cifrar", "detalle": "Los datos viajan en texto plano.", "severidad": "media"})
    servidor = cabeceras_respuesta.get("server", "")
    if re.search(r"\d+\.\d+", servidor) or "x-powered-by" in cabeceras_respuesta:
        hallazgos.append({"titulo": "Revela la tecnología y versión del servidor", "detalle": f"Cabecera: {servidor or cabeceras_respuesta.get('x-powered-by')}", "severidad": "baja"})
    for cookie in cookies:
        faltan = [atributo for atributo, ok in (("HttpOnly", "httponly" in cookie.lower()), ("Secure", "secure" in cookie.lower() or url_analizada.scheme == "http")) if not ok]
        if faltan:
            hallazgos.append({"titulo": f"Cookie sin {' ni '.join(faltan)}", "detalle": cookie.split("=")[0][:60], "severidad": "baja"})
    return {"contactado": True, "codigo_http": codigo, "hallazgos": hallazgos, "ip": ip}


# ---------------- Orquestación ----------------
# Cada actualización del análisis abre y cierra su propia sesión de BD. Si lo eliminaron mientras corría, no hago nada.
def _guardar(analisis_id: str, **campos) -> None:
    db = SessionLocal()
    try:
        analisis = db.get(Analisis, analisis_id)
        if analisis is None:
            return  # lo eliminaron mientras corría
        for campo, valor in campos.items():
            setattr(analisis, campo, valor)
        db.commit()
    finally:
        db.close()


# Texto corto que ve el usuario según el veredicto.
def _frase(veredicto: str, informe_vt: Optional[Dict], con_vt: bool) -> str:
    if veredicto == "malicioso":
        return f"Peligroso: {informe_vt['malicioso']} motores antivirus lo marcan como malicioso." if informe_vt and informe_vt["malicioso"] >= 3 else "Peligroso: se detectó una firma de malware conocida."
    if veredicto == "sospechoso":
        origen = "algún motor antivirus o indicador local" if informe_vt else "algún indicador local"
        return f"Sospechoso: {origen} lo señala. No lo abras ni lo compartas hasta confirmarlo."
    if veredicto == "limpio":
        return f"Sin detecciones: {informe_vt['motores']} motores no encontraron amenazas. Eso reduce el riesgo, pero no lo descarta."
    if not con_vt:
        return "Sin veredicto: VirusTotal no está configurado, solo hay indicadores locales."
    return "Sin veredicto: VirusTotal no conoce este elemento todavía."


# Orquestador del análisis rápido: señales locales -> VirusTotal (si hay clave) -> cabeceras (solo URLs) -> veredicto.
# Nunca lanza una excepción hacia afuera: si algo falla, el análisis queda con estado "error" y un mensaje.
def ejecutar_analisis(analisis_id: str, contenido: Optional[bytes] = None, subir: bool = False,
                      vt_cliente: Optional[VirusTotal] = None, cliente_http: Optional[httpx.Client] = None) -> None:
    """Corre en segundo plano con su propia sesión. Nunca lanza: los fallos quedan en el registro."""
    db = SessionLocal()
    try:
        analisis = db.get(Analisis, analisis_id)
        if analisis is None:
            return
        tipo, objetivo, sha = analisis.tipo, analisis.objetivo, analisis.sha256
    finally:
        db.close()

    detalle: Dict = {"virustotal": None, "senales": [], "cabeceras": None, "avisos": []}
    try:
        detalle["senales"] = senales_archivo(objetivo, contenido or b"") if tipo == "archivo" else senales_url(objetivo)
        informe_vt = None
        con_vt = virustotal_configurado() or vt_cliente is not None
        if con_vt:
            try:
                virustotal = vt_cliente or VirusTotal()
                if tipo == "url":
                    informe_vt = virustotal.informe_url(objetivo) or virustotal.enviar_url(objetivo)
                else:
                    informe_vt = virustotal.informe_archivo(sha)
                    # Un archivo solo se sube a VirusTotal si el usuario lo autoriza, porque lo que se sube lo puede ver la comunidad de seguridad.
                    if informe_vt is None and subir and contenido is not None:
                        informe_vt = virustotal.subir_archivo(objetivo, contenido)
                    elif informe_vt is None:
                        detalle["avisos"].append("VirusTotal no conoce este archivo. No se subió porque no lo pediste (lo que se sube pasa a ser visible para la comunidad de seguridad).")
            except AnalisisError as exc:
                detalle["avisos"].append(str(exc))
        else:
            detalle["avisos"].append("VirusTotal no está configurado en el servidor: se muestran solo indicadores locales.")
        detalle["virustotal"] = informe_vt
        if tipo == "url":
            detalle["cabeceras"] = revisar_cabeceras(objetivo, cliente_http)
        veredicto = veredicto_de(informe_vt, detalle["senales"])
        _guardar(analisis_id, estado="completado", veredicto=veredicto, detalle=detalle, finalizado_en=ahora_utc(),
                 resumen=_frase(veredicto, informe_vt, con_vt))
    except Exception as exc:  # noqa: BLE001  nunca dejar el análisis "pendiente" para siempre
        _guardar(analisis_id, estado="error", detalle=detalle, finalizado_en=ahora_utc(),
                 resumen=f"No se pudo completar el análisis ({type(exc).__name__}).")


# La huella SHA-256 identifica el archivo sin guardarlo.
def sha256_de(contenido: bytes) -> str:
    return hashlib.sha256(contenido).hexdigest()
