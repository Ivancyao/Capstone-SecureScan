"""Motor de escaneo: ejecuta Nmap sobre un objetivo y devuelve los puertos abiertos.

Decisiones de diseño:
1. Solo se escanean redes privadas o loopback (laboratorio), salvo que se active ALLOW_PUBLIC_SCANS=true.
   Así no se puede escanear por error un sistema de terceros.
2. El nombre se resuelve a IP una sola vez, se valida y se escanea esa misma IP. Así un DNS
   no puede cambiar la respuesta entre la validación y el escaneo.
3. Nmap se llama con una lista de argumentos (sin shell) y la IP pasa antes por el módulo ipaddress.
4. Se usa escaneo TCP connect (-sT) porque no pide permisos de administrador.
"""
import ipaddress
import os
import re
import signal
import socket
import subprocess  # nosec B404
import time
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as ET  # la salida de Nmap incluye texto del objetivo: se parsea sin entidades externas

# Puertos bien conocidos (1-1024) + puertos típicos de desarrollo y bases de datos.
DEFAULT_PORTS = (
    "1-1024,1433,1521,3000,3306,3389,5000,5432,5900,6379,8000,8080,8443,9200,27017"
)
NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "300"))


class ScanError(Exception):
    """Error controlado del motor de escaneo (objetivo no permitido, Nmap falló, etc.)."""


def extraer_host(url_objetivo: str) -> str:
    """Obtiene el host desde 'http://host:puerto/ruta' o desde 'host' a secas."""
    texto = url_objetivo.strip()
    parsed = urlparse(texto if "://" in texto else f"//{texto}")
    host = parsed.hostname
    if not host:
        raise ScanError(f"No se pudo extraer un host válido de '{url_objetivo}'")
    return host


def resolver_y_validar(host: str, permitir_publicos: Optional[bool] = None) -> str:
    """Resuelve el host a una IP y revisa que sea un objetivo permitido.

    `permitir_publicos` viene de la configuración, pero la variable ALLOW_PUBLIC_SCANS manda sobre ella:
    si vale "false", la configuración no puede habilitar direcciones públicas.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError(f"No se pudo resolver el host '{host}'") from None

    candado_servidor = os.getenv("ALLOW_PUBLIC_SCANS", "false").lower() == "true"
    permitir_publicos = candado_servidor and (True if permitir_publicos is None else permitir_publicos)
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        es_laboratorio = ip.is_private or ip.is_loopback or ip.is_link_local
        if not es_laboratorio and not permitir_publicos:
            raise ScanError(
                f"Objetivo bloqueado: {ip} no pertenece a una red privada. "
                "SecureScan solo escanea ambientes de laboratorio controlados."
            )
        ips.append(ip)
    return str(ips[0])


def parsear_xml_nmap(xml_texto: str) -> List[Dict]:
    """Convierte la salida XML de Nmap en una lista de puertos abiertos."""
    try:
        root = ET.fromstring(xml_texto)
    except (ET.ParseError, DefusedXmlException):
        raise ScanError("No se pudo interpretar la salida de Nmap") from None

    resultados = []
    for port in root.findall("./host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        resultados.append(
            {
                "puerto": int(port.get("portid")),
                "protocolo": port.get("protocol", "tcp"),
                "servicio": (svc.get("name") if svc is not None else None) or "desconocido",
                "producto": (svc.get("product") if svc is not None else None) or "",
                "version": (svc.get("version") if svc is not None else None) or "",
            }
        )
    return sorted(resultados, key=lambda r: r["puerto"])


def argumentos_de_puertos(perfil: Optional[str], puertos: Optional[str]) -> List[str]:
    """Traduce el perfil elegido en la configuración a argumentos de Nmap."""
    if puertos:
        if not re.fullmatch(r"[0-9,\-]+", puertos):
            raise ScanError("La lista de puertos tiene caracteres no permitidos")
        return ["-p", puertos]
    if perfil == "rapido":
        return ["--top-ports", "100"]
    if perfil == "completo":
        return ["-p", "1-65535"]
    return ["-p", os.getenv("NMAP_PORTS", DEFAULT_PORTS)]


def _matar(proceso: "subprocess.Popen") -> None:
    """Termina el proceso y todo su grupo (así no quedan procesos hijos con las tuberías abiertas)."""
    try:
        os.killpg(proceso.pid, signal.SIGKILL)
    except (AttributeError, ProcessLookupError, PermissionError):
        proceso.kill()


def escanear_puertos(
    ip: str,
    puertos: Optional[str] = None,
    perfil: Optional[str] = None,
    timeout: Optional[int] = None,
    versiones: bool = True,
    cancelar: Optional[Callable[[], bool]] = None,
) -> List[Dict]:
    """Ejecuta Nmap (-sT, y -sV si `versiones`) sobre una IP ya validada y devuelve los puertos abiertos.

    Si se entrega `cancelar`, se revisa cada segundo y, si devuelve True, se termina el proceso
    de Nmap y se lanza EvaluacionCancelada.
    """
    ipaddress.ip_address(ip)  # lanza ValueError si no es una IP válida (defensa extra)
    timeout = timeout or NMAP_TIMEOUT
    comando = ["nmap", "-sT"] + (["-sV"] if versiones else []) + ["-T4"]
    comando += argumentos_de_puertos(perfil, puertos) + ["-oX", "-", ip]
    if cancelar is None:
        try:
            proceso = subprocess.run(  # nosec B603
                comando, capture_output=True, text=True, timeout=timeout, check=False
            )
        except FileNotFoundError:
            raise ScanError("Nmap no está instalado en el servidor") from None
        except subprocess.TimeoutExpired:
            raise ScanError(f"El escaneo superó el tiempo máximo ({timeout}s)") from None
        codigo, salida, errores = proceso.returncode, proceso.stdout, proceso.stderr
    else:
        from app.cancelacion import EvaluacionCancelada

        try:
            proceso = subprocess.Popen(  # nosec B603
                comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True
            )
        except FileNotFoundError:
            raise ScanError("Nmap no está instalado en el servidor") from None
        inicio = time.monotonic()
        while True:
            try:
                salida, errores = proceso.communicate(timeout=1)
                break
            except subprocess.TimeoutExpired:
                if cancelar():
                    _matar(proceso)
                    proceso.communicate()
                    raise EvaluacionCancelada() from None
                if time.monotonic() - inicio > timeout:
                    _matar(proceso)
                    proceso.communicate()
                    raise ScanError(f"El escaneo superó el tiempo máximo ({timeout}s)") from None
        codigo = proceso.returncode

    if codigo != 0:
        raise ScanError(f"Nmap terminó con error: {errores.strip()[:200]}")
    return parsear_xml_nmap(salida)
