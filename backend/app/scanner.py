"""
Motor de escaneo: ejecuta Nmap sobre un objetivo y devuelve los puertos abiertos.

Decisiones de diseño (útiles para la defensa oral):
1. Solo se escanean objetivos de red privada/loopback (laboratorio) salvo que se active
   explícitamente ALLOW_PUBLIC_SCANS=true. Así la plataforma no puede usarse por error
   (o por mal uso) contra sistemas de terceros. Es el "ambiente controlado y autorizado".
2. Se resuelve el nombre a IP UNA vez, se valida esa IP y se escanea ESA IP. Así se evita
   que un DNS malicioso cambie de respuesta entre la validación y el escaneo.
3. Nmap se invoca con una lista de argumentos (sin shell), por lo que no hay inyección
   de comandos. La IP pasa por el módulo ipaddress antes de llegar al comando.
4. Escaneo TCP connect (-sT): no requiere privilegios de administrador.
"""
import ipaddress
import os
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from urllib.parse import urlparse

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
    """
    Resuelve el host a una IP y verifica que sea un objetivo permitido.

    `permitir_publicos` viene de la configuración de la plataforma, pero la variable de
    entorno ALLOW_PUBLIC_SCANS es siempre un candado superior: si vale "false", ninguna
    configuración puede habilitar direcciones públicas.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError(f"No se pudo resolver el host '{host}'")

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
    except ET.ParseError:
        raise ScanError("No se pudo interpretar la salida de Nmap")

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


def escanear_puertos(
    ip: str,
    puertos: Optional[str] = None,
    perfil: Optional[str] = None,
    timeout: Optional[int] = None,
    versiones: bool = True,
) -> List[Dict]:
    """Ejecuta Nmap (-sT, y -sV si `versiones`) sobre una IP ya validada y devuelve los puertos abiertos."""
    ipaddress.ip_address(ip)  # lanza ValueError si no es una IP válida (defensa extra)
    timeout = timeout or NMAP_TIMEOUT
    comando = ["nmap", "-sT"] + (["-sV"] if versiones else []) + ["-T4"]
    comando += argumentos_de_puertos(perfil, puertos) + ["-oX", "-", ip]
    try:
        proceso = subprocess.run(
            comando, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        raise ScanError("Nmap no está instalado en el servidor")
    except subprocess.TimeoutExpired:
        raise ScanError(f"El escaneo superó el tiempo máximo ({timeout}s)")

    if proceso.returncode != 0:
        raise ScanError(f"Nmap terminó con error: {proceso.stderr.strip()[:200]}")
    return parsear_xml_nmap(proceso.stdout)
