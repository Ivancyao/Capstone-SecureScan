"""
Motor de riesgo: traduce un puerto/servicio abierto a un hallazgo de negocio.

IMPORTANTE (honestidad técnica): el puntaje CVSS que asigna este motor es una ESTIMACIÓN
basada en reglas según el tipo de servicio expuesto. No es un cálculo vectorial completo
de CVSS (que requiere vector de ataque, complejidad, impacto, etc.). Para el MVP sirve para
priorizar; una mejora futura es calcular el vector CVSS v3.1 completo.

La severidad se deriva del puntaje con las bandas oficiales de CVSS v3.1:
  0.0 Informativa | 0.1-3.9 Baja | 4.0-6.9 Media | 7.0-8.9 Alta | 9.0-10.0 Crítica
"""
from typing import Dict

from app.models import SeveridadHallazgo

A02 = "A02:2021 - Cryptographic Failures"
A05 = "A05:2021 - Security Misconfiguration"

DB_PUERTOS = {
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def severidad_desde_cvss(cvss: float) -> SeveridadHallazgo:
    if cvss <= 0:
        return SeveridadHallazgo.INFORMATIVA
    if cvss < 4.0:
        return SeveridadHallazgo.BAJA
    if cvss < 7.0:
        return SeveridadHallazgo.MEDIA
    if cvss < 9.0:
        return SeveridadHallazgo.ALTA
    return SeveridadHallazgo.CRITICA


def _regla(puerto: int, servicio: str):
    """Devuelve (nombre, owasp, cvss_estimado, recomendación) según el servicio."""
    s = servicio.lower()
    if puerto == 23 or s == "telnet":
        return ("Telnet expuesto (credenciales sin cifrar)", A02, 7.5,
                "Deshabilitar Telnet y reemplazarlo por SSH con autenticación por llave.")
    if puerto == 21 or s == "ftp":
        return ("FTP expuesto (tráfico sin cifrar)", A02, 5.3,
                "Reemplazar FTP por SFTP o FTPS y restringir el acceso por IP.")
    if puerto in (139, 445) or s in ("microsoft-ds", "netbios-ssn"):
        return ("SMB/NetBIOS expuesto", A05, 7.5,
                "No exponer SMB fuera de la red interna; aplicar reglas de firewall.")
    if puerto == 3389 or s == "ms-wbt-server":
        return ("Escritorio remoto (RDP) expuesto", A05, 7.5,
                "Restringir RDP mediante VPN o lista de IP permitidas y exigir MFA.")
    if puerto in DB_PUERTOS:
        return (f"Base de datos expuesta ({DB_PUERTOS[puerto]})", A05, 7.5,
                "Las bases de datos no deben ser accesibles desde la red; limitar a la capa de aplicación.")
    if puerto == 22 or s == "ssh":
        return ("Servicio SSH expuesto", A05, 3.7,
                "Deshabilitar login por contraseña, usar llaves y limitar IPs de origen.")
    if puerto == 5900 or s == "vnc":
        return ("VNC expuesto", A05, 7.5,
                "No exponer VNC directamente; usar túnel SSH o VPN.")
    if s.startswith("http") and "ssl" not in s and "https" not in s:
        return ("Servicio HTTP expuesto sin cifrado", A05, 5.3,
                "Configurar HTTPS (TLS), redirigir HTTP a HTTPS y restringir servicios innecesarios.")
    if "https" in s or "ssl" in s:
        return ("Servicio HTTPS expuesto", A05, 0.0,
                "Verificar la configuración TLS (versiones y cifrados vigentes) y renovar certificados a tiempo.")
    return (f"Puerto {puerto}/tcp abierto ({servicio})", A05, 0.0,
            "Confirmar que el servicio es necesario; si no lo es, cerrar el puerto.")


def clasificar_puerto(p: Dict) -> Dict:
    """Convierte un puerto abierto (dict del escáner) en los campos de un Hallazgo."""
    nombre, owasp, cvss, recomendacion = _regla(p["puerto"], p["servicio"])
    detalle_servicio = " ".join(x for x in (p["producto"], p["version"]) if x)
    evidencia = f"Puerto {p['puerto']}/{p['protocolo']} abierto — servicio: {p['servicio']}"
    if detalle_servicio:
        evidencia += f" ({detalle_servicio})"
    return {
        "nombre_vulnerabilidad": nombre,
        "categoria_owasp": owasp,
        "cvss_score": cvss,
        "severidad": severidad_desde_cvss(cvss),
        "evidencia": evidencia,
        "recomendacion": recomendacion,
        "herramienta_origen": "nmap",
    }
