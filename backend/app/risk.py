"""Motor de riesgo: convierte un puerto o servicio abierto en un hallazgo.

Ojo: el puntaje CVSS de este módulo es una estimación según el tipo de servicio expuesto, no un
cálculo completo del vector CVSS. Sirve para priorizar. Como mejora futura queda calcular el
vector CVSS v3.1 completo (o usar los valores de la base NVD).

La severidad sale del puntaje con las bandas de CVSS v3.1:
  0.0 Informativa | 0.1-3.9 Baja | 4.0-6.9 Media | 7.0-8.9 Alta | 9.0-10.0 Crítica
"""
from typing import Dict

from app.models import SeveridadHallazgo

# Categorías del OWASP Top 10 (2021) que uso para clasificar los hallazgos de puertos.
A02 = "A02:2021 - Cryptographic Failures"
A05 = "A05:2021 - Security Misconfiguration"

# Puertos típicos de bases de datos: si están abiertos hacia afuera, es un riesgo alto.
DB_PUERTOS = {
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


# La severidad sale del puntaje CVSS usando las bandas oficiales de CVSS v3.1 (baja < 4, media < 7, alta < 9, crítica desde 9).
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


# Acá está la "base de conocimiento" del motor: una regla por tipo de servicio.
# OJO, y es algo que sé que me van a preguntar: el CVSS es una estimación mía por tipo de servicio (por ejemplo 7.5 para RDP o bases de datos),
# no el cálculo completo del vector. Sirve para priorizar, no es un puntaje oficial.
def _regla(puerto: int, servicio: str):
    """Devuelve (nombre, owasp, cvss_estimado, recomendación) según el servicio."""
    servicio_en_minuscula = servicio.lower()
    if puerto == 23 or servicio_en_minuscula == "telnet":
        return ("Telnet expuesto (credenciales sin cifrar)", A02, 7.5,
                "Deshabilitar Telnet y reemplazarlo por SSH con autenticación por llave.")
    if puerto == 21 or servicio_en_minuscula == "ftp":
        return ("FTP expuesto (tráfico sin cifrar)", A02, 5.3,
                "Reemplazar FTP por SFTP o FTPS y restringir el acceso por IP.")
    if puerto in (139, 445) or servicio_en_minuscula in ("microsoft-ds", "netbios-ssn"):
        return ("SMB/NetBIOS expuesto", A05, 7.5,
                "No exponer SMB fuera de la red interna; aplicar reglas de firewall.")
    if puerto == 3389 or servicio_en_minuscula == "ms-wbt-server":
        return ("Escritorio remoto (RDP) expuesto", A05, 7.5,
                "Restringir RDP mediante VPN o lista de IP permitidas y exigir MFA.")
    if puerto in DB_PUERTOS:
        return (f"Base de datos expuesta ({DB_PUERTOS[puerto]})", A05, 7.5,
                "Las bases de datos no deben ser accesibles desde la red; limitar a la capa de aplicación.")
    if puerto == 22 or servicio_en_minuscula == "ssh":
        return ("Servicio SSH expuesto", A05, 3.7,
                "Deshabilitar login por contraseña, usar llaves y limitar IPs de origen.")
    if puerto == 5900 or servicio_en_minuscula == "vnc":
        return ("VNC expuesto", A05, 7.5,
                "No exponer VNC directamente; usar túnel SSH o VPN.")
    # HTTP sin cifrado es riesgo medio. Si ya es HTTPS, solo dejo una recomendación (CVSS 0).
    if servicio_en_minuscula.startswith("http") and "ssl" not in servicio_en_minuscula and "https" not in servicio_en_minuscula:
        return ("Servicio HTTP expuesto sin cifrado", A05, 5.3,
                "Configurar HTTPS (TLS), redirigir HTTP a HTTPS y restringir servicios innecesarios.")
    if "https" in servicio_en_minuscula or "ssl" in servicio_en_minuscula:
        return ("Servicio HTTPS expuesto", A05, 0.0,
                "Verificar la configuración TLS (versiones y cifrados vigentes) y renovar certificados a tiempo.")
    # Si no calza con ninguna regla, igual lo registro como informativo para que el usuario sepa que ese puerto está abierto.
    return (f"Puerto {puerto}/tcp abierto ({servicio})", A05, 0.0,
            "Confirmar que el servicio es necesario; si no lo es, cerrar el puerto.")


# Toma un puerto que encontró Nmap y arma los datos del hallazgo (nombre, severidad, evidencia y recomendación).
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
