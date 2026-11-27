"""Pruebas del motor de escaneo, del motor de riesgo y del flujo de evaluación."""
import shutil
import socket
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

import pytest
from fastapi.testclient import TestClient

from app import risk, scanner
from app.database import Base, engine
from app.main import app
from app.models import SeveridadHallazgo

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


# ---------- Escáner ----------
# Saca el host desde URLs de distintos formatos.
@pytest.mark.parametrize(
    "entrada,esperado",
    [
        ("http://127.0.0.1:8080/app", "127.0.0.1"),
        ("https://lab.local", "lab.local"),
        ("192.168.1.10", "192.168.1.10"),
    ],
)
def test_extraer_host(entrada, esperado):
    assert scanner.extraer_host(entrada) == esperado


# Una IP pública se bloquea; también las direcciones link-local (como la de metadatos de la nube).
def test_bloquea_objetivo_publico():
    with pytest.raises(scanner.ScanError):
        scanner.resolver_y_validar("8.8.8.8")
    with pytest.raises(scanner.ScanError, match="link-local"):  # 169.254.169.254 = metadatos de la nube
        scanner.resolver_y_validar("169.254.169.254", permitir_publicos=True)


# Las redes privadas y el loopback sí se permiten.
def test_permite_objetivo_privado_y_loopback():
    assert scanner.resolver_y_validar("127.0.0.1") == "127.0.0.1"
    assert scanner.resolver_y_validar("192.168.1.10") == "192.168.1.10"


# Si lo que llega no es una IP válida, ni se ejecuta Nmap.
def test_ip_invalida_no_llega_a_nmap():
    with pytest.raises(ValueError):
        scanner.escanear_puertos("127.0.0.1; rm -rf /")  # intento de inyección de comandos


# De la salida XML de Nmap solo me quedo con los puertos abiertos.
def test_parsear_xml_solo_puertos_abiertos():
    xml = """<nmaprun><host><ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
    </ports></host></nmaprun>"""
    r = scanner.parsear_xml_nmap(xml)
    assert len(r) == 1 and r[0]["puerto"] == 22 and r[0]["producto"] == "OpenSSH"


# Esta prueba usa Nmap de verdad contra un servidor local; se salta si Nmap no está instalado (por eso hay 1 test "skipped").
@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap no instalado")
def test_nmap_real_detecta_servidor_local():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        puerto = s.getsockname()[1]
    servidor = HTTPServer(("127.0.0.1", puerto), SimpleHTTPRequestHandler)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        r = scanner.escanear_puertos("127.0.0.1", puertos=str(puerto))
        assert [p["puerto"] for p in r] == [puerto]
        assert r[0]["servicio"] == "http"
    finally:
        servidor.shutdown()


# ---------- Motor de riesgo ----------
# Verifica los límites entre severidades (por ejemplo 3.9 es baja y 4.0 es media).
@pytest.mark.parametrize(
    "cvss,esperada",
    [
        (0.0, SeveridadHallazgo.INFORMATIVA),
        (3.9, SeveridadHallazgo.BAJA),
        (4.0, SeveridadHallazgo.MEDIA),
        (6.9, SeveridadHallazgo.MEDIA),
        (7.0, SeveridadHallazgo.ALTA),
        (8.9, SeveridadHallazgo.ALTA),
        (9.0, SeveridadHallazgo.CRITICA),
    ],
)
def test_bandas_cvss(cvss, esperada):
    assert risk.severidad_desde_cvss(cvss) == esperada


# Telnet abierto debe salir con severidad alta.
def test_telnet_es_severidad_alta():
    h = risk.clasificar_puerto({"puerto": 23, "protocolo": "tcp", "servicio": "telnet", "producto": "", "version": ""})
    assert h["severidad"] == SeveridadHallazgo.ALTA
    assert "Cryptographic" in h["categoria_owasp"]


# Un puerto sin regla propia queda como informativo.
def test_puerto_desconocido_es_informativo():
    h = risk.clasificar_puerto({"puerto": 9999, "protocolo": "tcp", "servicio": "raro", "producto": "", "version": ""})
    assert h["severidad"] == SeveridadHallazgo.INFORMATIVA


# ---------- Flujo de evaluación de punta a punta ----------
# Crea usuario, proyecto y activo para probar la evaluación completa.
def _preparar(url):
    client.post("/auth/register", json={"nombre": "Ivan", "email": "i@t.cl", "password": "Password123"})
    token = client.post("/auth/login", data={"username": "i@t.cl", "password": "Password123"}).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    p = client.post("/proyectos", json={"nombre": "Lab"}, headers=h).json()
    a = client.post(f"/proyectos/{p['id']}/activos", json={"nombre": "App", "url_objetivo": url}, headers=h).json()
    return a["id"], h


# Flujo completo con un Nmap simulado: se crean los hallazgos y la evaluación queda completada.
def test_evaluacion_completa_genera_hallazgos(monkeypatch):
    falsos = [
        {"puerto": 23, "protocolo": "tcp", "servicio": "telnet", "producto": "", "version": ""},
        {"puerto": 80, "protocolo": "tcp", "servicio": "http", "producto": "nginx", "version": "1.25"},
    ]
    monkeypatch.setattr(scanner, "escanear_puertos", lambda ip, **kw: falsos)
    activo_id, h = _preparar("http://127.0.0.1:80")

    client.post(f"/activos/{activo_id}/evaluaciones", headers=h)
    evals = client.get(f"/activos/{activo_id}/evaluaciones", headers=h).json()

    assert evals[0]["estado"] == "completada"
    assert evals[0]["finalizada_en"] is not None
    severidades = sorted(x["severidad"] for x in evals[0]["hallazgos"])
    assert severidades == ["alta", "media"]


# Contra un objetivo público la evaluación falla y no se escanea nada.
def test_evaluacion_contra_objetivo_publico_falla_sin_escanear(monkeypatch):
    llamado = []
    monkeypatch.setattr(scanner, "escanear_puertos", lambda ip, **kw: llamado.append(ip) or [])
    activo_id, h = _preparar("http://8.8.8.8")

    client.post(f"/activos/{activo_id}/evaluaciones", headers=h)
    ev = client.get(f"/activos/{activo_id}/evaluaciones", headers=h).json()[0]

    assert ev["estado"] == "fallida"
    assert "bloqueado" in ev["detalle_error"].lower()
    assert llamado == []  # Nmap jamás se ejecutó


# Si cancelan a mitad del escaneo, el proceso de Nmap se termina.
def test_nmap_se_cancela_a_mitad_de_camino(tmp_path, monkeypatch):
    """Un 'nmap' falso que tarda 60 s: al cancelar se termina el proceso en vez de esperarlo."""
    import os
    import time
    from app.cancelacion import EvaluacionCancelada

    falso = tmp_path / "nmap"
    falso.write_text("#!/bin/sh\nsleep 60\n")
    falso.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    t = time.monotonic()
    with pytest.raises(EvaluacionCancelada):
        scanner.escanear_puertos("127.0.0.1", timeout=120, cancelar=lambda: time.monotonic() - t > 1.5)
    assert time.monotonic() - t < 15


# El escaneo cancelable también respeta el tiempo máximo.
def test_nmap_cancelable_tambien_respeta_el_tiempo_maximo(tmp_path, monkeypatch):
    import os
    falso = tmp_path / "nmap"
    falso.write_text("#!/bin/sh\nsleep 60\n")
    falso.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    with pytest.raises(scanner.ScanError, match="tiempo máximo"):
        scanner.escanear_puertos("127.0.0.1", timeout=2, cancelar=lambda: False)
