"""Pruebas de las medidas añadidas tras la revisión de seguridad: límite de intentos, cabeceras y SSRF."""
import pytest
from fastapi.testclient import TestClient

from app import analisis_service, limitador
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def _limpio():
    limitador.reiniciar()
    yield
    limitador.reiniciar()


def _registrar(email="limite@test.cl"):
    client.post("/auth/register", json={"nombre": "Limite", "email": email, "password": "Clave1234!"})


def _login(email, password):
    return client.post("/auth/login", data={"username": email, "password": password})


def test_login_se_bloquea_tras_cinco_fallos():
    _registrar()
    for _ in range(limitador.MAX_INTENTOS):
        assert _login("limite@test.cl", "mala").status_code == 401
    r = _login("limite@test.cl", "mala")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0


def test_login_bloqueado_rechaza_incluso_la_clave_correcta():
    _registrar("bloqueo@test.cl")
    for _ in range(limitador.MAX_INTENTOS):
        _login("bloqueo@test.cl", "mala")
    assert _login("bloqueo@test.cl", "Clave1234!").status_code == 429


def test_login_correcto_borra_el_contador():
    _registrar("reinicio@test.cl")
    for _ in range(limitador.MAX_INTENTOS - 1):
        _login("reinicio@test.cl", "mala")
    assert _login("reinicio@test.cl", "Clave1234!").status_code == 200
    for _ in range(limitador.MAX_INTENTOS - 1):
        assert _login("reinicio@test.cl", "mala").status_code == 401


def test_el_bloqueo_es_por_cuenta():
    _registrar("a@test.cl")
    _registrar("b@test.cl")
    for _ in range(limitador.MAX_INTENTOS):
        _login("a@test.cl", "mala")
    assert _login("b@test.cl", "Clave1234!").status_code == 200


def test_cabeceras_de_seguridad_presentes():
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert r.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://localhost:8000/", "http://169.254.169.254/latest/meta-data/"])
def test_analisis_de_url_no_contacta_direcciones_locales(url):
    r = analisis_service.revisar_cabeceras(url)
    assert r["contactado"] is False


def test_xml_de_nmap_con_entidades_externas_se_rechaza():
    from app import scanner
    malicioso = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>'
    with pytest.raises(scanner.ScanError):
        scanner.parsear_xml_nmap(malicioso)
