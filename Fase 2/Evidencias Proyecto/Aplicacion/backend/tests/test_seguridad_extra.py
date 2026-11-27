"""Pruebas de las medidas añadidas tras la revisión de seguridad: límite de intentos, cabeceras y SSRF."""
# Estas pruebas cubren las medidas que agregué después de revisar la seguridad de mi propia aplicación:
# límite de intentos de login, cabeceras de seguridad, protección SSRF en el análisis de URL y lectura segura del XML de Nmap.
import pytest
from fastapi.testclient import TestClient

from app import analisis_service, limitador
from app.main import app

client = TestClient(app)


# El contador de intentos vive en memoria; lo reinicio antes y después de cada prueba para que no se contaminen entre sí.
@pytest.fixture(autouse=True)
def _limpio():
    limitador.reiniciar()
    yield
    limitador.reiniciar()


def _registrar(email="limite@test.cl"):
    client.post("/auth/register", json={"nombre": "Limite", "email": email, "password": "Clave1234!"})


def _login(email, password):
    return client.post("/auth/login", data={"username": email, "password": password})


# Anti fuerza bruta: tras 5 contraseñas malas seguidas, el siguiente intento da 429 (demasiadas solicitudes)
# y la respuesta trae Retry-After, que indica cuántos segundos hay que esperar.
def test_login_se_bloquea_tras_cinco_fallos():
    _registrar()
    for _ in range(limitador.MAX_INTENTOS):
        assert _login("limite@test.cl", "mala").status_code == 401
    r = _login("limite@test.cl", "mala")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0


# Mientras la cuenta está bloqueada, ni la clave correcta entra: si no, el bloqueo no serviría de nada.
def test_login_bloqueado_rechaza_incluso_la_clave_correcta():
    _registrar("bloqueo@test.cl")
    for _ in range(limitador.MAX_INTENTOS):
        _login("bloqueo@test.cl", "mala")
    assert _login("bloqueo@test.cl", "Clave1234!").status_code == 429


# Un login exitoso limpia los fallos acumulados: 4 errores + 1 acierto, y después se vuelve a tener margen de 4 errores.
def test_login_correcto_borra_el_contador():
    _registrar("reinicio@test.cl")
    for _ in range(limitador.MAX_INTENTOS - 1):
        _login("reinicio@test.cl", "mala")
    assert _login("reinicio@test.cl", "Clave1234!").status_code == 200
    for _ in range(limitador.MAX_INTENTOS - 1):
        assert _login("reinicio@test.cl", "mala").status_code == 401


# El bloqueo es por cuenta: que fallen los intentos de a@ no impide que b@ inicie sesión normalmente.
def test_el_bloqueo_es_por_cuenta():
    _registrar("a@test.cl")
    _registrar("b@test.cl")
    for _ in range(limitador.MAX_INTENTOS):
        _login("a@test.cl", "mala")
    assert _login("b@test.cl", "Clave1234!").status_code == 200


# Compruebo las cabeceras que agrega la API a todas las respuestas (evitan que el navegador adivine el tipo de contenido,
# que la página se muestre dentro de un iframe, que se envíe el referer y que se guarde en caché).
def test_cabeceras_de_seguridad_presentes():
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert r.headers["Cache-Control"] == "no-store"


# Protección SSRF (OWASP A10): el análisis rápido de URL nunca debe conectarse a la propia máquina ni al servicio de
# metadatos de la nube (169.254.169.254). "contactado" en False significa que ni siquiera intentó la conexión.
@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://localhost:8000/", "http://169.254.169.254/latest/meta-data/"])
def test_analisis_de_url_no_contacta_direcciones_locales(url):
    r = analisis_service.revisar_cabeceras(url)
    assert r["contactado"] is False


# Ataque XXE: un XML con una entidad externa que intenta leer /etc/passwd debe rechazarse.
# Por eso leo la salida de Nmap con defusedxml en vez del parser normal.
def test_xml_de_nmap_con_entidades_externas_se_rechaza():
    from app import scanner
    malicioso = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>'
    with pytest.raises(scanner.ScanError):
        scanner.parsear_xml_nmap(malicioso)
