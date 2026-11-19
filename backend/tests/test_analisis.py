"""
Pruebas del análisis de URL y archivos. VirusTotal se simula con httpx.MockTransport (no se usa red ni clave real);
por eso estas pruebas demuestran el manejo de las respuestas, no la comunicación con el servicio real.
"""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_securescan.db"

import base64
import httpx
import pytest
from fastapi.testclient import TestClient

from app import analisis_service as svc
from app.database import Base, engine
from app.main import app

client = TestClient(app)
PWD = "Password123"
VT_REAL = svc.VirusTotal


@pytest.fixture(autouse=True)
def entorno(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("ALLOW_PUBLIC_SCANS", raising=False)
    yield


def login(email="ana@t.cl"):
    client.post("/auth/register", json={"nombre": "Ana", "email": email, "password": PWD})
    r = client.post("/auth/login", data={"username": email, "password": PWD})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def vt_falso(monkeypatch, manejador):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "clave-de-prueba")
    monkeypatch.setattr(svc, "VirusTotal", lambda: VT_REAL("clave-de-prueba", transport=httpx.MockTransport(manejador), dormir=lambda s: None))


def informe(malicious=0, suspicious=0, harmless=60, undetected=10):
    resultados = {f"Motor{i}": {"category": "malicious", "result": "Trojan.Gen", "engine_name": f"Motor{i}"} for i in range(malicious)}
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected},
                                    "last_analysis_results": resultados}}}


def esperar(h, aid):
    return client.get(f"/analisis/{aid}", headers=h).json()  # BackgroundTasks ya corrieron con TestClient


def test_requiere_sesion():
    assert client.post("/analisis/url", json={"url": "http://a.cl"}).status_code == 401


def test_url_invalida():
    h = login()
    assert client.post("/analisis/url", json={"url": "ftp://x.cl"}, headers=h).status_code == 422
    assert client.post("/analisis/url", json={"url": "javascript:alert(1)"}, headers=h).status_code == 422


def test_estado_sin_clave():
    h = login()
    j = client.get("/analisis/estado", headers=h).json()
    assert j["virustotal"] is False and j["max_mb"] >= 1


def test_url_sin_clave_da_solo_senales_locales():
    h = login()
    r = client.post("/analisis/url", json={"url": "http://bit.ly/abc"}, headers=h)
    assert r.status_code == 202
    a = esperar(h, r.json()["id"])
    assert a["estado"] == "completado"
    codigos = {s["codigo"] for s in a["detalle"]["senales"]}
    assert {"sin_https", "acortador"} <= codigos
    assert a["veredicto"] == "sospechoso"
    assert any("no está configurado" in x for x in a["detalle"]["avisos"])


def test_url_con_virustotal_malicioso(monkeypatch):
    h = login()
    visto = {}

    def manejador(req: httpx.Request):
        visto["clave"] = req.headers.get("x-apikey")
        visto["ruta"] = req.url.path
        return httpx.Response(200, json=informe(malicious=7))

    vt_falso(monkeypatch, manejador)
    url = "https://sitio-raro.example/descarga"
    a = esperar(h, client.post("/analisis/url", json={"url": url}, headers=h).json()["id"])
    assert visto["clave"] == "clave-de-prueba"
    assert visto["ruta"] == "/api/v3/urls/" + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert a["veredicto"] == "malicioso"
    assert a["detalle"]["virustotal"]["malicioso"] == 7
    assert "7 motores" in a["resumen"]
    assert "clave-de-prueba" not in str(a)


def test_url_limpia(monkeypatch):
    h = login()
    vt_falso(monkeypatch, lambda req: httpx.Response(200, json=informe()))
    a = esperar(h, client.post("/analisis/url", json={"url": "https://example.com"}, headers=h).json()["id"])
    assert a["veredicto"] == "limpio"


def test_url_desconocida_se_envia_y_se_espera_el_resultado(monkeypatch):
    h = login()
    llamadas = []

    def manejador(req: httpx.Request):
        llamadas.append((req.method, req.url.path))
        if req.method == "GET" and req.url.path.startswith("/api/v3/urls/"):
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        if req.method == "POST" and req.url.path == "/api/v3/urls":
            return httpx.Response(200, json={"data": {"id": "u-123"}})
        if req.url.path == "/api/v3/analyses/u-123":
            return httpx.Response(200, json={"data": {"attributes": {"status": "completed", "stats": {"malicious": 1, "harmless": 70, "undetected": 5, "suspicious": 0}, "results": {}}}})
        return httpx.Response(500)

    vt_falso(monkeypatch, manejador)
    a = esperar(h, client.post("/analisis/url", json={"url": "https://nuevo.example"}, headers=h).json()["id"])
    assert a["veredicto"] == "sospechoso"
    assert ("POST", "/api/v3/urls") in llamadas


def test_limite_de_virustotal_y_clave_invalida(monkeypatch):
    h = login()
    vt_falso(monkeypatch, lambda req: httpx.Response(429))
    a = esperar(h, client.post("/analisis/url", json={"url": "https://example.com"}, headers=h).json()["id"])
    assert a["estado"] == "completado" and any("límite" in x for x in a["detalle"]["avisos"])
    vt_falso(monkeypatch, lambda req: httpx.Response(401))
    a = esperar(h, client.post("/analisis/url", json={"url": "https://example.com"}, headers=h).json()["id"])
    assert any("clave" in x for x in a["detalle"]["avisos"])


def test_sitio_publico_no_se_contacta_sin_los_dos_candados(monkeypatch):
    h = login()
    llamado = []

    def resolver(host, permitir_publicos=False):
        llamado.append(permitir_publicos)
        raise svc.scanner.ScanError("El destino es una IP pública y no está permitido.")

    monkeypatch.setattr(svc.scanner, "resolver_y_validar", resolver)
    a = esperar(h, client.post("/analisis/url", json={"url": "https://example.com/"}, headers=h).json()["id"])
    cab = a["detalle"]["cabeceras"]
    assert llamado == [False]
    assert cab["contactado"] is False and cab["motivo"].startswith("No se contactó")


def test_cabeceras_de_un_sitio_permitido(monkeypatch):
    login()
    monkeypatch.setattr(svc.scanner, "resolver_y_validar", lambda host, permitir_publicos=False: "10.0.0.5")

    transporte = httpx.MockTransport(lambda req: httpx.Response(200, headers={"Server": "nginx/1.18.0", "Set-Cookie": "sid=1; Path=/"}, text="ok"))
    cliente = httpx.Client(transport=transporte)
    r = svc.revisar_cabeceras("http://lab.local/", cliente)
    titulos = " ".join(x["titulo"] for x in r["hallazgos"])
    assert r["contactado"] and "CSP" in titulos and "clickjacking" in titulos and "versión" in titulos and "Cookie" in titulos


def test_archivo_eicar_es_malicioso_sin_clave():
    h = login()
    r = client.post("/analisis/archivo", files={"archivo": ("prueba.txt", svc.EICAR)}, headers=h)
    assert r.status_code == 202
    assert r.json()["sha256"] == svc.sha256_de(svc.EICAR)
    a = esperar(h, r.json()["id"])
    assert a["veredicto"] == "malicioso"
    assert "contenido" not in a  # no se devuelve ni guarda el archivo


def test_doble_extension_y_ejecutable_disfrazado():
    h = login()
    a = esperar(h, client.post("/analisis/archivo", files={"archivo": ("factura.pdf.exe", b"MZ\x90\x00datos")}, headers=h).json()["id"])
    codigos = {s["codigo"] for s in a["detalle"]["senales"]}
    assert {"doble_extension", "ejecutable_windows"} <= codigos
    assert a["veredicto"] == "sospechoso"
    a = esperar(h, client.post("/analisis/archivo", files={"archivo": ("foto.jpg", b"MZ\x90\x00datos")}, headers=h).json()["id"])
    assert "extension_no_coincide" in {s["codigo"] for s in a["detalle"]["senales"]}


def test_archivo_desconocido_no_se_sube_sin_consentimiento(monkeypatch):
    h = login()
    metodos = []

    def manejador(req):
        metodos.append((req.method, req.url.path))
        return httpx.Response(404)

    vt_falso(monkeypatch, manejador)
    a = esperar(h, client.post("/analisis/archivo", files={"archivo": ("a.txt", b"hola")}, headers=h).json()["id"])
    assert ("POST", "/api/v3/files") not in metodos
    assert any("no lo pediste" in x for x in a["detalle"]["avisos"])
    assert a["veredicto"] == "sin_datos"


def test_archivo_se_sube_con_consentimiento(monkeypatch):
    h = login()
    metodos = []

    def manejador(req):
        metodos.append((req.method, req.url.path))
        if req.method == "GET" and req.url.path.startswith("/api/v3/files/"):
            return httpx.Response(404)
        if req.method == "POST" and req.url.path == "/api/v3/files":
            return httpx.Response(200, json={"data": {"id": "f-9"}})
        return httpx.Response(200, json={"data": {"attributes": {"status": "completed", "stats": {"malicious": 0, "harmless": 60, "undetected": 10, "suspicious": 0}, "results": {}}}})

    vt_falso(monkeypatch, manejador)
    a = esperar(h, client.post("/analisis/archivo", files={"archivo": ("a.txt", b"hola")}, data={"subir": "true"}, headers=h).json()["id"])
    assert ("POST", "/api/v3/files") in metodos
    assert a["veredicto"] == "limpio"


def test_archivo_vacio_y_demasiado_grande(monkeypatch):
    h = login()
    assert client.post("/analisis/archivo", files={"archivo": ("v.txt", b"")}, headers=h).status_code == 422
    monkeypatch.setattr(svc, "MAX_ARCHIVO_BYTES", 10)
    assert client.post("/analisis/archivo", files={"archivo": ("g.txt", b"x" * 11)}, headers=h).status_code == 413


def test_historial_propiedad_y_borrado():
    h = login("ana@t.cl")
    otro = login("beto@t.cl")
    aid = client.post("/analisis/url", json={"url": "http://a.example"}, headers=h).json()["id"]
    assert len(client.get("/analisis", headers=h).json()) == 1
    assert client.get("/analisis", headers=otro).json() == []
    assert client.get(f"/analisis/{aid}", headers=otro).status_code == 404
    assert client.delete(f"/analisis/{aid}", headers=otro).status_code == 404
    assert client.delete(f"/analisis/{aid}", headers=h).status_code == 204
    assert client.get(f"/analisis/{aid}", headers=h).status_code == 404


def test_se_borra_mientras_corre_no_falla():
    h = login()
    aid = client.post("/analisis/url", json={"url": "http://a.example"}, headers=h).json()["id"]
    client.delete(f"/analisis/{aid}", headers=h)
    svc.ejecutar_analisis(aid)  # el registro ya no existe: debe terminar en silencio


def test_veredicto_mapeo():
    vt = lambda m, s=0, tot=70: {"malicioso": m, "sospechoso": s, "motores": tot}
    assert svc.veredicto_de(vt(5), []) == "malicioso"
    assert svc.veredicto_de(vt(1), []) == "sospechoso"
    assert svc.veredicto_de(vt(0, 1), []) == "sospechoso"
    assert svc.veredicto_de(vt(0), []) == "limpio"
    assert svc.veredicto_de(None, []) == "sin_datos"
    assert svc.veredicto_de(None, [svc.sena("x", "medio", "t")]) == "sospechoso"
