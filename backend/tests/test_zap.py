"""
Pruebas de la integración con OWASP ZAP.

IMPORTANTE: ZAP real no corre en el entorno de pruebas. Estas pruebas usan un SIMULACRO del API de
ZAP (httpx.MockTransport) que imita los endpoints documentados (/JSON/spider/..., /JSON/ascan/...,
/JSON/pscan/..., /JSON/core/view/alerts/). Validan nuestra lógica (flujo, agrupación, severidades,
manejo de errores y seguridad); NO prueban que ZAP real responda exactamente así.
Para validar contra ZAP real: levantar el servicio `zap` del docker-compose y evaluar Juice Shop.
"""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_securescan.db"

import httpx
import pytest
from fastapi.testclient import TestClient

from app import scanner, zap_client
from app.database import Base, engine
from app.main import app
from app.models import Hallazgo
from app.zap_client import ZapClient, ZapError, agrupar_alertas

client = TestClient(app)
KEY = "clave-zap"


def alerta(nombre="Content Security Policy (CSP) Header Not Set", plugin="10038", riesgo=2, url="http://10.0.0.5:3000/", **extra):
    base = {
        "pluginId": plugin, "alert": nombre, "name": nombre, "riskcode": str(riesgo), "risk": "Medium",
        "confidence": "High", "url": url, "param": "", "evidence": "",
        "description": "<p>Content Security Policy (CSP) is an added layer of security.</p>",
        "solution": "<p>Ensure that your web server sets the <b>Content-Security-Policy</b> header.</p>",
        "tags": {"OWASP_2021_A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "CWE-693": "x"},
    }
    base.update(extra)
    return base


def zap_falso(alertas, estados_spider=(50, 100), pendientes=(3, 0), llamadas=None, clave=KEY):
    """Simulacro del API de ZAP. `llamadas` acumula las rutas pedidas."""
    cont = {"spider": 0, "pscan": 0}

    def manejar(req: httpx.Request) -> httpx.Response:
        if llamadas is not None:
            llamadas.append(req.url.path)
        if req.url.params.get("apikey") != clave:
            return httpx.Response(401, json={"code": "bad_api_key"})
        ruta = req.url.path
        if ruta == "/JSON/core/view/version/":
            return httpx.Response(200, json={"version": "2.15.0"})
        if ruta in ("/JSON/spider/action/scan/", "/JSON/ascan/action/scan/"):
            return httpx.Response(200, json={"scan": "0"})
        if ruta == "/JSON/spider/view/status/":
            i = min(cont["spider"], len(estados_spider) - 1); cont["spider"] += 1
            return httpx.Response(200, json={"status": str(estados_spider[i])})
        if ruta == "/JSON/ascan/view/status/":
            return httpx.Response(200, json={"status": "100"})
        if ruta == "/JSON/pscan/view/recordsToScan/":
            i = min(cont["pscan"], len(pendientes) - 1); cont["pscan"] += 1
            return httpx.Response(200, json={"recordsToScan": str(pendientes[i])})
        if ruta == "/JSON/core/view/alerts/":
            ini, n = int(req.url.params["start"]), int(req.url.params["count"])
            return httpx.Response(200, json={"alerts": alertas[ini:ini + n]})
        return httpx.Response(404, json={"code": "no_implemented"})

    return httpx.MockTransport(manejar)


def cliente(alertas=(), **kw):
    return ZapClient("http://zap:8080", KEY, transport=zap_falso(list(alertas), **kw), dormir=lambda s: None)


# ---------------- Cliente ----------------
def test_version_y_clave_de_api():
    assert cliente().version() == "2.15.0"
    malo = ZapClient("http://zap:8080", "otra", transport=zap_falso([]), dormir=lambda s: None)
    with pytest.raises(ZapError, match="clave de API"):
        malo.version()


def test_sin_zap_url_no_se_puede_crear(monkeypatch):
    monkeypatch.delenv("ZAP_URL", raising=False)
    assert zap_client.disponible() is False
    with pytest.raises(ZapError, match="ZAP_URL"):
        ZapClient()


def test_zap_apagado_o_inalcanzable():
    def caido(req):
        raise httpx.ConnectError("sin conexión")
    c = ZapClient("http://zap:8080", KEY, transport=httpx.MockTransport(caido), dormir=lambda s: None)
    with pytest.raises(ZapError, match="No se pudo conectar"):
        c.version()


def test_flujo_espera_spider_y_analisis_pasivo():
    llamadas = []
    c = cliente([alerta()], estados_spider=(0, 40, 100), pendientes=(5, 2, 0), llamadas=llamadas)
    hs = c.analizar("http://10.0.0.5:3000/")
    assert len(hs) == 1
    assert llamadas.count("/JSON/spider/view/status/") == 3   # esperó hasta 100 %
    assert llamadas.count("/JSON/pscan/view/recordsToScan/") == 3  # y a que terminara el análisis pasivo
    assert "/JSON/ascan/action/scan/" not in llamadas           # el escaneo activo NO se lanza por defecto


def test_escaneo_activo_solo_si_se_pide():
    llamadas = []
    cliente([], llamadas=llamadas).analizar("http://10.0.0.5/", activo=True)
    assert "/JSON/ascan/action/scan/" in llamadas


def test_tiempo_maximo_si_el_spider_no_termina():
    c = ZapClient("http://zap:8080", KEY, transport=zap_falso([], estados_spider=(10,)), dormir=lambda s: __import__("time").sleep(0.01))
    with pytest.raises(ZapError, match="tiempo máximo"):
        c.analizar("http://10.0.0.5/", limite_s=0.05)


def test_alertas_se_leen_por_paginas():
    muchas = [alerta(nombre=f"Alerta {i}", plugin=str(i)) for i in range(1203)]
    assert len(cliente(muchas).alertas("http://10.0.0.5/")) == 1203


def test_respuesta_de_zap_con_error():
    def roto(req):
        return httpx.Response(500, json={"message": "boom"})
    c = ZapClient("http://zap:8080", KEY, transport=httpx.MockTransport(roto), dormir=lambda s: None)
    with pytest.raises(ZapError, match="500"):
        c.version()


# ---------------- Traducción de alertas ----------------
def test_agrupa_por_tipo_y_cuenta_instancias():
    alertas = [alerta(url=f"http://10.0.0.5:3000/p{i}") for i in range(7)] + [alerta("Cookie sin HttpOnly", "10010", 1, param="sid")]
    hs = agrupar_alertas(alertas)
    assert len(hs) == 2
    csp = next(h for h in hs if "CSP" in h["nombre_vulnerabilidad"])
    assert csp["evidencia"].startswith("7 instancia(s). Ejemplos: http://10.0.0.5:3000/p0")
    assert csp["evidencia"].count("http://") == 3  # solo 3 ejemplos


def test_severidad_cvss_y_orden():
    hs = agrupar_alertas([alerta("Info", "1", 0), alerta("Baja", "2", 1), alerta("Media", "3", 2), alerta("Alta", "4", 3)])
    assert [(h["severidad"].value, h["cvss_score"]) for h in hs] == [("alta", 7.5), ("media", 5.3), ("baja", 3.1), ("informativa", 0.0)]
    assert all(h["herramienta_origen"] == "owasp_zap" for h in hs)


def test_zap_nunca_produce_critica():
    assert all(h["severidad"].value != "critica" for h in agrupar_alertas([alerta(riesgo=r) for r in (0, 1, 2, 3, 4)]))


def test_categoria_owasp_desde_etiquetas():
    assert agrupar_alertas([alerta()])[0]["categoria_owasp"] == "A05:2021 - Security Misconfiguration"
    sqli = alerta("SQL Injection", "40018", 3, tags={"OWASP_2021_A03": "x"})
    assert agrupar_alertas([sqli])[0]["categoria_owasp"] == "A03:2021 - Injection"
    assert agrupar_alertas([alerta(tags={})])[0]["categoria_owasp"] is None
    assert agrupar_alertas([alerta(tags={"OWASP_2021_A99": "x"})])[0]["categoria_owasp"] is None


def test_html_se_limpia_y_los_textos_se_acotan():
    h = agrupar_alertas([alerta(solution="<p>Haz <b>esto</b></p><p>y aquello</p>", description="x" * 5000)])[0]
    assert "<" not in h["recomendacion"] and h["recomendacion"] == "Haz esto y aquello"
    assert len(h["evidencia"]) <= 1500


def test_contenido_hostil_no_rompe_nada():
    h = agrupar_alertas([alerta(nombre="<script>alert(1)</script>", evidence="'; DROP TABLE hallazgos;--")])[0]
    assert "DROP TABLE" in h["evidencia"]  # se guarda como texto; los parámetros SQL van enlazados, no concatenados


# ---------------- Dirección que se le entrega a ZAP ----------------
@pytest.mark.parametrize("url,ip,puertos,esperado", [
    ("http://juiceshop:3000", "172.18.0.5", [], "http://172.18.0.5:3000/"),
    ("https://app.lab.local/login", "10.0.0.7", [], "https://10.0.0.7/login"),
    ("ftp://servidor", "10.0.0.7", [], None),
    ("192.168.56.20", "192.168.56.20", [], None),
    ("192.168.56.20", "192.168.56.20", [{"puerto": 22, "servicio": "ssh"}], None),
    ("192.168.56.20", "192.168.56.20", [{"puerto": 8080, "servicio": "http-proxy"}], "http://192.168.56.20:8080/"),
    ("dvwa.lab.local", "10.0.0.9", [{"puerto": 80, "servicio": "http"}, {"puerto": 443, "servicio": "https"}], "https://10.0.0.9:443/"),
])
def test_url_para_zap(url, ip, puertos, esperado):
    from app.scan_service import url_para_zap
    assert url_para_zap(url, ip, puertos) == esperado


# ---------------- Integración con la evaluación ----------------
@pytest.fixture
def entorno(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setenv("ZAP_URL", "http://zap:8080")
    client.post("/auth/register", json={"nombre": "Admin", "email": "a@t.cl", "password": "Password123"})
    r = client.post("/auth/login", data={"username": "a@t.cl", "password": "Password123"})
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    cfg = client.get("/configuracion", headers=h).json()
    cfg["motores"]["zap"].update({"activo": True, "escaneo_activo": False})
    assert client.put("/configuracion", json=cfg, headers=h).status_code == 200
    monkeypatch.setattr(scanner, "resolver_y_validar", lambda host, permitir_publicos=None: "10.0.0.5")
    monkeypatch.setattr(scanner, "escanear_puertos", lambda ip, **kw: [
        {"puerto": 3000, "protocolo": "tcp", "servicio": "http", "producto": "Express", "version": ""}])
    p = client.post("/proyectos", json={"nombre": "Proyecto P"}, headers=h).json()
    a = client.post(f"/proyectos/{p['id']}/activos", json={"nombre": "Juice", "url_objetivo": "http://juiceshop:3000"}, headers=h).json()
    return h, a


def evaluar(h, activo):
    ev = client.post(f"/activos/{activo['id']}/evaluaciones", headers=h).json()
    return client.get(f"/evaluaciones/{ev['id']}", headers=h).json()


def test_evaluacion_combina_nmap_y_zap(entorno, monkeypatch):
    h, a = entorno
    usado = {}

    class Falso:
        def analizar(self, url, limite_s, activo):
            usado.update(url=url, limite=limite_s, activo=activo)
            return agrupar_alertas([alerta(), alerta("SQL Injection", "40018", 3, tags={"OWASP_2021_A03": "x"})])
    monkeypatch.setattr(zap_client, "ZapClient", Falso)
    ev = evaluar(h, a)
    assert ev["estado"] == "completada" and ev["detalle_error"] is None and ev["progreso"] == 100
    herramientas = sorted(x["herramienta_origen"] for x in ev["hallazgos"])
    assert herramientas == ["nmap", "owasp_zap", "owasp_zap"]
    assert usado == {"url": "http://10.0.0.5:3000/", "limite": 600, "activo": False}  # usa la IP validada


def test_si_zap_falla_se_conserva_lo_de_nmap(entorno, monkeypatch):
    h, a = entorno

    class Roto:
        def analizar(self, *args, **kw):
            raise ZapError("OWASP ZAP superó el tiempo máximo mientras exploraba el sitio")
    monkeypatch.setattr(zap_client, "ZapClient", Roto)
    ev = evaluar(h, a)
    assert ev["estado"] == "completada"
    assert [x["herramienta_origen"] for x in ev["hallazgos"]] == ["nmap"]
    assert "no pudo completar" in ev["detalle_error"] and "tiempo máximo" in ev["detalle_error"]


def test_error_inesperado_de_zap_tampoco_pierde_resultados(entorno, monkeypatch):
    h, a = entorno

    class Raro:
        def analizar(self, *args, **kw):
            raise KeyError("x")
    monkeypatch.setattr(zap_client, "ZapClient", Raro)
    ev = evaluar(h, a)
    assert ev["estado"] == "completada" and len(ev["hallazgos"]) == 1 and "inesperada" in ev["detalle_error"]


def test_objetivo_que_no_es_web_no_lanza_zap(entorno, monkeypatch):
    h, a = entorno
    monkeypatch.setattr(scanner, "escanear_puertos", lambda ip, **kw: [
        {"puerto": 22, "protocolo": "tcp", "servicio": "ssh", "producto": "OpenSSH", "version": ""}])
    monkeypatch.setattr(zap_client, "ZapClient", lambda: pytest.fail("no debía invocarse ZAP"))
    p = client.post("/proyectos", json={"nombre": "Proyecto Q"}, headers=h).json()
    b = client.post(f"/proyectos/{p['id']}/activos", json={"nombre": "Servidor", "url_objetivo": "192.168.56.20"}, headers=h).json()
    ev = evaluar(h, b)
    assert ev["estado"] == "completada" and "no se detectó una aplicación web" in ev["detalle_error"]


def test_objetivo_publico_nunca_llega_a_zap(entorno, monkeypatch):
    h, a = entorno
    monkeypatch.undo()  # restaura el validador real
    monkeypatch.setenv("ZAP_URL", "http://zap:8080")
    monkeypatch.setattr(scanner.socket, "getaddrinfo", lambda *x, **k: [(2, 1, 6, "", ("8.8.8.8", 0))])
    monkeypatch.setattr(zap_client, "ZapClient", lambda: pytest.fail("ZAP no debe recibir un objetivo público"))
    ev = evaluar(h, a)
    assert ev["estado"] == "fallida" and "Objetivo bloqueado" in ev["detalle_error"]


def test_zap_desactivado_en_la_configuracion_no_se_usa(entorno, monkeypatch):
    h, a = entorno
    cfg = client.get("/configuracion", headers=h).json()
    cfg["motores"]["zap"]["activo"] = False
    client.put("/configuracion", json=cfg, headers=h)
    monkeypatch.setattr(zap_client, "ZapClient", lambda: pytest.fail("ZAP está desactivado"))
    ev = evaluar(h, a)
    assert ev["estado"] == "completada" and [x["herramienta_origen"] for x in ev["hallazgos"]] == ["nmap"]


def test_la_configuracion_de_zap_solo_se_activa_si_el_servidor_lo_tiene(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.delenv("ZAP_URL", raising=False)
    client.post("/auth/register", json={"nombre": "Admin", "email": "a@t.cl", "password": "Password123"})
    h = {"Authorization": "Bearer " + client.post("/auth/login", data={"username": "a@t.cl", "password": "Password123"}).json()["access_token"]}
    cfg = client.get("/configuracion", headers=h).json()
    assert cfg["motores"]["zap"]["disponible"] is False
    cfg["motores"]["zap"]["activo"] = True
    r = client.put("/configuracion", json=cfg, headers=h)
    assert r.status_code == 400 and "ZAP_URL" in r.json()["detail"]
    monkeypatch.setenv("ZAP_URL", "http://zap:8080")
    assert client.get("/configuracion", headers=h).json()["motores"]["zap"]["disponible"] is True
    assert client.put("/configuracion", json=cfg, headers=h).status_code == 200
