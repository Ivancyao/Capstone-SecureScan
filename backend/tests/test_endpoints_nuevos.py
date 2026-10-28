"""
Pruebas de los endpoints agregados en la Fase 3: hallazgos, usuarios y roles, perfil,
configuración, reportes PDF, progreso de evaluaciones y migración de columnas.
Usan SQLite temporal; el escáner real se reemplaza por datos falsos.
"""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_securescan.db"

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from app import config_service, scanner
from app.database import Base, SessionLocal, engine
from app.main import _cerrar_evaluaciones_huerfanas, app
from app.migrar import agregar_columnas_faltantes
from app.models import Activo, EstadoEvaluacion, Evaluacion, Hallazgo, SeveridadHallazgo

client = TestClient(app)
PWD = "Password123"


@pytest.fixture(autouse=True)
def entorno(tmp_path, monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reportes"))
    monkeypatch.delenv("ALLOW_PUBLIC_SCANS", raising=False)
    yield


def registrar(email, nombre="Persona"):
    return client.post("/auth/register", json={"nombre": nombre, "email": email, "password": PWD})


def cabecera(email, password=PWD):
    r = client.post("/auth/login", data={"username": email, "password": password})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def admin():
    registrar("admin@t.cl", "Admin")  # el primero queda como admin
    return cabecera("admin@t.cl")


@pytest.fixture
def ana(admin):
    registrar("ana@t.cl", "Ana")
    return cabecera("ana@t.cl")


def crear_activo(h, nombre="DVWA", url="http://dvwa.local"):
    p = client.post("/proyectos", json={"nombre": "Lab " + nombre}, headers=h).json()
    a = client.post(f"/proyectos/{p['id']}/activos", json={"nombre": nombre, "url_objetivo": url}, headers=h).json()
    return p, a


def evaluacion_completada(activo_id, hallazgos=(("Telnet expuesto", "alta", 7.5),), hace_dias=0):
    db = SessionLocal()
    ev = Evaluacion(
        activo_id=activo_id,
        estado=EstadoEvaluacion.COMPLETADA,
        iniciada_en=datetime.utcnow() - timedelta(days=hace_dias),
        finalizada_en=datetime.utcnow() - timedelta(days=hace_dias),
    )
    db.add(ev)
    db.flush()
    for nombre, sev, cvss in hallazgos:
        db.add(Hallazgo(evaluacion_id=ev.id, nombre_vulnerabilidad=nombre, severidad=SeveridadHallazgo(sev),
                        cvss_score=cvss, evidencia="Puerto 23/tcp abierto <script>", recomendacion="Usar SSH & llaves",
                        categoria_owasp="A02:2021 - Cryptographic Failures", herramienta_origen="nmap"))
    db.commit()
    eid = ev.id
    db.close()
    return eid


# ---------------- Hallazgos ----------------
def test_marcar_hallazgo_corregido_y_reabrir(admin):
    _, a = crear_activo(admin)
    eid = evaluacion_completada(a["id"])
    hid = client.get(f"/evaluaciones/{eid}", headers=admin).json()["hallazgos"][0]["id"]
    r = client.patch(f"/hallazgos/{hid}", json={"corregido": "si"}, headers=admin)
    assert r.status_code == 200 and r.json()["corregido"] == "si"
    assert client.get(f"/evaluaciones/{eid}", headers=admin).json()["hallazgos"][0]["corregido"] == "si"
    assert client.patch(f"/hallazgos/{hid}", json={"corregido": "no"}, headers=admin).json()["corregido"] == "no"


def test_hallazgo_valor_invalido_y_ajeno(admin, ana):
    _, a = crear_activo(admin)
    eid = evaluacion_completada(a["id"])
    hid = client.get(f"/evaluaciones/{eid}", headers=admin).json()["hallazgos"][0]["id"]
    assert client.patch(f"/hallazgos/{hid}", json={"corregido": "quizas"}, headers=admin).status_code == 422
    # Ana no es dueña del proyecto: no debe poder tocarlo (A01) ni saber que existe
    assert client.patch(f"/hallazgos/{hid}", json={"corregido": "si"}, headers=ana).status_code == 404
    assert client.patch("/hallazgos/no-existe", json={"corregido": "si"}, headers=admin).status_code == 404


def test_hallazgo_incluye_evaluacion_id(admin):
    _, a = crear_activo(admin)
    eid = evaluacion_completada(a["id"])
    assert client.get(f"/evaluaciones/{eid}", headers=admin).json()["hallazgos"][0]["evaluacion_id"] == eid


# ---------------- Usuarios y roles ----------------
def test_usuarios_solo_admin(admin, ana):
    assert client.get("/usuarios", headers=ana).status_code == 403
    assert client.post("/usuarios", json={"nombre": "X Y", "email": "x@t.cl"}, headers=ana).status_code == 403
    assert client.get("/usuarios").status_code == 401
    lista = client.get("/usuarios", headers=admin).json()
    assert {u["email"] for u in lista} == {"admin@t.cl", "ana@t.cl"}
    assert all("password" not in u and "password_hash" not in u for u in lista)


def test_admin_crea_usuario_con_password_temporal(admin):
    r = client.post("/usuarios", json={"nombre": "Luis Perez", "email": "luis@t.cl", "rol": "analista"}, headers=admin)
    assert r.status_code == 201
    cuerpo = r.json()
    assert cuerpo["rol"] == "analista" and cuerpo["activo"] is True
    assert len(cuerpo["password_temporal"]) >= 8
    assert cabecera("luis@t.cl", cuerpo["password_temporal"])  # la contraseña temporal sirve
    # y no se vuelve a mostrar en el listado
    assert all("password_temporal" not in u for u in client.get("/usuarios", headers=admin).json())
    assert client.post("/usuarios", json={"nombre": "Luis Dos", "email": "luis@t.cl"}, headers=admin).status_code == 400


def test_cambiar_rol_y_desactivar(admin, ana):
    uid = next(u["id"] for u in client.get("/usuarios", headers=admin).json() if u["email"] == "ana@t.cl")
    assert client.patch(f"/usuarios/{uid}", json={"rol": "analista"}, headers=admin).json()["rol"] == "analista"
    assert client.patch(f"/usuarios/{uid}", json={"rol": "jefe"}, headers=admin).status_code == 422

    # Desactivar: pierde el acceso de inmediato, incluso con un token que ya tenía
    assert client.get("/proyectos", headers=ana).status_code == 200
    assert client.patch(f"/usuarios/{uid}", json={"activo": False}, headers=admin).json()["activo"] is False
    assert client.get("/proyectos", headers=ana).status_code == 401
    r = client.post("/auth/login", data={"username": "ana@t.cl", "password": PWD})
    assert r.status_code == 403
    # Reactivar
    client.patch(f"/usuarios/{uid}", json={"activo": True}, headers=admin)
    assert client.post("/auth/login", data={"username": "ana@t.cl", "password": PWD}).status_code == 200


def test_admin_no_puede_cambiarse_a_si_mismo(admin):
    yo = client.get("/auth/me", headers=admin).json()
    assert client.patch(f"/usuarios/{yo['id']}", json={"rol": "usuario"}, headers=admin).status_code == 400
    assert client.patch(f"/usuarios/{yo['id']}", json={"activo": False}, headers=admin).status_code == 400
    assert client.patch("/usuarios/no-existe", json={"rol": "usuario"}, headers=admin).status_code == 404


# ---------------- Perfil ----------------
def test_editar_nombre_y_cambiar_password(ana):
    assert client.patch("/auth/me", json={"nombre": "Ana María"}, headers=ana).json()["nombre"] == "Ana María"
    assert client.patch("/auth/me", json={"nombre": "A"}, headers=ana).status_code == 422
    assert client.post("/auth/password", json={"actual": "incorrecta1", "nueva": "NuevaClave123"}, headers=ana).status_code == 400
    assert client.post("/auth/password", json={"actual": PWD, "nueva": "corta"}, headers=ana).status_code == 422
    assert client.post("/auth/password", json={"actual": PWD, "nueva": "NuevaClave123"}, headers=ana).status_code == 200
    assert client.post("/auth/login", data={"username": "ana@t.cl", "password": PWD}).status_code == 401
    assert client.post("/auth/login", data={"username": "ana@t.cl", "password": "NuevaClave123"}).status_code == 200


# ---------------- Configuración ----------------
def test_configuracion_por_defecto_y_permisos(admin, ana):
    cfg = client.get("/configuracion", headers=ana).json()  # cualquier usuario puede leerla
    assert cfg["motores"]["nmap"]["activo"] is True
    assert cfg["motores"]["zap"]["activo"] is False
    assert cfg["alcance"]["permitir_publicas"] is False
    assert cfg["alcance"]["publicas_permitidas_por_servidor"] is False
    assert "10.0.0.0/8" in cfg["alcance"]["rangos"]
    assert client.put("/configuracion", json=cfg, headers=ana).status_code == 403


def test_guardar_configuracion_persiste(admin):
    cfg = client.get("/configuracion", headers=admin).json()
    cfg["motores"]["nmap"].update({"puertos": "rapido", "timeout_s": 120, "detectar_versiones": False})
    cfg["retencion_dias"] = 90
    r = client.put("/configuracion", json=cfg, headers=admin)
    assert r.status_code == 200
    de_nuevo = client.get("/configuracion", headers=admin).json()
    assert de_nuevo["motores"]["nmap"]["puertos"] == "rapido"
    assert de_nuevo["motores"]["nmap"]["timeout_s"] == 120
    assert de_nuevo["motores"]["nmap"]["detectar_versiones"] is False
    assert de_nuevo["retencion_dias"] == 90


def test_configuracion_rechaza_valores_peligrosos(admin):
    cfg = client.get("/configuracion", headers=admin).json()
    malo = {**cfg, "motores": {**cfg["motores"], "zap": {"activo": True}}}
    assert client.put("/configuracion", json=malo, headers=admin).status_code == 400
    malo = {**cfg, "motores": {**cfg["motores"], "nmap": {**cfg["motores"]["nmap"], "puertos": "1-10; rm -rf /"}}}
    assert client.put("/configuracion", json=malo, headers=admin).status_code == 422
    malo = {**cfg, "motores": {**cfg["motores"], "nmap": {**cfg["motores"]["nmap"], "timeout_s": 5}}}
    assert client.put("/configuracion", json=malo, headers=admin).status_code == 422


def test_publicas_solo_si_el_servidor_lo_permite(admin, monkeypatch):
    cfg = client.get("/configuracion", headers=admin).json()
    cfg["alcance"]["permitir_publicas"] = True
    r = client.put("/configuracion", json=cfg, headers=admin)
    assert r.status_code == 400 and "ALLOW_PUBLIC_SCANS" in r.json()["detail"]
    monkeypatch.setenv("ALLOW_PUBLIC_SCANS", "true")
    assert client.put("/configuracion", json=cfg, headers=admin).status_code == 200


def test_candado_del_servidor_manda_sobre_la_configuracion(admin, monkeypatch):
    """Aunque la BD diga 'permitir públicas', si el servidor lo bloquea no se escanea."""
    monkeypatch.setenv("ALLOW_PUBLIC_SCANS", "true")
    cfg = client.get("/configuracion", headers=admin).json()
    cfg["alcance"]["permitir_publicas"] = True
    client.put("/configuracion", json=cfg, headers=admin)
    monkeypatch.setenv("ALLOW_PUBLIC_SCANS", "false")
    db = SessionLocal()
    assert config_service.publicas_efectivas(config_service.obtener(db)) is False
    db.close()
    monkeypatch.setattr(scanner.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0))])
    with pytest.raises(scanner.ScanError):
        scanner.resolver_y_validar("ejemplo.com", permitir_publicos=True)


def test_nmap_desactivado_hace_fallar_la_evaluacion(admin, monkeypatch):
    cfg = client.get("/configuracion", headers=admin).json()
    cfg["motores"]["nmap"]["activo"] = False
    client.put("/configuracion", json=cfg, headers=admin)
    _, a = crear_activo(admin)
    ev = client.post(f"/activos/{a['id']}/evaluaciones", headers=admin).json()  # el escaneo corre al terminar la petición
    final = client.get(f"/evaluaciones/{ev['id']}", headers=admin).json()
    assert final["estado"] == "fallida" and "desactivado" in final["detalle_error"]


def test_la_configuracion_llega_al_escaner(admin, monkeypatch):
    cfg = client.get("/configuracion", headers=admin).json()
    cfg["motores"]["nmap"].update({"puertos": "completo", "timeout_s": 77, "detectar_versiones": False})
    client.put("/configuracion", json=cfg, headers=admin)
    recibido = {}
    monkeypatch.setattr(scanner, "resolver_y_validar", lambda host, permitir_publicos=None: "127.0.0.1")
    monkeypatch.setattr(scanner, "escanear_puertos", lambda ip, **kw: recibido.update(kw) or [])
    _, a = crear_activo(admin, url="http://localhost:3000")
    client.post(f"/activos/{a['id']}/evaluaciones", headers=admin)
    assert recibido == {"perfil": "completo", "timeout": 77, "versiones": False}


def test_argumentos_de_nmap_segun_perfil():
    assert scanner.argumentos_de_puertos("rapido", None) == ["--top-ports", "100"]
    assert scanner.argumentos_de_puertos("completo", None) == ["-p", "1-65535"]
    assert scanner.argumentos_de_puertos("predeterminado", None)[0] == "-p"
    assert scanner.argumentos_de_puertos(None, "80,443") == ["-p", "80,443"]
    with pytest.raises(scanner.ScanError):
        scanner.argumentos_de_puertos(None, "80; ls")


# ---------------- Progreso y concurrencia de evaluaciones ----------------
def test_evaluacion_guarda_progreso_y_etapa(admin, monkeypatch):
    monkeypatch.setattr(scanner, "resolver_y_validar", lambda host, permitir_publicos=None: "127.0.0.1")
    monkeypatch.setattr(scanner, "escanear_puertos", lambda ip, **kw: [
        {"puerto": 22, "protocolo": "tcp", "servicio": "ssh", "producto": "OpenSSH", "version": "8.9"}])
    _, a = crear_activo(admin, url="http://localhost")
    ev = client.post(f"/activos/{a['id']}/evaluaciones", headers=admin).json()
    assert ev["estado"] == "pendiente" and ev["progreso"] == 0 and ev["etapa"] == "En cola"
    final = client.get(f"/evaluaciones/{ev['id']}", headers=admin).json()
    assert final["estado"] == "completada" and final["progreso"] == 100
    assert len(final["hallazgos"]) == 1


def test_no_se_lanzan_dos_evaluaciones_a_la_vez(admin):
    _, a = crear_activo(admin)
    db = SessionLocal()
    db.add(Evaluacion(activo_id=a["id"], estado=EstadoEvaluacion.EN_PROGRESO))
    db.commit()
    db.close()
    r = client.post(f"/activos/{a['id']}/evaluaciones", headers=admin)
    assert r.status_code == 409


def test_una_evaluacion_colgada_no_bloquea_para_siempre(admin):
    _, a = crear_activo(admin)
    db = SessionLocal()
    db.add(Evaluacion(activo_id=a["id"], estado=EstadoEvaluacion.EN_PROGRESO, iniciada_en=datetime.utcnow() - timedelta(hours=3)))
    db.commit()
    db.close()
    assert client.post(f"/activos/{a['id']}/evaluaciones", headers=admin).status_code == 201


def test_al_reiniciar_las_evaluaciones_huerfanas_se_marcan_fallidas(admin):
    _, a = crear_activo(admin)
    db = SessionLocal()
    ev = Evaluacion(activo_id=a["id"], estado=EstadoEvaluacion.EN_PROGRESO)
    db.add(ev)
    db.commit()
    eid = ev.id
    db.close()
    _cerrar_evaluaciones_huerfanas()
    final = client.get(f"/evaluaciones/{eid}", headers=admin).json()
    assert final["estado"] == "fallida" and "reinició" in final["detalle_error"]


# ---------------- Retención de datos ----------------
def test_retencion_borra_lo_antiguo_pero_conserva_el_estado_vigente(admin):
    _, a = crear_activo(admin)
    vieja = evaluacion_completada(a["id"], hace_dias=400)
    reciente = evaluacion_completada(a["id"], hace_dias=1)
    _, b = crear_activo(admin, nombre="Solo vieja")
    unica_vieja = evaluacion_completada(b["id"], hace_dias=500)  # es la vigente de su activo: se conserva
    db = SessionLocal()
    assert config_service.aplicar_retencion(db) == 1
    db.close()
    assert client.get(f"/evaluaciones/{vieja}", headers=admin).status_code == 404
    assert client.get(f"/evaluaciones/{reciente}", headers=admin).status_code == 200
    assert client.get(f"/evaluaciones/{unica_vieja}", headers=admin).status_code == 200


def test_retencion_cero_es_sin_limite(admin):
    cfg = client.get("/configuracion", headers=admin).json()
    cfg["retencion_dias"] = 0
    client.put("/configuracion", json=cfg, headers=admin)
    _, a = crear_activo(admin)
    evaluacion_completada(a["id"], hace_dias=900)
    evaluacion_completada(a["id"], hace_dias=1)
    db = SessionLocal()
    assert config_service.aplicar_retencion(db) == 0
    db.close()


# ---------------- Reportes ----------------
def test_generar_y_descargar_reporte_pdf(admin):
    p, a = crear_activo(admin)
    eid = evaluacion_completada(a["id"], hallazgos=(("Telnet expuesto", "alta", 7.5), ("Servicio SSH expuesto", "baja", 3.7)))
    r = client.post(f"/proyectos/{p['id']}/reportes", json={"titulo": "Informe <b>piloto</b>", "evaluacion_ids": [eid, eid]}, headers=admin)
    assert r.status_code == 201
    rep = r.json()
    assert rep["evaluacion_ids"] == [eid] and rep["tamano_kb"] >= 1
    assert rep["generado_por"] == "Admin" and rep["nombre_archivo"].endswith(".pdf")

    d = client.get(f"/reportes/{rep['id']}/descargar", headers=admin)
    assert d.status_code == 200
    assert d.headers["content-type"] == "application/pdf"
    assert d.content.startswith(b"%PDF") and len(d.content) > 1500

    assert [x["id"] for x in client.get("/reportes", headers=admin).json()] == [rep["id"]]


def test_reporte_titulo_por_defecto(admin):
    p, a = crear_activo(admin)
    eid = evaluacion_completada(a["id"])
    rep = client.post(f"/proyectos/{p['id']}/reportes", json={"evaluacion_ids": [eid]}, headers=admin).json()
    assert rep["titulo"].startswith("Informe de seguridad — Lab")


def test_reporte_valida_las_evaluaciones(admin):
    p, a = crear_activo(admin)
    _, otro = crear_activo(admin, nombre="Otro")
    ajena = evaluacion_completada(otro["id"])
    url = f"/proyectos/{p['id']}/reportes"
    assert client.post(url, json={"evaluacion_ids": []}, headers=admin).status_code == 422
    assert client.post(url, json={"evaluacion_ids": ["no-existe"]}, headers=admin).status_code == 400
    assert client.post(url, json={"evaluacion_ids": [ajena]}, headers=admin).status_code == 400  # de otro proyecto
    db = SessionLocal()
    ev = Evaluacion(activo_id=a["id"], estado=EstadoEvaluacion.FALLIDA)
    db.add(ev)
    db.commit()
    fallida = ev.id
    db.close()
    assert client.post(url, json={"evaluacion_ids": [fallida]}, headers=admin).status_code == 400


def test_reportes_respetan_la_propiedad(admin, ana):
    p, a = crear_activo(admin)
    eid = evaluacion_completada(a["id"])
    rep = client.post(f"/proyectos/{p['id']}/reportes", json={"evaluacion_ids": [eid]}, headers=admin).json()
    assert client.post(f"/proyectos/{p['id']}/reportes", json={"evaluacion_ids": [eid]}, headers=ana).status_code == 404
    assert client.get(f"/reportes/{rep['id']}/descargar", headers=ana).status_code == 404
    assert client.delete(f"/reportes/{rep['id']}", headers=ana).status_code == 404
    assert client.get("/reportes", headers=ana).json() == []
    assert client.get("/reportes").status_code == 401


def test_eliminar_reporte_borra_el_archivo(admin, tmp_path):
    p, a = crear_activo(admin)
    eid = evaluacion_completada(a["id"])
    rep = client.post(f"/proyectos/{p['id']}/reportes", json={"evaluacion_ids": [eid]}, headers=admin).json()
    archivo = tmp_path / "reportes" / f"{rep['id']}.pdf"
    assert archivo.is_file()
    assert client.delete(f"/reportes/{rep['id']}", headers=admin).status_code == 204
    assert not archivo.exists()
    assert client.get(f"/reportes/{rep['id']}/descargar", headers=admin).status_code == 404


def test_pdf_con_proyecto_sin_hallazgos(admin):
    p, a = crear_activo(admin)
    eid = evaluacion_completada(a["id"], hallazgos=())
    r = client.post(f"/proyectos/{p['id']}/reportes", json={"evaluacion_ids": [eid]}, headers=admin)
    assert r.status_code == 201


# ---------------- Migración de columnas ----------------
def test_migracion_agrega_columnas_a_una_base_antigua(tmp_path):
    ruta = tmp_path / "vieja.db"
    eng = create_engine(f"sqlite:///{ruta}")
    with eng.begin() as c:
        c.execute(text("CREATE TABLE usuarios (id VARCHAR PRIMARY KEY, nombre VARCHAR, email VARCHAR, password_hash VARCHAR, rol VARCHAR, creado_en DATETIME)"))
        c.execute(text("INSERT INTO usuarios (id, nombre, email, password_hash, rol) VALUES ('1','Vieja','v@t.cl','x','admin')"))
        c.execute(text("CREATE TABLE evaluaciones (id VARCHAR PRIMARY KEY, activo_id VARCHAR, estado VARCHAR, iniciada_en DATETIME, finalizada_en DATETIME, detalle_error TEXT)"))
    agregadas = agregar_columnas_faltantes(eng)
    assert "usuarios.activo" in agregadas and "evaluaciones.progreso" in agregadas and "evaluaciones.etapa" in agregadas
    cols = {c["name"] for c in inspect(eng).get_columns("usuarios")}
    assert "activo" in cols
    with eng.connect() as c:
        assert c.execute(text("SELECT activo FROM usuarios WHERE id='1'")).scalar() in (1, True)  # los existentes quedan activos
    assert agregar_columnas_faltantes(eng) == []  # idempotente


# ---------------- Listados globales (una sola consulta para el panel) ----------------
def test_listados_globales_respetan_la_propiedad(admin, ana):
    _, a_admin = crear_activo(admin, nombre="Del admin")
    _, a_ana = crear_activo(ana, nombre="De Ana")
    e_admin = evaluacion_completada(a_admin["id"])
    e_ana = evaluacion_completada(a_ana["id"])

    assert {a["nombre"] for a in client.get("/activos", headers=admin).json()} == {"Del admin", "De Ana"}  # el admin ve todo
    assert [a["nombre"] for a in client.get("/activos", headers=ana).json()] == ["De Ana"]
    assert {e["id"] for e in client.get("/evaluaciones", headers=admin).json()} == {e_admin, e_ana}
    assert [e["id"] for e in client.get("/evaluaciones", headers=ana).json()] == [e_ana]
    assert client.get("/activos").status_code == 401
    assert client.get("/evaluaciones").status_code == 401


def test_listados_globales_vacios(admin):
    assert client.get("/activos", headers=admin).json() == []
    assert client.get("/evaluaciones", headers=admin).json() == []


def test_evaluaciones_con_limite_por_activo(admin):
    _, a = crear_activo(admin, nombre="Uno")
    _, b = crear_activo(admin, nombre="Dos")
    ids_a = [evaluacion_completada(a["id"], hace_dias=d) for d in (30, 20, 10, 1)]  # la más reciente es la última
    ids_b = [evaluacion_completada(b["id"], hace_dias=d) for d in (15, 2)]
    todas = client.get("/evaluaciones", headers=admin).json()
    assert len(todas) == 6
    dos = client.get("/evaluaciones?ultimas=2", headers=admin).json()
    assert {e["id"] for e in dos} == {ids_a[3], ids_a[2], ids_b[0], ids_b[1]}
    assert all(e["hallazgos"] for e in dos)  # siguen trayendo sus hallazgos
    assert [e["iniciada_en"] for e in dos] == sorted((e["iniciada_en"] for e in dos), reverse=True)
    assert client.get("/evaluaciones?ultimas=0", headers=admin).status_code == 422
    # El detalle de una evaluación antigua sigue disponible
    assert client.get(f"/evaluaciones/{ids_a[0]}", headers=admin).status_code == 200
