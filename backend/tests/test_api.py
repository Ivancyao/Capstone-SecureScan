"""
Pruebas funcionales y de seguridad básicas de la API (evidencia para la competencia
"Realizar pruebas de calidad"). Usan una BD SQLite temporal, no tocan PostgreSQL.
"""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_securescan.db"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


def registrar(nombre="Ivan", email="ivan@test.cl", password="Password123"):
    return client.post("/auth/register", json={"nombre": nombre, "email": email, "password": password})


def login(email="ivan@test.cl", password="Password123"):
    r = client.post("/auth/login", data={"username": email, "password": password})
    return r


def auth_header(email="ivan@test.cl", password="Password123"):
    token = login(email, password).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------- Funcionales: autenticación ----------
def test_registro_ok_y_primer_usuario_es_admin():
    r = registrar()
    assert r.status_code == 201
    assert r.json()["rol"] == "admin"


def test_segundo_usuario_es_usuario_normal():
    registrar()
    r = registrar(nombre="Ana", email="ana@test.cl")
    assert r.json()["rol"] == "usuario"


def test_registro_email_duplicado():
    registrar()
    assert registrar().status_code == 400


def test_login_correcto():
    registrar()
    r = login()
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_login_incorrecto():
    registrar()
    assert login(password="Incorrecta999").status_code == 401


def test_password_se_guarda_hasheada():
    from app.database import SessionLocal
    from app.models import Usuario

    registrar()
    db = SessionLocal()
    user = db.query(Usuario).first()
    assert user.password_hash != "Password123"
    assert user.password_hash.startswith("$2")  # prefijo bcrypt
    db.close()


# ---------- Seguridad: validación de entrada ----------
def test_password_corta_es_rechazada():
    r = registrar(password="123")
    assert r.status_code == 422


# ---------- Seguridad: acceso sin token ----------
def test_ruta_protegida_sin_token():
    assert client.get("/proyectos").status_code == 401


def test_token_invalido():
    r = client.get("/proyectos", headers={"Authorization": "Bearer token.falso.123"})
    assert r.status_code == 401


# ---------- Funcionales: proyectos / activos / evaluaciones ----------
def test_flujo_completo_proyecto_activo_evaluacion():
    registrar()
    h = auth_header()
    p = client.post("/proyectos", json={"nombre": "Lab"}, headers=h).json()
    a = client.post(
        f"/proyectos/{p['id']}/activos",
        json={"nombre": "DVWA", "url_objetivo": "http://dvwa.local"},
        headers=h,
    )
    assert a.status_code == 201
    e = client.post(f"/activos/{a.json()['id']}/evaluaciones", headers=h)
    assert e.status_code == 201
    assert e.json()["estado"] == "pendiente"


# ---------- Seguridad: Broken Access Control (OWASP A01) ----------
def test_usuario_no_puede_ver_proyecto_de_otro():
    registrar()                                   # admin
    registrar(nombre="Ana", email="ana@test.cl")  # usuario normal
    h_admin = auth_header()
    h_ana = auth_header("ana@test.cl")

    p = client.post("/proyectos", json={"nombre": "Privado"}, headers=h_admin).json()

    # Ana no es dueña ni admin -> no debe ver los activos de ese proyecto
    r = client.get(f"/proyectos/{p['id']}/activos", headers=h_ana)
    assert r.status_code == 404

    # Y su listado de proyectos no debe incluirlo
    assert client.get("/proyectos", headers=h_ana).json() == []
