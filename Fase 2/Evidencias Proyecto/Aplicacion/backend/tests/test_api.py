"""
Pruebas funcionales y de seguridad básicas de la API (evidencia para la competencia
"Realizar pruebas de calidad"). Usan una BD SQLite temporal, no tocan PostgreSQL.
"""
# Acá pruebo lo básico de la API: registro, login, rutas protegidas y que un usuario no pueda ver lo de otro.
# Todas las pruebas de este archivo usan los endpoints reales a través de TestClient (no hay que levantar el servidor).
import os

# Lo fijo antes de importar la app para que las pruebas usen SQLite y nunca toquen la base PostgreSQL de verdad.
os.environ["DATABASE_URL"] = "sqlite:///./test_securescan.db"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import app

client = TestClient(app)


# Antes de cada prueba borro y recreo las tablas, así cada prueba parte de cero y no depende del resultado de otra.
@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


# Funciones de ayuda para no repetir código: registrar crea una cuenta, login pide el token y auth_header arma
# la cabecera "Authorization: Bearer ..." que usan las rutas protegidas.
def registrar(nombre="Ivan", email="ivan@test.cl", password="Password123"):
    return client.post("/auth/register", json={"nombre": nombre, "email": email, "password": password})


def login(email="ivan@test.cl", password="Password123"):
    return client.post("/auth/login", data={"username": email, "password": password})


def auth_header(email="ivan@test.cl", password="Password123"):
    token = login(email, password).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------- Funcionales: autenticación ----------
# Regla de negocio: la primera cuenta que se registra queda como administrador (así se crea el primer admin).
def test_registro_ok_y_primer_usuario_es_admin():
    r = registrar()
    assert r.status_code == 201
    assert r.json()["rol"] == "admin"


# El resto de las cuentas parte con el rol más bajo (usuario), nadie se vuelve admin solo por registrarse.
def test_segundo_usuario_es_usuario_normal():
    registrar()
    r = registrar(nombre="Ana", email="ana@test.cl")
    assert r.json()["rol"] == "usuario"


# No se puede registrar dos veces el mismo correo (error 400).
def test_registro_email_duplicado():
    registrar()
    assert registrar().status_code == 400


def test_login_correcto():
    registrar()
    r = login()
    assert r.status_code == 200
    assert "access_token" in r.json()


# Contraseña equivocada: la API responde 401 y no entrega ningún token.
def test_login_incorrecto():
    registrar()
    assert login(password="Incorrecta999").status_code == 401


# Seguridad: reviso directo en la base que la contraseña NO queda en texto plano. Los hash de bcrypt empiezan con "$2".
def test_password_se_guarda_hasheada():
    from app.database import SessionLocal
    from app.models import Usuario

    registrar()
    db = SessionLocal()
    usuario = db.query(Usuario).first()
    assert usuario.password_hash != "Password123"
    assert usuario.password_hash.startswith("$2")  # prefijo bcrypt
    db.close()


# ---------- Seguridad: validación de entrada ----------
# Validación de entrada: con una contraseña de 3 caracteres la API responde 422 (el esquema de datos la rechaza).
def test_password_corta_es_rechazada():
    r = registrar(password="123")
    assert r.status_code == 422


# ---------- Seguridad: acceso sin token ----------
# Sin token no se entra a las rutas protegidas (401).
def test_ruta_protegida_sin_token():
    assert client.get("/proyectos").status_code == 401


# Un token inventado o alterado tampoco sirve: la firma no coincide y responde 401.
def test_token_invalido():
    r = client.get("/proyectos", headers={"Authorization": "Bearer token.falso.123"})
    assert r.status_code == 401


# ---------- Funcionales: proyectos / activos / evaluaciones ----------
# Recorrido principal del sistema: crear proyecto, agregar un activo (la URL a evaluar) y pedir una evaluación.
# Compruebo que la evaluación nace con estado "pendiente".
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
# Control de acceso (OWASP A01, Broken Access Control): un usuario normal no debe ver los recursos de otra persona.
# Responde 404 y no 403, para no confirmar siquiera que ese proyecto existe.
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
