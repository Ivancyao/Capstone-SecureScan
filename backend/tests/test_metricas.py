"""
Pruebas de las métricas calculadas con SQL. La prueba clave compara el resultado de las
consultas GROUP BY contra un cálculo independiente hecho en Python sobre datos aleatorios.
"""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_securescan.db"

import random
from collections import Counter
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import Activo, EstadoEvaluacion, Evaluacion, Hallazgo, Proyecto, SeveridadHallazgo, Usuario
from app.security import hash_password

client = TestClient(app)
SEV = [s.value for s in SeveridadHallazgo]
OWASP = ["A02:2021 - Cryptographic Failures", "A05:2021 - Security Misconfiguration", None]


@pytest.fixture(autouse=True)
def limpio():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def usuario(db, email, rol="usuario"):
    u = Usuario(nombre=email.split("@")[0].title(), email=email, password_hash=hash_password("Password123"), rol=rol)
    db.add(u)
    db.commit()
    return u


def cab(email):
    r = client.post("/auth/login", data={"username": email, "password": "Password123"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def sembrar(db, dueno, semilla=1, activos=6, evals_por_activo=5):
    """Datos aleatorios; devuelve las evaluaciones creadas para calcular el resultado esperado en Python."""
    rnd = random.Random(semilla)
    p = Proyecto(nombre="P", propietario_id=dueno.id)
    db.add(p)
    db.flush()
    todas = []
    for i in range(activos):
        a = Activo(proyecto_id=p.id, nombre=f"A{i}", url_objetivo="http://10.0.0.1")
        db.add(a)
        db.flush()
        for j in range(evals_por_activo):
            estado = rnd.choice([EstadoEvaluacion.COMPLETADA] * 4 + [EstadoEvaluacion.FALLIDA])
            ev = Evaluacion(activo_id=a.id, estado=estado, iniciada_en=datetime.utcnow() - timedelta(days=rnd.randint(0, 80), hours=rnd.randint(0, 23)))
            db.add(ev)
            db.flush()
            hs = []
            if estado == EstadoEvaluacion.COMPLETADA:
                for _ in range(rnd.randint(0, 6)):
                    h = Hallazgo(evaluacion_id=ev.id, nombre_vulnerabilidad="x", severidad=SeveridadHallazgo(rnd.choice(SEV)),
                                 categoria_owasp=rnd.choice(OWASP), corregido=rnd.choice(["no", "no", "si"]))
                    db.add(h)
                    hs.append(h)
            todas.append((a.id, ev, hs))
    db.commit()
    return todas


def esperado(todas):
    """Cálculo independiente, en Python puro."""
    ultima = {}
    for aid, ev, hs in sorted(todas, key=lambda t: t[1].iniciada_en):
        if ev.estado == EstadoEvaluacion.COMPLETADA:
            ultima[aid] = (ev, hs)
    sev, owasp = Counter(), Counter()
    corregidos = 0
    for ev, hs in ultima.values():
        for h in hs:
            if h.corregido == "si":
                corregidos += 1
            else:
                sev[h.severidad.value] += 1
                owasp[h.categoria_owasp] += 1
    return sev, owasp, corregidos


def test_sql_coincide_con_calculo_independiente():
    db = SessionLocal()
    admin = usuario(db, "admin@t.cl", "admin")
    for semilla in (1, 2, 3):
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        admin = usuario(db, "admin@t.cl", "admin")
        todas = sembrar(db, admin, semilla=semilla)
        sev, owasp, corregidos = esperado(todas)
        m = client.get("/metricas", headers=cab("admin@t.cl")).json()
        assert m["por_severidad"] == {s: sev.get(s, 0) for s in SEV}
        assert {x["categoria"]: x["n"] for x in m["por_owasp"]} == dict(owasp)
        assert m["totales"]["hallazgos_abiertos"] == sum(sev.values())
        assert m["totales"]["hallazgos_corregidos"] == corregidos
        comp = sum(1 for _, e, _ in todas if e.estado == EstadoEvaluacion.COMPLETADA)
        assert m["totales"]["completadas"] == comp and m["totales"]["evaluaciones"] == len(todas)
        db.close()


def test_semanas_son_ocho_y_suman_los_hallazgos_recientes():
    db = SessionLocal()
    admin = usuario(db, "admin@t.cl", "admin")
    todas = sembrar(db, admin, semilla=7)
    m = client.get("/metricas", headers=cab("admin@t.cl")).json()
    assert len(m["por_semana"]) == 8
    assert [s["inicio"] for s in m["por_semana"]] == sorted(s["inicio"] for s in m["por_semana"])
    assert all(s["total"] == sum(s[x] for x in SEV) for s in m["por_semana"])
    inicio = datetime.fromisoformat(m["por_semana"][0]["inicio"])
    esp = sum(len(hs) for _, ev, hs in todas if ev.estado == EstadoEvaluacion.COMPLETADA and ev.iniciada_en >= inicio)
    assert sum(s["total"] for s in m["por_semana"]) == esp


def test_cada_usuario_solo_ve_sus_metricas():
    db = SessionLocal()
    admin = usuario(db, "admin@t.cl", "admin")
    ana = usuario(db, "ana@t.cl")
    sembrar(db, admin, semilla=1)
    sembrar(db, ana, semilla=2, activos=2, evals_por_activo=2)
    todo = client.get("/metricas", headers=cab("admin@t.cl")).json()["totales"]
    solo_ana = client.get("/metricas", headers=cab("ana@t.cl")).json()["totales"]
    assert todo["activos"] == 8 and solo_ana["activos"] == 2 and solo_ana["proyectos"] == 1
    otra = usuario(db, "otra@t.cl")
    vacio = client.get("/metricas", headers=cab("otra@t.cl")).json()
    assert vacio["totales"]["activos"] == 0 and len(vacio["por_semana"]) == 8
    assert client.get("/metricas").status_code == 401


def test_corregir_un_hallazgo_baja_los_abiertos():
    db = SessionLocal()
    admin = usuario(db, "admin@t.cl", "admin")
    sembrar(db, admin, semilla=4)
    h = cab("admin@t.cl")
    antes = client.get("/metricas", headers=h).json()["totales"]["hallazgos_abiertos"]
    assert antes > 0
    # corrige un hallazgo abierto y vigente
    todos = client.get("/evaluaciones", headers=h).json()
    ultima = {}
    for e in sorted(todos, key=lambda e: e["iniciada_en"]):
        if e["estado"] == "completada":
            ultima[e["activo_id"]] = e
    objetivo = next(x for e in ultima.values() for x in e["hallazgos"] if x["corregido"] != "si")
    client.patch(f"/hallazgos/{objetivo['id']}", json={"corregido": "si"}, headers=h)
    despues = client.get("/metricas", headers=h).json()["totales"]
    assert despues["hallazgos_abiertos"] == antes - 1
