"""
Prueba de rendimiento de la API con volúmenes crecientes de datos.

Uso (desde backend/):
    DATABASE_URL=sqlite:///./rendimiento.db python tools/rendimiento.py
    DATABASE_URL=postgresql://... python tools/rendimiento.py      # contra PostgreSQL real

Siembra datos aleatorios en 3 escalas, mide la latencia de los endpoints (mediana, p95 y máximo
de N repeticiones) y el tamaño de la respuesta, y escribe un resumen en rendimiento_resultados.md.
Usa la base indicada en DATABASE_URL: ¡usa una base de pruebas, se BORRAN y recrean las tablas!
"""
import os
import random
import statistics
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("DATABASE_URL", "sqlite:///./rendimiento.db")
os.environ.setdefault("REPORTS_DIR", "./rendimiento_reportes")

from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Activo, Evaluacion, Hallazgo, Proyecto, Usuario  # noqa: E402
from app.security import hash_password  # noqa: E402

ESCALAS = [  # (nombre, proyectos, activos por proyecto, evaluaciones por activo)
    ("pequeña", 3, 3, 4),
    ("mediana", 10, 10, 10),
    ("grande", 20, 15, 20),
]
REPETICIONES = 15
SEV = ["critica", "alta", "media", "baja", "informativa"]
PESOS = [1, 3, 6, 5, 8]
OWASP = ["A02:2021 - Cryptographic Failures", "A05:2021 - Security Misconfiguration"]
client = TestClient(app)


def sembrar(proyectos, activos_por, evals_por):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    rnd = random.Random(42)
    db = SessionLocal()
    admin = Usuario(nombre="Admin", email="admin@perf.cl", password_hash=hash_password("Password123"), rol="admin")
    db.add(admin)
    db.commit()
    import uuid
    ps, acts, evs, hs = [], [], [], []
    for i in range(proyectos):
        pid = str(uuid.uuid4())
        ps.append(dict(id=pid, nombre=f"Proyecto {i}", propietario_id=admin.id, creado_en=datetime.utcnow()))
        for j in range(activos_por):
            aid = str(uuid.uuid4())
            acts.append(dict(id=aid, proyecto_id=pid, nombre=f"Activo {i}-{j}", url_objetivo="http://10.0.0.5", creado_en=datetime.utcnow()))
            for k in range(evals_por):
                eid = str(uuid.uuid4())
                ini = datetime.utcnow() - timedelta(days=rnd.randint(0, 120), hours=rnd.randint(0, 23))
                evs.append(dict(id=eid, activo_id=aid, estado="completada", iniciada_en=ini, finalizada_en=ini + timedelta(seconds=30), progreso=100, etapa="Completada"))
                for _ in range(rnd.randint(1, 8)):
                    sev = rnd.choices(SEV, PESOS)[0]
                    hs.append(dict(id=str(uuid.uuid4()), evaluacion_id=eid, nombre_vulnerabilidad="Servicio HTTP expuesto sin cifrado",
                                   categoria_owasp=rnd.choice(OWASP), cvss_score=5.3, severidad=sev,
                                   evidencia="Puerto 80/tcp abierto — servicio: http (nginx 1.22)",
                                   recomendacion="Configurar HTTPS (TLS), redirigir HTTP a HTTPS y restringir servicios innecesarios.",
                                   herramienta_origen="nmap", corregido=rnd.choice(["no", "no", "si"])))
    from sqlalchemy import insert
    for modelo, filas in ((Proyecto, ps), (Activo, acts), (Evaluacion, evs), (Hallazgo, hs)):
        for i in range(0, len(filas), 5000):
            db.execute(insert(modelo), filas[i:i + 5000])
    db.commit()
    db.close()
    return dict(proyectos=len(ps), activos=len(acts), evaluaciones=len(evs), hallazgos=len(hs)), evs[0]["id"], ps[0]["id"]


def medir(cabecera, metodo, ruta, **kw):
    tiempos, tam = [], 0
    for _ in range(REPETICIONES):
        t = time.perf_counter()
        r = client.request(metodo, ruta, headers=cabecera, **kw)
        tiempos.append((time.perf_counter() - t) * 1000)
        assert r.status_code < 400, (ruta, r.status_code, r.text[:200])
        tam = len(r.content)
    tiempos.sort()
    return statistics.median(tiempos), tiempos[int(len(tiempos) * 0.95) - 1], tiempos[-1], tam


def main():
    motor = engine.dialect.name
    lineas = [f"# Resultados de rendimiento\n", f"Motor de base de datos: **{motor}** · {REPETICIONES} repeticiones por medición · tiempos en milisegundos (incluye la pila completa de la API, sin red).\n"]
    for nombre, p, a, e in ESCALAS:
        cuentas, una_eval, un_proy = sembrar(p, a, e)
        t = time.perf_counter()
        r = client.post("/auth/login", data={"username": "admin@perf.cl", "password": "Password123"})
        login_ms = (time.perf_counter() - t) * 1000
        cab = {"Authorization": f"Bearer {r.json()['access_token']}"}
        lineas.append(f"\n## Escala {nombre}: {cuentas['proyectos']} proyectos, {cuentas['activos']} activos, {cuentas['evaluaciones']} evaluaciones, {cuentas['hallazgos']} hallazgos\n")
        lineas.append("| Endpoint | Mediana | p95 | Máximo | Tamaño respuesta |\n|---|---|---|---|---|")
        lineas.append(f"| POST /auth/login (bcrypt, 1 vez) | {login_ms:.0f} | — | — | — |")
        pruebas = [
            ("GET", "/proyectos", {}), ("GET", "/activos", {}), ("GET", "/metricas", {}),
            ("GET", f"/evaluaciones/{una_eval}", {}), ("GET", "/evaluaciones?ultimas=10", {}), ("GET", "/evaluaciones", {}),
        ]
        for metodo, ruta, kw in pruebas:
            med, p95, mx, tam = medir(cab, metodo, ruta, **kw)
            lineas.append(f"| {metodo} {ruta if 'evaluaciones/' not in ruta else '/evaluaciones/{id}'} | {med:.1f} | {p95:.1f} | {mx:.1f} | {tam/1024:.0f} KB |")
        # Reporte PDF con las 10 evaluaciones más recientes del primer proyecto
        evs = [x["id"] for x in client.get("/evaluaciones", headers=cab).json() if True][:10]
        db = SessionLocal()
        ids_ok = [ev.id for ev in db.query(Evaluacion).join(Activo).filter(Activo.proyecto_id == un_proy).limit(10).all()]
        db.close()
        t = time.perf_counter()
        r = client.post(f"/proyectos/{un_proy}/reportes", json={"evaluacion_ids": ids_ok}, headers=cab)
        pdf_ms = (time.perf_counter() - t) * 1000
        lineas.append(f"| POST /proyectos/{{id}}/reportes (PDF, {len(ids_ok)} evaluaciones) | {pdf_ms:.0f} | — | — | {r.json().get('tamano_kb')} KB |")
        print("\n".join(lineas[-9:]), flush=True)
    Path("rendimiento_resultados.md").write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print("\nEscrito en rendimiento_resultados.md")


if __name__ == "__main__":
    main()
