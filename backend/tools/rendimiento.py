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
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("DATABASE_URL", "sqlite:///./rendimiento.db")
os.environ.setdefault("REPORTS_DIR", "./rendimiento_reportes")

from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Activo, Evaluacion, Hallazgo, Proyecto, Usuario  # noqa: E402
from app.security import hashear_contrasena  # noqa: E402
from app.tiempo import ahora_utc  # noqa: E402

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


def sembrar(cantidad_de_proyectos, activos_por_proyecto, evaluaciones_por_activo):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    azar = random.Random(42)
    db = SessionLocal()
    admin = Usuario(nombre="Admin", email="admin@perf.cl", password_hash=hashear_contrasena("Password123"), rol="admin")
    db.add(admin)
    db.commit()
    import uuid
    proyectos_creados, activos_creados, evaluaciones_creadas, hallazgos_creados = [], [], [], []
    for i in range(cantidad_de_proyectos):
        proyecto_id = str(uuid.uuid4())
        proyectos_creados.append(dict(id=proyecto_id, nombre=f"Proyecto {i}", propietario_id=admin.id, creado_en=ahora_utc()))
        for numero_de_activo in range(activos_por_proyecto):
            activo_id = str(uuid.uuid4())
            activos_creados.append(dict(id=activo_id, proyecto_id=proyecto_id, nombre=f"Activo {i}-{numero_de_activo}", url_objetivo="http://10.0.0.5", creado_en=ahora_utc()))
            for numero_de_evaluacion in range(evaluaciones_por_activo):
                evaluacion_id = str(uuid.uuid4())
                inicio = ahora_utc() - timedelta(days=azar.randint(0, 120), hours=azar.randint(0, 23))
                evaluaciones_creadas.append(dict(id=evaluacion_id, activo_id=activo_id, estado="completada", iniciada_en=inicio, finalizada_en=inicio + timedelta(seconds=30), progreso=100, etapa="Completada"))
                for _ in range(azar.randint(1, 8)):
                    severidad = azar.choices(SEV, PESOS)[0]
                    hallazgos_creados.append(dict(id=str(uuid.uuid4()), evaluacion_id=evaluacion_id, nombre_vulnerabilidad="Servicio HTTP expuesto sin cifrado",
                                   categoria_owasp=azar.choice(OWASP), cvss_score=5.3, severidad=severidad,
                                   evidencia="Puerto 80/tcp abierto — servicio: http (nginx 1.22)",
                                   recomendacion="Configurar HTTPS (TLS), redirigir HTTP a HTTPS y restringir servicios innecesarios.",
                                   herramienta_origen="nmap", corregido=azar.choice(["no", "no", "si"])))
    from sqlalchemy import insert
    for modelo, filas in ((Proyecto, proyectos_creados), (Activo, activos_creados), (Evaluacion, evaluaciones_creadas), (Hallazgo, hallazgos_creados)):
        for i in range(0, len(filas), 5000):
            db.execute(insert(modelo), filas[i:i + 5000])
    db.commit()
    db.close()
    return dict(proyectos=len(proyectos_creados), activos=len(activos_creados), evaluaciones=len(evaluaciones_creadas), hallazgos=len(hallazgos_creados)), evaluaciones_creadas[0]["id"], proyectos_creados[0]["id"]


def medir(cabecera, metodo, ruta, **opciones):
    tiempos, tamano_respuesta = [], 0
    for _ in range(REPETICIONES):
        inicio = time.perf_counter()
        respuesta = client.request(metodo, ruta, headers=cabecera, **opciones)
        tiempos.append((time.perf_counter() - inicio) * 1000)
        assert respuesta.status_code < 400, (ruta, respuesta.status_code, respuesta.text[:200])
        tamano_respuesta = len(respuesta.content)
    tiempos.sort()
    return statistics.median(tiempos), tiempos[int(len(tiempos) * 0.95) - 1], tiempos[-1], tamano_respuesta


def main():
    motor = engine.dialect.name
    lineas = ["# Resultados de rendimiento\n", f"Motor de base de datos: **{motor}** · {REPETICIONES} repeticiones por medición · tiempos en milisegundos (incluye la pila completa de la API, sin red).\n"]
    for nombre, cantidad_de_proyectos, activos_por_proyecto, evaluaciones_por_activo in ESCALAS:
        cuentas, una_eval, un_proy = sembrar(cantidad_de_proyectos, activos_por_proyecto, evaluaciones_por_activo)
        inicio = time.perf_counter()
        respuesta = client.post("/auth/login", data={"username": "admin@perf.cl", "password": "Password123"})
        login_ms = (time.perf_counter() - inicio) * 1000
        cabecera = {"Authorization": f"Bearer {respuesta.json()['access_token']}"}
        lineas.append(f"\n## Escala {nombre}: {cuentas['proyectos']} proyectos, {cuentas['activos']} activos, {cuentas['evaluaciones']} evaluaciones, {cuentas['hallazgos']} hallazgos\n")
        lineas.append("| Endpoint | Mediana | p95 | Máximo | Tamaño respuesta |\n|---|---|---|---|---|")
        lineas.append(f"| POST /auth/login (bcrypt, 1 vez) | {login_ms:.0f} | — | — | — |")
        pruebas = [
            ("GET", "/proyectos", {}), ("GET", "/activos", {}), ("GET", "/metricas", {}),
            ("GET", f"/evaluaciones/{una_eval}", {}), ("GET", "/evaluaciones?ultimas=10", {}), ("GET", "/evaluaciones?pagina=1&por_pagina=50", {}),
            ("GET", "/evaluaciones?pagina=60&por_pagina=50", {}), ("GET", "/evaluaciones", {}),
        ]
        for metodo, ruta, opciones in pruebas:
            mediana, p95, maximo, tamano_respuesta = medir(cabecera, metodo, ruta, **opciones)
            lineas.append(f"| {metodo} {ruta if 'evaluaciones/' not in ruta else '/evaluaciones/{id}'} | {mediana:.1f} | {p95:.1f} | {maximo:.1f} | {tamano_respuesta/1024:.0f} KB |")
        # Reporte PDF con las 10 evaluaciones más recientes del primer proyecto
        db = SessionLocal()
        ids_ok = [ev.id for ev in db.query(Evaluacion).join(Activo).filter(Activo.proyecto_id == un_proy).limit(10).all()]
        db.close()
        inicio = time.perf_counter()
        respuesta = client.post(f"/proyectos/{un_proy}/reportes", json={"evaluacion_ids": ids_ok}, headers=cabecera)
        pdf_ms = (time.perf_counter() - inicio) * 1000
        lineas.append(f"| POST /proyectos/{{id}}/reportes (PDF, {len(ids_ok)} evaluaciones) | {pdf_ms:.0f} | — | — | {respuesta.json().get('tamano_kb')} KB |")
        print("\n".join(lineas[-9:]), flush=True)
    Path("rendimiento_resultados.md").write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print("\nEscrito en rendimiento_resultados.md")


if __name__ == "__main__":
    main()
