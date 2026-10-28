"""
Métricas del panel, calculadas en la base de datos con consultas de agregación (GROUP BY).

Definiciones (las mismas que usa la interfaz):
- "Vigente": hallazgos de la ÚLTIMA evaluación completada de cada activo. Las evaluaciones
  anteriores son historial y no cuentan como riesgo actual.
- "Abierto": hallazgo vigente que no está marcado como corregido.
- Por semana: todos los hallazgos de las evaluaciones completadas de las últimas 8 semanas
  (semana = lunes a domingo, en UTC), agrupados por severidad.

Solo se consideran los proyectos que el usuario puede ver (los suyos; el admin ve todos).
"""
from datetime import date, datetime, timedelta
from typing import Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Activo, EstadoEvaluacion, Evaluacion, Hallazgo, SeveridadHallazgo, Usuario
from app.routers.proyectos import _ids_de_proyectos_visibles
from app.security import get_current_user

router = APIRouter(tags=["Métricas"])

SEVERIDADES = [s.value for s in SeveridadHallazgo]  # critica, alta, media, baja, informativa
SEMANAS = 8


def _lunes(d: date) -> date:
    return d - timedelta(days=d.weekday())


def _como_fecha(valor) -> date:
    return valor if isinstance(valor, date) and not isinstance(valor, datetime) else date.fromisoformat(str(valor)[:10])


@router.get("/metricas")
def metricas(db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)) -> Dict:
    ids = _ids_de_proyectos_visibles(db, user)
    vacio = {
        "totales": {"proyectos": 0, "activos": 0, "evaluaciones": 0, "completadas": 0, "fallidas": 0, "en_curso": 0, "hallazgos_abiertos": 0, "hallazgos_corregidos": 0},
        "por_severidad": {s: 0 for s in SEVERIDADES},
        "por_owasp": [],
        "por_semana": [],
    }
    hoy_lunes = _lunes(datetime.utcnow().date())
    semanas = [hoy_lunes - timedelta(weeks=i) for i in range(SEMANAS - 1, -1, -1)]
    vacio["por_semana"] = [{"inicio": s.isoformat(), **{x: 0 for x in SEVERIDADES}, "total": 0} for s in semanas]
    if not ids:
        return vacio

    # ---- Evaluaciones por estado (GROUP BY estado) ----
    por_estado = dict(
        db.query(Evaluacion.estado, func.count(Evaluacion.id))
        .join(Activo, Activo.id == Evaluacion.activo_id)
        .filter(Activo.proyecto_id.in_(ids))
        .group_by(Evaluacion.estado)
        .all()
    )
    n = lambda e: int(por_estado.get(e, 0))  # noqa: E731

    # ---- Última evaluación completada de cada activo (función de ventana) ----
    ranking = (
        db.query(
            Evaluacion.id.label("id"),
            func.row_number().over(partition_by=Evaluacion.activo_id, order_by=Evaluacion.iniciada_en.desc()).label("rn"),
        )
        .join(Activo, Activo.id == Evaluacion.activo_id)
        .filter(Evaluacion.estado == EstadoEvaluacion.COMPLETADA, Activo.proyecto_id.in_(ids))
        .subquery()
    )
    vigentes = db.query(ranking.c.id).filter(ranking.c.rn == 1).subquery()

    abierto = or_(Hallazgo.corregido.is_(None), Hallazgo.corregido != "si")

    # ---- GROUP BY severidad (hallazgos abiertos vigentes) ----
    por_severidad = {s: 0 for s in SEVERIDADES}
    for sev, cuenta in (
        db.query(Hallazgo.severidad, func.count(Hallazgo.id))
        .filter(Hallazgo.evaluacion_id.in_(db.query(vigentes.c.id)), abierto)
        .group_by(Hallazgo.severidad)
        .all()
    ):
        por_severidad[sev.value] = int(cuenta)

    corregidos = (
        db.query(func.count(Hallazgo.id))
        .filter(Hallazgo.evaluacion_id.in_(db.query(vigentes.c.id)), Hallazgo.corregido == "si")
        .scalar()
    )

    # ---- GROUP BY categoría OWASP ----
    por_owasp = [
        {"categoria": cat, "n": int(cuenta)}
        for cat, cuenta in (
            db.query(Hallazgo.categoria_owasp, func.count(Hallazgo.id))
            .filter(Hallazgo.evaluacion_id.in_(db.query(vigentes.c.id)), abierto)
            .group_by(Hallazgo.categoria_owasp)
            .order_by(func.count(Hallazgo.id).desc())
            .all()
        )
    ]

    # ---- GROUP BY día y severidad; luego se agrupa en semanas ----
    desde = datetime.combine(semanas[0], datetime.min.time())
    dia = func.date(Evaluacion.iniciada_en)
    filas = (
        db.query(dia, Hallazgo.severidad, func.count(Hallazgo.id))
        .join(Evaluacion, Evaluacion.id == Hallazgo.evaluacion_id)
        .join(Activo, Activo.id == Evaluacion.activo_id)
        .filter(Evaluacion.estado == EstadoEvaluacion.COMPLETADA, Activo.proyecto_id.in_(ids), Evaluacion.iniciada_en >= desde)
        .group_by(dia, Hallazgo.severidad)
        .all()
    )
    por_semana: List[Dict] = vacio["por_semana"]
    indice = {s["inicio"]: s for s in por_semana}
    for d, sev, cuenta in filas:
        bucket = indice.get(_lunes(_como_fecha(d)).isoformat())
        if bucket:
            bucket[sev.value] += int(cuenta)
            bucket["total"] += int(cuenta)

    activos_n = db.query(func.count(Activo.id)).filter(Activo.proyecto_id.in_(ids)).scalar()
    return {
        "totales": {
            "proyectos": len(ids),
            "activos": int(activos_n),
            "evaluaciones": sum(por_estado.values()),
            "completadas": n(EstadoEvaluacion.COMPLETADA),
            "fallidas": n(EstadoEvaluacion.FALLIDA),
            "en_curso": n(EstadoEvaluacion.PENDIENTE) + n(EstadoEvaluacion.EN_PROGRESO),
            "hallazgos_abiertos": sum(por_severidad.values()),
            "hallazgos_corregidos": int(corregidos or 0),
        },
        "por_severidad": por_severidad,
        "por_owasp": por_owasp,
        "por_semana": por_semana,
    }
