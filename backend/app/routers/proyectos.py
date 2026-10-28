"""
Proyectos, Activos y Evaluaciones.

Control de acceso (previene "Broken Access Control", OWASP A01):
cada usuario solo puede ver/modificar sus propios proyectos. El ADMIN puede ver todos.
"""
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app import config_service
from app.models import Activo, EstadoEvaluacion, Evaluacion, Hallazgo, Proyecto, RolUsuario, Usuario
from app.schemas import (
    ActivoCreate,
    ActivoOut,
    EvaluacionOut,
    HallazgoOut,
    HallazgoUpdate,
    ProyectoCreate,
    ProyectoOut,
)
from app.scan_service import ejecutar_evaluacion
from app.security import get_current_user

router = APIRouter(tags=["Proyectos, Activos y Evaluaciones"])


def _get_proyecto_or_404(db: Session, proyecto_id: str, user: Usuario) -> Proyecto:
    proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
    if not proyecto:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    if proyecto.propietario_id != user.id and user.rol != RolUsuario.ADMIN:
        # Respondemos 404 (no 403) para no revelar que el recurso existe.
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    return proyecto


def _get_activo_or_404(db: Session, activo_id: str, user: Usuario) -> Activo:
    activo = db.query(Activo).filter(Activo.id == activo_id).first()
    if not activo:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    _get_proyecto_or_404(db, activo.proyecto_id, user)  # reutiliza la verificación de propiedad
    return activo


# ---------------- Proyectos ----------------
@router.post("/proyectos", response_model=ProyectoOut, status_code=status.HTTP_201_CREATED)
def crear_proyecto(
    data: ProyectoCreate,
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    proyecto = Proyecto(nombre=data.nombre, descripcion=data.descripcion, propietario_id=user.id)
    db.add(proyecto)
    db.commit()
    db.refresh(proyecto)
    return proyecto


@router.get("/proyectos", response_model=List[ProyectoOut])
def listar_proyectos(
    db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)
):
    query = db.query(Proyecto)
    if user.rol != RolUsuario.ADMIN:
        query = query.filter(Proyecto.propietario_id == user.id)
    return query.order_by(Proyecto.creado_en.desc()).all()


def _ids_de_proyectos_visibles(db: Session, user: Usuario) -> List[str]:
    q = db.query(Proyecto.id)
    if user.rol != RolUsuario.ADMIN:
        q = q.filter(Proyecto.propietario_id == user.id)
    return [i for (i,) in q.all()]


# ---------------- Activos ----------------
@router.get("/activos", response_model=List[ActivoOut])
def listar_todos_los_activos(db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    """Todos los activos que el usuario puede ver (los de sus proyectos; el admin ve todos)."""
    ids = _ids_de_proyectos_visibles(db, user)
    if not ids:
        return []
    return db.query(Activo).filter(Activo.proyecto_id.in_(ids)).order_by(Activo.creado_en.asc()).all()


@router.post(
    "/proyectos/{proyecto_id}/activos",
    response_model=ActivoOut,
    status_code=status.HTTP_201_CREATED,
)
def crear_activo(
    proyecto_id: str,
    data: ActivoCreate,
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    _get_proyecto_or_404(db, proyecto_id, user)
    activo = Activo(
        proyecto_id=proyecto_id,
        nombre=data.nombre,
        url_objetivo=data.url_objetivo,
        descripcion=data.descripcion,
    )
    db.add(activo)
    db.commit()
    db.refresh(activo)
    return activo


@router.get("/proyectos/{proyecto_id}/activos", response_model=List[ActivoOut])
def listar_activos(
    proyecto_id: str,
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    _get_proyecto_or_404(db, proyecto_id, user)
    return db.query(Activo).filter(Activo.proyecto_id == proyecto_id).all()


# ---------------- Evaluaciones ----------------
@router.post(
    "/activos/{activo_id}/evaluaciones",
    response_model=EvaluacionOut,
    status_code=status.HTTP_201_CREATED,
)
def iniciar_evaluacion(
    activo_id: str,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    """
    Crea la evaluación (PENDIENTE) y lanza el escaneo en segundo plano.
    La respuesta es inmediata; el cliente consulta el estado hasta que sea COMPLETADA o FALLIDA.
    """
    _get_activo_or_404(db, activo_id, user)

    # Una sola evaluación a la vez por activo. Las que quedaron "colgadas" (más antiguas que
    # el tiempo máximo de escaneo) no cuentan, para que un fallo no bloquee el activo para siempre.
    timeout = config_service.obtener(db)["motores"]["nmap"]["timeout_s"]
    limite = datetime.utcnow() - timedelta(seconds=timeout + 120)
    en_curso = (
        db.query(Evaluacion)
        .filter(
            Evaluacion.activo_id == activo_id,
            Evaluacion.estado.in_([EstadoEvaluacion.PENDIENTE, EstadoEvaluacion.EN_PROGRESO]),
            Evaluacion.iniciada_en > limite,
        )
        .first()
    )
    if en_curso:
        raise HTTPException(status_code=409, detail="Ya hay una evaluación en curso para este activo.")

    evaluacion = Evaluacion(activo_id=activo_id, progreso=0, etapa="En cola")
    db.add(evaluacion)
    db.commit()
    db.refresh(evaluacion)
    background.add_task(ejecutar_evaluacion, evaluacion.id)
    return evaluacion


@router.get("/activos/{activo_id}/evaluaciones", response_model=List[EvaluacionOut])
def listar_evaluaciones(
    activo_id: str,
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    _get_activo_or_404(db, activo_id, user)
    return (
        db.query(Evaluacion)
        .filter(Evaluacion.activo_id == activo_id)
        .options(selectinload(Evaluacion.hallazgos))
        .order_by(Evaluacion.iniciada_en.desc())
        .all()
    )


@router.get("/evaluaciones", response_model=List[EvaluacionOut])
def listar_todas_las_evaluaciones(
    ultimas: Optional[int] = Query(default=None, ge=1, le=200, description="Solo las N evaluaciones más recientes de cada activo"),
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    """
    Evaluaciones visibles para el usuario, de la más reciente a la más antigua.
    Con `ultimas=N` se limita a las N más recientes de cada activo: así la respuesta no crece
    sin límite a medida que se acumula historial (el detalle de una evaluación antigua sigue
    disponible en GET /evaluaciones/{id}).
    """
    ids = _ids_de_proyectos_visibles(db, user)
    if not ids:
        return []
    q = (
        db.query(Evaluacion)
        .join(Activo, Activo.id == Evaluacion.activo_id)
        .filter(Activo.proyecto_id.in_(ids))
    )
    if ultimas:
        ranking = (
            db.query(
                Evaluacion.id.label("id"),
                func.row_number().over(partition_by=Evaluacion.activo_id, order_by=Evaluacion.iniciada_en.desc()).label("rn"),
            )
            .join(Activo, Activo.id == Evaluacion.activo_id)
            .filter(Activo.proyecto_id.in_(ids))
            .subquery()
        )
        q = q.filter(Evaluacion.id.in_(db.query(ranking.c.id).filter(ranking.c.rn <= ultimas)))
    return (
        q.options(selectinload(Evaluacion.hallazgos))  # una consulta para todos los hallazgos (evita N+1)
        .order_by(Evaluacion.iniciada_en.desc())
        .all()
    )


@router.get("/evaluaciones/{evaluacion_id}", response_model=EvaluacionOut)
def obtener_evaluacion(
    evaluacion_id: str,
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    evaluacion = db.query(Evaluacion).filter(Evaluacion.id == evaluacion_id).first()
    if not evaluacion:
        raise HTTPException(status_code=404, detail="Evaluación no encontrada")
    _get_activo_or_404(db, evaluacion.activo_id, user)
    return evaluacion


# ---------------- Hallazgos ----------------
@router.patch("/hallazgos/{hallazgo_id}", response_model=HallazgoOut)
def actualizar_hallazgo(
    hallazgo_id: str,
    data: HallazgoUpdate,
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    """Marca un hallazgo como corregido ("si") o lo reabre ("no")."""
    hallazgo = db.query(Hallazgo).filter(Hallazgo.id == hallazgo_id).first()
    if not hallazgo:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    evaluacion = db.query(Evaluacion).filter(Evaluacion.id == hallazgo.evaluacion_id).first()
    _get_activo_or_404(db, evaluacion.activo_id, user)  # misma verificación de propiedad
    hallazgo.corregido = data.corregido
    db.commit()
    db.refresh(hallazgo)
    return hallazgo
