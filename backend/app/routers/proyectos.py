"""Proyectos, activos y evaluaciones.

Control de acceso (Broken Access Control, OWASP A01): cada usuario solo ve y modifica sus propios
proyectos. El ADMIN puede ver todos.
"""
from datetime import timedelta
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
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
from app.cancelacion import ETAPA_CANCELADA
from app.scan_service import ejecutar_evaluacion
from app.security import obtener_usuario_actual
from app.tiempo import ahora_utc

router = APIRouter(tags=["Proyectos, Activos y Evaluaciones"])


def _get_proyecto_or_404(db: Session, proyecto_id: str, usuario: Usuario) -> Proyecto:
    proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
    if not proyecto:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    if proyecto.propietario_id != usuario.id and usuario.rol != RolUsuario.ADMIN:
        # Respondemos 404 (no 403) para no revelar que el recurso existe.
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    return proyecto


def _get_activo_or_404(db: Session, activo_id: str, usuario: Usuario) -> Activo:
    activo = db.query(Activo).filter(Activo.id == activo_id).first()
    if not activo:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    _get_proyecto_or_404(db, activo.proyecto_id, usuario)  # reutiliza la verificación de propiedad
    return activo


def _get_evaluacion_or_404(db: Session, evaluacion_id: str, usuario: Usuario) -> Evaluacion:
    evaluacion = db.query(Evaluacion).filter(Evaluacion.id == evaluacion_id).first()
    if not evaluacion:
        raise HTTPException(status_code=404, detail="Evaluación no encontrada")
    _get_activo_or_404(db, evaluacion.activo_id, usuario)  # misma verificación de propiedad
    return evaluacion


# ---------------- Proyectos ----------------
@router.post("/proyectos", response_model=ProyectoOut, status_code=status.HTTP_201_CREATED)
def crear_proyecto(
    datos: ProyectoCreate,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    proyecto = Proyecto(nombre=datos.nombre, descripcion=datos.descripcion, propietario_id=usuario.id)
    db.add(proyecto)
    db.commit()
    db.refresh(proyecto)
    return proyecto


@router.get("/proyectos", response_model=List[ProyectoOut])
def listar_proyectos(
    db: Session = Depends(get_db), usuario: Usuario = Depends(obtener_usuario_actual)
):
    query = db.query(Proyecto)
    if usuario.rol != RolUsuario.ADMIN:
        query = query.filter(Proyecto.propietario_id == usuario.id)
    return query.order_by(Proyecto.creado_en.desc()).all()


def _ids_de_proyectos_visibles(db: Session, usuario: Usuario) -> List[str]:
    consulta = db.query(Proyecto.id)
    if usuario.rol != RolUsuario.ADMIN:
        consulta = consulta.filter(Proyecto.propietario_id == usuario.id)
    return [proyecto_id for (proyecto_id,) in consulta.all()]


# ---------------- Activos ----------------
@router.get("/activos", response_model=List[ActivoOut])
def listar_todos_los_activos(db: Session = Depends(get_db), usuario: Usuario = Depends(obtener_usuario_actual)):
    """Todos los activos que el usuario puede ver (los de sus proyectos; el admin ve todos)."""
    ids = _ids_de_proyectos_visibles(db, usuario)
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
    datos: ActivoCreate,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    _get_proyecto_or_404(db, proyecto_id, usuario)
    activo = Activo(
        proyecto_id=proyecto_id,
        nombre=datos.nombre,
        url_objetivo=datos.url_objetivo,
        descripcion=datos.descripcion,
    )
    db.add(activo)
    db.commit()
    db.refresh(activo)
    return activo


@router.get("/proyectos/{proyecto_id}/activos", response_model=List[ActivoOut])
def listar_activos(
    proyecto_id: str,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    _get_proyecto_or_404(db, proyecto_id, usuario)
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
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """
    Crea la evaluación (PENDIENTE) y lanza el escaneo en segundo plano.
    La respuesta es inmediata; el cliente consulta el estado hasta que sea COMPLETADA o FALLIDA.
    """
    _get_activo_or_404(db, activo_id, usuario)

    # Una sola evaluación a la vez por activo. Las que quedaron "colgadas" (más antiguas que
    # el tiempo máximo de escaneo) no cuentan, para que un fallo no bloquee el activo para siempre.
    timeout = config_service.obtener(db)["motores"]["nmap"]["timeout_s"]
    limite = ahora_utc() - timedelta(seconds=timeout + 120)
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
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    _get_activo_or_404(db, activo_id, usuario)
    return (
        db.query(Evaluacion)
        .filter(Evaluacion.activo_id == activo_id)
        .options(selectinload(Evaluacion.hallazgos))
        .order_by(Evaluacion.iniciada_en.desc())
        .all()
    )


@router.get("/evaluaciones", response_model=List[EvaluacionOut])
def listar_todas_las_evaluaciones(
    response: Response,
    ultimas: Optional[int] = Query(default=None, ge=1, le=200, description="Solo las N evaluaciones más recientes de cada activo"),
    pagina: Optional[int] = Query(default=None, ge=1, description="Número de página (desde 1). Sin este parámetro se devuelve todo."),
    por_pagina: int = Query(default=50, ge=1, le=200, description="Evaluaciones por página; solo se usa junto con `pagina`"),
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """
    Evaluaciones visibles para el usuario, de la más reciente a la más antigua.
    Con `ultimas=N` se limita a las N más recientes de cada activo: así la respuesta no crece
    sin límite a medida que se acumula historial (el detalle de una evaluación antigua sigue
    disponible en GET /evaluaciones/{id}).

    Con `pagina` (y opcionalmente `por_pagina`) la respuesta se entrega por páginas y el total
    de evaluaciones que cumplen el filtro viaja en la cabecera `X-Total-Count`.
    """
    ids = _ids_de_proyectos_visibles(db, usuario)
    if not ids:
        if pagina is not None:
            response.headers["X-Total-Count"] = "0"
        return []
    consulta = (
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
        consulta = consulta.filter(Evaluacion.id.in_(db.query(ranking.c.id).filter(ranking.c.rn <= ultimas)))
    consulta = consulta.order_by(Evaluacion.iniciada_en.desc(), Evaluacion.id)  # el id desempata para que las páginas sean estables
    if pagina is not None:
        response.headers["X-Total-Count"] = str(consulta.order_by(None).count())
        consulta = consulta.offset((pagina - 1) * por_pagina).limit(por_pagina)
    return consulta.options(selectinload(Evaluacion.hallazgos)).all()  # una consulta para todos los hallazgos (evita N+1)


@router.get("/evaluaciones/{evaluacion_id}", response_model=EvaluacionOut)
def obtener_evaluacion(
    evaluacion_id: str,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    evaluacion = _get_evaluacion_or_404(db, evaluacion_id, usuario)
    return evaluacion


@router.post("/evaluaciones/{evaluacion_id}/cancelar", response_model=EvaluacionOut)
def cancelar_evaluacion(
    evaluacion_id: str,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """
    Cancela una evaluación pendiente o en curso. Queda registrada como fallida con la etapa
    "Cancelada"; el proceso de fondo detiene Nmap/ZAP y descarta los resultados parciales.
    """
    evaluacion = _get_evaluacion_or_404(db, evaluacion_id, usuario)
    if evaluacion.estado not in (EstadoEvaluacion.PENDIENTE, EstadoEvaluacion.EN_PROGRESO):
        raise HTTPException(status_code=409, detail="La evaluación ya terminó; no hay nada que cancelar.")
    evaluacion.estado = EstadoEvaluacion.FALLIDA
    evaluacion.etapa = ETAPA_CANCELADA
    evaluacion.detalle_error = "Cancelada por el usuario."
    evaluacion.finalizada_en = ahora_utc()
    db.commit()
    db.refresh(evaluacion)
    return evaluacion


@router.delete("/evaluaciones/{evaluacion_id}", status_code=status.HTTP_204_NO_CONTENT)
def eliminar_evaluacion(
    evaluacion_id: str,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """Elimina una evaluación y sus hallazgos. Si está en curso hay que cancelarla primero."""
    evaluacion = _get_evaluacion_or_404(db, evaluacion_id, usuario)
    if evaluacion.estado in (EstadoEvaluacion.PENDIENTE, EstadoEvaluacion.EN_PROGRESO):
        raise HTTPException(status_code=409, detail="La evaluación está en curso: cancélala antes de eliminarla.")
    db.delete(evaluacion)  # los hallazgos se eliminan en cascada
    db.commit()


# ---------------- Hallazgos ----------------
@router.patch("/hallazgos/{hallazgo_id}", response_model=HallazgoOut)
def actualizar_hallazgo(
    hallazgo_id: str,
    datos: HallazgoUpdate,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """Marca un hallazgo como corregido ("si") o lo reabre ("no")."""
    hallazgo = db.query(Hallazgo).filter(Hallazgo.id == hallazgo_id).first()
    if not hallazgo:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    evaluacion = db.query(Evaluacion).filter(Evaluacion.id == hallazgo.evaluacion_id).first()
    _get_activo_or_404(db, evaluacion.activo_id, usuario)  # misma verificación de propiedad
    hallazgo.corregido = datos.corregido
    db.commit()
    db.refresh(hallazgo)
    return hallazgo
