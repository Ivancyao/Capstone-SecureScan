"""
Reportes PDF. Se generan al pedirlos y se guardan en disco (REPORTS_DIR), para que el
informe sea una "foto" del momento aunque luego cambien los hallazgos.
Control de acceso: mismas reglas que los proyectos (dueño o admin).
"""
import os
import re
import unicodedata
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Activo, EstadoEvaluacion, Evaluacion, Proyecto, Reporte, RolUsuario, Usuario
from app.reportes_pdf import generar_pdf
from app.routers.proyectos import _get_proyecto_or_404
from app.schemas import ReporteCreate, ReporteOut
from app.security import get_current_user

router = APIRouter(tags=["Reportes"])


def _directorio() -> Path:
    d = Path(os.getenv("REPORTS_DIR", "./reportes_generados"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _slug(texto: str) -> str:
    t = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-") or "informe"


def _reporte_o_404(db: Session, reporte_id: str, user: Usuario) -> Reporte:
    r = db.query(Reporte).filter(Reporte.id == reporte_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    _get_proyecto_or_404(db, r.proyecto_id, user)
    return r


@router.get("/reportes", response_model=List[ReporteOut])
def listar_reportes(db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    q = db.query(Reporte)
    if user.rol != RolUsuario.ADMIN:
        ids = [p.id for p in db.query(Proyecto).filter(Proyecto.propietario_id == user.id).all()]
        q = q.filter(Reporte.proyecto_id.in_(ids)) if ids else q.filter(False)
    return q.order_by(Reporte.generado_en.desc()).all()


@router.post("/proyectos/{proyecto_id}/reportes", response_model=ReporteOut, status_code=status.HTTP_201_CREATED)
def crear_reporte(
    proyecto_id: str,
    data: ReporteCreate,
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    proyecto = _get_proyecto_or_404(db, proyecto_id, user)
    ids = list(dict.fromkeys(data.evaluacion_ids))  # sin repetidos, conservando el orden
    evaluaciones = (
        db.query(Evaluacion)
        .join(Activo, Activo.id == Evaluacion.activo_id)
        .filter(Evaluacion.id.in_(ids), Activo.proyecto_id == proyecto_id)
        .all()
    )
    if len(evaluaciones) != len(ids):
        raise HTTPException(status_code=400, detail="Alguna evaluación no existe o no pertenece a este proyecto")
    if any(e.estado != EstadoEvaluacion.COMPLETADA for e in evaluaciones):
        raise HTTPException(status_code=400, detail="Solo se pueden incluir evaluaciones completadas")

    titulo = (data.titulo or "").strip() or f"Informe de seguridad — {proyecto.nombre}"
    contenido = generar_pdf(
        {"nombre": proyecto.nombre},
        titulo,
        user.nombre,
        [
            {
                "activo": {"nombre": e.activo.nombre, "url_objetivo": e.activo.url_objetivo},
                "iniciada_en": e.iniciada_en,
                "hallazgos": [
                    {
                        "nombre_vulnerabilidad": h.nombre_vulnerabilidad,
                        "severidad": h.severidad.value,
                        "cvss_score": h.cvss_score,
                        "categoria_owasp": h.categoria_owasp,
                        "evidencia": h.evidencia,
                        "recomendacion": h.recomendacion,
                        "corregido": h.corregido,
                    }
                    for h in e.hallazgos
                ],
            }
            for e in sorted(evaluaciones, key=lambda e: e.iniciada_en)
        ],
    )

    reporte = Reporte(
        proyecto_id=proyecto_id,
        titulo=titulo,
        nombre_archivo=f"informe-{_slug(proyecto.nombre)}.pdf",
        generado_por=user.nombre,
        evaluacion_ids=ids,
        tamano_kb=max(1, round(len(contenido) / 1024)),
    )
    db.add(reporte)
    db.commit()
    db.refresh(reporte)
    (_directorio() / f"{reporte.id}.pdf").write_bytes(contenido)
    return reporte


@router.get("/reportes/{reporte_id}/descargar")
def descargar_reporte(reporte_id: str, db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    r = _reporte_o_404(db, reporte_id, user)
    ruta = _directorio() / f"{r.id}.pdf"
    if not ruta.is_file():
        raise HTTPException(status_code=404, detail="El archivo del reporte ya no está disponible")
    return FileResponse(ruta, media_type="application/pdf", filename=r.nombre_archivo)


@router.delete("/reportes/{reporte_id}", status_code=status.HTTP_204_NO_CONTENT)
def eliminar_reporte(reporte_id: str, db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    r = _reporte_o_404(db, reporte_id, user)
    ruta = _directorio() / f"{r.id}.pdf"
    db.delete(r)
    db.commit()
    ruta.unlink(missing_ok=True)
