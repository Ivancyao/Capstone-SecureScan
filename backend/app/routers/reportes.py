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
from app.security import obtener_usuario_actual

router = APIRouter(tags=["Reportes"])


def _directorio() -> Path:
    carpeta = Path(os.getenv("REPORTS_DIR", "./reportes_generados"))
    carpeta.mkdir(parents=True, exist_ok=True)
    return carpeta


def _slug(texto: str) -> str:
    texto_ascii = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", texto_ascii.lower()).strip("-") or "informe"


def _reporte_o_404(db: Session, reporte_id: str, usuario: Usuario) -> Reporte:
    reporte = db.query(Reporte).filter(Reporte.id == reporte_id).first()
    if not reporte:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    _get_proyecto_or_404(db, reporte.proyecto_id, usuario)
    return reporte


@router.get("/reportes", response_model=List[ReporteOut])
def listar_reportes(db: Session = Depends(get_db), usuario: Usuario = Depends(obtener_usuario_actual)):
    consulta = db.query(Reporte)
    if usuario.rol != RolUsuario.ADMIN:
        ids = [proyecto.id for proyecto in db.query(Proyecto).filter(Proyecto.propietario_id == usuario.id).all()]
        consulta = consulta.filter(Reporte.proyecto_id.in_(ids)) if ids else consulta.filter(False)
    return consulta.order_by(Reporte.generado_en.desc()).all()


@router.post("/proyectos/{proyecto_id}/reportes", response_model=ReporteOut, status_code=status.HTTP_201_CREATED)
def crear_reporte(
    proyecto_id: str,
    datos: ReporteCreate,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    proyecto = _get_proyecto_or_404(db, proyecto_id, usuario)
    ids = list(dict.fromkeys(datos.evaluacion_ids))  # sin repetidos, conservando el orden
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

    titulo = (datos.titulo or "").strip() or f"Informe de seguridad — {proyecto.nombre}"
    contenido = generar_pdf(
        {"nombre": proyecto.nombre},
        titulo,
        usuario.nombre,
        [
            {
                "activo": {"nombre": evaluacion.activo.nombre, "url_objetivo": evaluacion.activo.url_objetivo},
                "iniciada_en": evaluacion.iniciada_en,
                "hallazgos": [
                    {
                        "nombre_vulnerabilidad": hallazgo.nombre_vulnerabilidad,
                        "severidad": hallazgo.severidad.value,
                        "cvss_score": hallazgo.cvss_score,
                        "categoria_owasp": hallazgo.categoria_owasp,
                        "evidencia": hallazgo.evidencia,
                        "recomendacion": hallazgo.recomendacion,
                        "corregido": hallazgo.corregido,
                    }
                    for hallazgo in evaluacion.hallazgos
                ],
            }
            for evaluacion in sorted(evaluaciones, key=lambda evaluacion: evaluacion.iniciada_en)
        ],
    )

    reporte = Reporte(
        proyecto_id=proyecto_id,
        titulo=titulo,
        nombre_archivo=f"informe-{_slug(proyecto.nombre)}.pdf",
        generado_por=usuario.nombre,
        evaluacion_ids=ids,
        tamano_kb=max(1, round(len(contenido) / 1024)),
    )
    db.add(reporte)
    db.commit()
    db.refresh(reporte)
    (_directorio() / f"{reporte.id}.pdf").write_bytes(contenido)
    return reporte


@router.get("/reportes/{reporte_id}/descargar")
def descargar_reporte(reporte_id: str, db: Session = Depends(get_db), usuario: Usuario = Depends(obtener_usuario_actual)):
    reporte = _reporte_o_404(db, reporte_id, usuario)
    ruta = _directorio() / f"{reporte.id}.pdf"
    if not ruta.is_file():
        raise HTTPException(status_code=404, detail="El archivo del reporte ya no está disponible")
    return FileResponse(ruta, media_type="application/pdf", filename=reporte.nombre_archivo)


@router.delete("/reportes/{reporte_id}", status_code=status.HTTP_204_NO_CONTENT)
def eliminar_reporte(reporte_id: str, db: Session = Depends(get_db), usuario: Usuario = Depends(obtener_usuario_actual)):
    reporte = _reporte_o_404(db, reporte_id, usuario)
    ruta = _directorio() / f"{reporte.id}.pdf"
    db.delete(reporte)
    db.commit()
    ruta.unlink(missing_ok=True)
