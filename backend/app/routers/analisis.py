"""
Análisis rápido de una URL o de un archivo ("¿es seguro / tiene malware?").

Cada usuario solo ve sus propios análisis. El archivo se lee en memoria, se calcula su huella SHA-256 y se
descarta: no se guarda en disco ni en la base de datos. Se sube a VirusTotal solo si el usuario lo pide.
"""
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Response, UploadFile, status
from sqlalchemy.orm import Session

from app import analisis_service as svc
from app.database import get_db
from app.models import Analisis, Usuario
from app.schemas import AnalisisEstado, AnalisisOut, AnalisisUrlIn
from app.security import get_current_user

router = APIRouter(prefix="/analisis", tags=["Análisis de URL y archivos"])


def _propio_o_404(db: Session, analisis_id: str, user: Usuario) -> Analisis:
    a = db.get(Analisis, analisis_id)
    if a is None or a.usuario_id != user.id:
        raise HTTPException(status_code=404, detail="Análisis no encontrado")
    return a


@router.get("/estado", response_model=AnalisisEstado)
def estado(_: Usuario = Depends(get_current_user)):
    return AnalisisEstado(virustotal=svc.virustotal_configurado(), max_mb=svc.MAX_ARCHIVO_BYTES // (1024 * 1024))


@router.post("/url", response_model=AnalisisOut, status_code=status.HTTP_202_ACCEPTED)
def analizar_url(datos: AnalisisUrlIn, tareas: BackgroundTasks, db: Session = Depends(get_db),
                 user: Usuario = Depends(get_current_user)):
    a = Analisis(usuario_id=user.id, tipo="url", objetivo=datos.url, estado="pendiente")
    db.add(a)
    db.commit()
    db.refresh(a)
    tareas.add_task(svc.ejecutar_analisis, a.id)
    return a


@router.post("/archivo", response_model=AnalisisOut, status_code=status.HTTP_202_ACCEPTED)
async def analizar_archivo(tareas: BackgroundTasks, archivo: UploadFile = File(...), subir: bool = Form(False),
                           db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    contenido = await archivo.read(svc.MAX_ARCHIVO_BYTES + 1)
    if len(contenido) > svc.MAX_ARCHIVO_BYTES:
        raise HTTPException(status_code=413, detail=f"El archivo supera el máximo de {svc.MAX_ARCHIVO_BYTES // (1024 * 1024)} MB.")
    if not contenido:
        raise HTTPException(status_code=422, detail="El archivo está vacío.")
    nombre = (archivo.filename or "archivo")[:255]
    a = Analisis(usuario_id=user.id, tipo="archivo", objetivo=nombre, sha256=svc.sha256_de(contenido),
                 tamano_bytes=len(contenido), estado="pendiente")
    db.add(a)
    db.commit()
    db.refresh(a)
    tareas.add_task(svc.ejecutar_analisis, a.id, contenido, subir)
    return a


@router.get("", response_model=List[AnalisisOut])
def listar(db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    return (db.query(Analisis).filter(Analisis.usuario_id == user.id)
            .order_by(Analisis.creado_en.desc(), Analisis.id).limit(100).all())


@router.get("/{analisis_id}", response_model=AnalisisOut)
def obtener(analisis_id: str, db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    return _propio_o_404(db, analisis_id, user)


@router.delete("/{analisis_id}", status_code=status.HTTP_204_NO_CONTENT)
def eliminar(analisis_id: str, db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    db.delete(_propio_o_404(db, analisis_id, user))
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
