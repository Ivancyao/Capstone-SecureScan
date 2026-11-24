"""Configuración de motores y alcance. Leer: cualquier usuario autenticado. Cambiar: solo ADMIN."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import config_service, zap_client
from app.database import get_db
from app.models import RolUsuario, Usuario
from app.schemas import ConfiguracionIn
from app.security import obtener_usuario_actual, exigir_roles

router = APIRouter(prefix="/configuracion", tags=["Configuración"])


@router.get("")
def obtener_configuracion(db: Session = Depends(get_db), _: Usuario = Depends(obtener_usuario_actual)):
    return config_service.obtener(db)


@router.put("")
def guardar_configuracion(
    datos: ConfiguracionIn,
    db: Session = Depends(get_db),
    _: Usuario = Depends(exigir_roles(RolUsuario.ADMIN)),
):
    if datos.motores.nikto.activo:
        raise HTTPException(status_code=400, detail="Nikto no está integrado (queda como extensión futura)")
    if datos.motores.zap.activo and not zap_client.disponible():
        raise HTTPException(
            status_code=400,
            detail="OWASP ZAP no está configurado en el servidor (falta ZAP_URL). Levanta el servicio zap del docker-compose.",
        )
    if datos.alcance.permitir_publicas and not config_service.servidor_permite_publicas():
        raise HTTPException(
            status_code=400,
            detail="El servidor bloquea las direcciones públicas (ALLOW_PUBLIC_SCANS=false). "
            "Debe habilitarlo quien administra el servidor.",
        )
    return config_service.guardar(db, datos.model_dump())
