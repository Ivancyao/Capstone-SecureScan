"""Configuración de motores y alcance. Leer: cualquier usuario autenticado. Cambiar: solo ADMIN."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import config_service, zap_client
from app.database import get_db
from app.models import RolUsuario, Usuario
from app.schemas import ConfiguracionIn
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/configuracion", tags=["Configuración"])


@router.get("")
def obtener_configuracion(db: Session = Depends(get_db), _: Usuario = Depends(get_current_user)):
    return config_service.obtener(db)


@router.put("")
def guardar_configuracion(
    data: ConfiguracionIn,
    db: Session = Depends(get_db),
    _: Usuario = Depends(require_roles(RolUsuario.ADMIN)),
):
    if data.motores.nikto.activo:
        raise HTTPException(status_code=400, detail="Nikto no está integrado (queda como extensión futura)")
    if data.motores.zap.activo and not zap_client.disponible():
        raise HTTPException(
            status_code=400,
            detail="OWASP ZAP no está configurado en el servidor (falta ZAP_URL). Levanta el servicio zap del docker-compose.",
        )
    if data.alcance.permitir_publicas and not config_service.servidor_permite_publicas():
        raise HTTPException(
            status_code=400,
            detail="El servidor bloquea las direcciones públicas (ALLOW_PUBLIC_SCANS=false). "
            "Debe habilitarlo quien administra el servidor.",
        )
    return config_service.guardar(db, data.model_dump())
