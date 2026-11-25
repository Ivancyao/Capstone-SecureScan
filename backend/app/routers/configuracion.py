"""Configuración de motores y alcance. Leer: cualquier usuario autenticado. Cambiar: solo ADMIN."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import config_service, zap_client
from app.database import get_db
from app.models import RolUsuario, Usuario
from app.schemas import ConfiguracionIn
from app.security import obtener_usuario_actual, exigir_roles

router = APIRouter(prefix="/configuracion", tags=["Configuración"])


# Cualquier usuario logueado puede ver la configuración (la web la necesita, por ejemplo, para saber si ZAP está disponible).
@router.get("")
def obtener_configuracion(db: Session = Depends(get_db), _: Usuario = Depends(obtener_usuario_actual)):
    return config_service.obtener(db)


# Cambiarla es solo para ADMIN. Antes de guardar hago tres validaciones para no dejar una configuración imposible:
@router.put("")
def guardar_configuracion(
    datos: ConfiguracionIn,
    db: Session = Depends(get_db),
    _: Usuario = Depends(exigir_roles(RolUsuario.ADMIN)),
):
    # Nikto no lo implementé; lo dejé como idea a futuro, así que no se puede activar.
    if datos.motores.nikto.activo:
        raise HTTPException(status_code=400, detail="Nikto no está integrado (queda como extensión futura)")
    # No dejo activar ZAP si el servidor no lo tiene configurado.
    if datos.motores.zap.activo and not zap_client.disponible():
        raise HTTPException(
            status_code=400,
            detail="OWASP ZAP no está configurado en el servidor (falta ZAP_URL). Levanta el servicio zap del docker-compose.",
        )
    # Segundo candado: aunque el admin lo marque en la web, si el servidor tiene ALLOW_PUBLIC_SCANS=false se rechaza.
    if datos.alcance.permitir_publicas and not config_service.servidor_permite_publicas():
        raise HTTPException(
            status_code=400,
            detail="El servidor bloquea las direcciones públicas (ALLOW_PUBLIC_SCANS=false). "
            "Debe habilitarlo quien administra el servidor.",
        )
    return config_service.guardar(db, datos.model_dump())
