"""Seguridad de la API: contraseñas, JWT y roles.

- Las contraseñas se guardan con hash bcrypt, nunca en texto plano.
- Al iniciar sesión se entrega un JWT firmado, que el cliente manda en cada petición
  (cabecera Authorization: Bearer <token>).
- Algunas rutas exigen un rol específico, por ejemplo solo ADMIN.
"""
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RolUsuario, Usuario

_CLAVES_DE_EJEMPLO = {"", "cambia-esta-clave-en-produccion", "genera-una-clave-larga-y-aleatoria"}
SECRET_KEY = os.getenv("SECRET_KEY", "")
if SECRET_KEY in _CLAVES_DE_EJEMPLO:
    # Sin una clave propia se genera una aleatoria: es segura, pero las sesiones se cierran al reiniciar.
    SECRET_KEY = secrets.token_urlsafe(48)
    logging.getLogger("uvicorn.error").warning(
        "SECRET_KEY no está definida en el .env: se usa una clave temporal y las sesiones se cerrarán al reiniciar."
    )
ALGORITMO_JWT = "HS256"
MINUTOS_DE_VIGENCIA_DEL_TOKEN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

esquema_oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hashear_contrasena(contrasena: str) -> str:
    return bcrypt.hashpw(contrasena.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verificar_contrasena(contrasena: str, hash_guardado: str) -> bool:
    return bcrypt.checkpw(contrasena.encode("utf-8"), hash_guardado.encode("utf-8"))


# Se compara contra este hash cuando el correo no existe, para que el login tarde lo mismo
# exista o no la cuenta (así no se puede averiguar qué correos están registrados midiendo el tiempo).
HASH_FALSO = hashear_contrasena("contrasena-que-nadie-usa")


def crear_token_de_acceso(usuario_id: str, rol: str) -> str:
    vence_en = datetime.now(timezone.utc) + timedelta(minutes=MINUTOS_DE_VIGENCIA_DEL_TOKEN)
    contenido = {"sub": usuario_id, "rol": rol, "exp": vence_en}
    return jwt.encode(contenido, SECRET_KEY, algorithm=ALGORITMO_JWT)


def obtener_usuario_actual(
    token: str = Depends(esquema_oauth2), db: Session = Depends(get_db)
) -> Usuario:
    error_de_credenciales = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas o token expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        contenido = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITMO_JWT])
        usuario_id = contenido.get("sub")
        if usuario_id is None:
            raise error_de_credenciales
    except jwt.PyJWTError:
        raise error_de_credenciales from None

    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if usuario is None or not usuario.activo:
        # Una cuenta desactivada pierde el acceso de inmediato, aunque su token siga vigente.
        raise error_de_credenciales
    return usuario


def exigir_roles(*roles_permitidos: RolUsuario):
    """Fábrica de dependencias RBAC: permite el acceso solo a los roles indicados."""

    def verificar_rol(usuario: Usuario = Depends(obtener_usuario_actual)) -> Usuario:
        if usuario.rol not in roles_permitidos:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos para realizar esta acción",
            )
        return usuario

    return verificar_rol
