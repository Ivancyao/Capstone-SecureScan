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
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(subject: str, rol: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "rol": rol, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> Usuario:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas o token expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_error
    except jwt.PyJWTError:
        raise credentials_error from None

    user = db.query(Usuario).filter(Usuario.id == user_id).first()
    if user is None or not user.activo:
        # Una cuenta desactivada pierde el acceso de inmediato, aunque su token siga vigente.
        raise credentials_error
    return user


def require_roles(*roles: RolUsuario):
    """Fábrica de dependencias RBAC: permite el acceso solo a los roles indicados."""

    def checker(user: Usuario = Depends(get_current_user)) -> Usuario:
        if user.rol not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos para realizar esta acción",
            )
        return user

    return checker
