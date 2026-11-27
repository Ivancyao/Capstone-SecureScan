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

# Estas son las claves de ejemplo que dejé en el .env.example. Si alguien las deja tal cual,
# las trato como si no hubiera clave, porque son públicas (están en el repositorio).
_CLAVES_DE_EJEMPLO = {"", "cambia-esta-clave-en-produccion", "genera-una-clave-larga-y-aleatoria"}
SECRET_KEY = os.getenv("SECRET_KEY", "")
if SECRET_KEY in _CLAVES_DE_EJEMPLO:
    # Sin una clave propia se genera una aleatoria: es segura, pero las sesiones se cierran al reiniciar.
    SECRET_KEY = secrets.token_urlsafe(48)
    logging.getLogger("uvicorn.error").warning(
        "SECRET_KEY no está definida en el .env: se usa una clave temporal y las sesiones se cerrarán al reiniciar."
    )
# HS256 = firma con una sola clave secreta (la del servidor). Para este proyecto alcanza y es lo más simple.
ALGORITMO_JWT = "HS256"
# El token dura 60 minutos por defecto; se puede cambiar con ACCESS_TOKEN_EXPIRE_MINUTES en el .env.
MINUTOS_DE_VIGENCIA_DEL_TOKEN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Esto le dice a FastAPI de dónde sacar el token (cabecera Authorization) y de paso deja funcionando el botón Authorize de /docs.
esquema_oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


# bcrypt agrega una sal aleatoria en cada hash, por eso dos usuarios con la misma contraseña tienen hashes distintos.
def hashear_contrasena(contrasena: str) -> str:
    return bcrypt.hashpw(contrasena.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verificar_contrasena(contrasena: str, hash_guardado: str) -> bool:
    return bcrypt.checkpw(contrasena.encode("utf-8"), hash_guardado.encode("utf-8"))


# Se compara contra este hash cuando el correo no existe, para que el login tarde lo mismo
# exista o no la cuenta (así no se puede averiguar qué correos están registrados midiendo el tiempo).
HASH_FALSO = hashear_contrasena("contrasena-que-nadie-usa")


# Guardo en el token el id del usuario (sub), el rol y cuándo vence. OJO: igual el rol se vuelve a leer desde la BD en cada petición,
# así que si un admin cambia el rol de alguien no hay que esperar a que venza el token.
def crear_token_de_acceso(usuario_id: str, rol: str) -> str:
    vence_en = datetime.now(timezone.utc) + timedelta(minutes=MINUTOS_DE_VIGENCIA_DEL_TOKEN)
    contenido = {"sub": usuario_id, "rol": rol, "exp": vence_en}
    return jwt.encode(contenido, SECRET_KEY, algorithm=ALGORITMO_JWT)


# Esta función es la "puerta" de casi todos los endpoints: valida el token y devuelve el usuario.
# Si me preguntan por qué siempre es 401 con el mismo mensaje: para no darle pistas a un atacante de qué falló exactamente.
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

    # Busco al usuario en la BD en vez de confiar solo en el token. Así, si lo desactivan, pierde el acceso al tiro.
    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if usuario is None or not usuario.activo:
        # Una cuenta desactivada pierde el acceso de inmediato, aunque su token siga vigente.
        raise error_de_credenciales
    return usuario


# Así protejo rutas por rol, por ejemplo Depends(exigir_roles(RolUsuario.ADMIN)). Devuelve 403 si el rol no corresponde.
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
