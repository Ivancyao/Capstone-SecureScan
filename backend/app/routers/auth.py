from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app import limitador
from app.database import get_db
from app.models import RolUsuario, Usuario
from app.schemas import PasswordCambio, PerfilUpdate, Token, UsuarioCreate, UsuarioOut
from app.security import (
    HASH_FALSO,
    crear_token_de_acceso,
    hashear_contrasena,
    obtener_usuario_actual,
    verificar_contrasena,
)

router = APIRouter(prefix="/auth", tags=["Autenticación"])


# Registro abierto: cualquiera puede crear una cuenta. La primera que se crea queda como ADMIN
# (así no necesito un usuario cargado a mano al instalar). Las demás parten como USUARIO.
@router.post("/register", response_model=UsuarioOut, status_code=status.HTTP_201_CREATED)
def register(datos: UsuarioCreate, db: Session = Depends(get_db)):
    # Primero reviso que el correo no exista; la columna es única, pero así devuelvo un mensaje claro en vez de un error de BD.
    if db.query(Usuario).filter(Usuario.email == datos.email).first():
        raise HTTPException(status_code=400, detail="El email ya está registrado")

    # El primer usuario registrado se convierte en ADMIN; el resto parte como USUARIO.
    es_primero = db.query(Usuario).count() == 0
    usuario = Usuario(
        nombre=datos.nombre,
        email=datos.email,
        password_hash=hashear_contrasena(datos.password),
        rol=RolUsuario.ADMIN if es_primero else RolUsuario.USUARIO,
    )
    db.add(usuario)
    db.commit()
    db.refresh(usuario)
    return usuario


# Login con protección contra fuerza bruta: después de 5 intentos fallidos se bloquea por 5 minutos (ver limitador.py).
@router.post("/login", response_model=Token)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # OAuth2PasswordRequestForm usa el campo "username"; aquí corresponde al email.
    origen = request.client.host if request.client else "desconocido"
    # Se limita por correo + IP de origen, así un atacante no puede bloquear a un usuario desde cualquier parte sin más.
    espera = limitador.segundos_de_espera(form.username, origen)
    if espera:
        raise HTTPException(
            status_code=429,
            detail=f"Demasiados intentos fallidos. Espera {espera} segundos antes de volver a intentarlo.",
            headers={"Retry-After": str(espera)},
        )
    usuario = db.query(Usuario).filter(Usuario.email == form.username).first()
    # Si el correo no existe se compara igual contra un hash falso, para tardar lo mismo en ambos casos.
    hash_a_comparar = usuario.password_hash if usuario else HASH_FALSO
    contrasena_correcta = verificar_contrasena(form.password, hash_a_comparar)
    if not usuario or not contrasena_correcta:
        limitador.registrar_fallo(form.username, origen)
        raise HTTPException(status_code=401, detail="Email o contraseña incorrectos")
    # Si la contraseña es correcta borro los fallos anteriores.
    limitador.limpiar(form.username, origen)
    # La cuenta desactivada se avisa recién después de validar la contraseña, para no revelar a un extraño que el correo existe.
    if not usuario.activo:
        raise HTTPException(status_code=403, detail="Esta cuenta está desactivada. Contacta a un administrador.")
    token = crear_token_de_acceso(usuario_id=usuario.id, rol=usuario.rol.value)
    return Token(access_token=token)


@router.get("/me", response_model=UsuarioOut)
def me(usuario: Usuario = Depends(obtener_usuario_actual)):
    return usuario


# Acá el usuario solo puede cambiar su nombre. El rol y el correo no se tocan desde acá (el rol solo lo cambia un admin).
@router.patch("/me", response_model=UsuarioOut)
def actualizar_perfil(
    datos: PerfilUpdate, db: Session = Depends(get_db), usuario: Usuario = Depends(obtener_usuario_actual)
):
    usuario.nombre = datos.nombre.strip()
    db.commit()
    db.refresh(usuario)
    return usuario


# Para cambiar la contraseña pido la actual: así, si alguien deja la sesión abierta, no puede cambiarla sin saberla.
@router.post("/password")
def cambiar_password(
    datos: PasswordCambio, db: Session = Depends(get_db), usuario: Usuario = Depends(obtener_usuario_actual)
):
    if not verificar_contrasena(datos.actual, usuario.password_hash):
        raise HTTPException(status_code=400, detail="La contraseña actual no coincide")
    usuario.password_hash = hashear_contrasena(datos.nueva)
    db.commit()
    return {"detail": "Contraseña actualizada"}
