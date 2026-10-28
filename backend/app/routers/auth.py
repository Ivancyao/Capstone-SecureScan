from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RolUsuario, Usuario
from app.schemas import PasswordCambio, PerfilUpdate, Token, UsuarioCreate, UsuarioOut
from app.security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["Autenticación"])


@router.post("/register", response_model=UsuarioOut, status_code=status.HTTP_201_CREATED)
def register(data: UsuarioCreate, db: Session = Depends(get_db)):
    if db.query(Usuario).filter(Usuario.email == data.email).first():
        raise HTTPException(status_code=400, detail="El email ya está registrado")

    # El primer usuario registrado se convierte en ADMIN; el resto parte como USUARIO.
    es_primero = db.query(Usuario).count() == 0
    user = Usuario(
        nombre=data.nombre,
        email=data.email,
        password_hash=hash_password(data.password),
        rol=RolUsuario.ADMIN if es_primero else RolUsuario.USUARIO,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # OAuth2PasswordRequestForm usa el campo "username"; aquí corresponde al email.
    user = db.query(Usuario).filter(Usuario.email == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email o contraseña incorrectos")
    if not user.activo:
        raise HTTPException(status_code=403, detail="Esta cuenta está desactivada. Contacta a un administrador.")
    token = create_access_token(subject=user.id, rol=user.rol.value)
    return Token(access_token=token)


@router.get("/me", response_model=UsuarioOut)
def me(user: Usuario = Depends(get_current_user)):
    return user


@router.patch("/me", response_model=UsuarioOut)
def actualizar_perfil(
    data: PerfilUpdate, db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)
):
    user.nombre = data.nombre.strip()
    db.commit()
    db.refresh(user)
    return user


@router.post("/password")
def cambiar_password(
    data: PasswordCambio, db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)
):
    if not verify_password(data.actual, user.password_hash):
        raise HTTPException(status_code=400, detail="La contraseña actual no coincide")
    user.password_hash = hash_password(data.nueva)
    db.commit()
    return {"detail": "Contraseña actualizada"}
