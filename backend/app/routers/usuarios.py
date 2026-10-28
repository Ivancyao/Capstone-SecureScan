"""
Gestión de usuarios y roles. Solo el ADMIN puede usarla (RBAC, OWASP A01).
"""
import secrets
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RolUsuario, Usuario
from app.schemas import UsuarioAdminCreate, UsuarioCreado, UsuarioOut, UsuarioUpdate
from app.security import hash_password, require_roles

router = APIRouter(prefix="/usuarios", tags=["Usuarios (solo administrador)"])


@router.get("", response_model=List[UsuarioOut])
def listar_usuarios(
    db: Session = Depends(get_db), _: Usuario = Depends(require_roles(RolUsuario.ADMIN))
):
    return db.query(Usuario).order_by(Usuario.creado_en.asc()).all()


@router.post("", response_model=UsuarioCreado, status_code=status.HTTP_201_CREATED)
def crear_usuario(
    data: UsuarioAdminCreate,
    db: Session = Depends(get_db),
    _: Usuario = Depends(require_roles(RolUsuario.ADMIN)),
):
    if db.query(Usuario).filter(Usuario.email == data.email).first():
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    temporal = None
    password = data.password
    if not password:
        temporal = password = secrets.token_urlsafe(9)  # 12 caracteres, aleatoria
    user = Usuario(
        nombre=data.nombre.strip(),
        email=data.email,
        password_hash=hash_password(password),
        rol=data.rol,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    salida = UsuarioCreado.model_validate(user)
    salida.password_temporal = temporal
    return salida


@router.patch("/{usuario_id}", response_model=UsuarioOut)
def actualizar_usuario(
    usuario_id: str,
    data: UsuarioUpdate,
    db: Session = Depends(get_db),
    admin: Usuario = Depends(require_roles(RolUsuario.ADMIN)),
):
    objetivo = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not objetivo:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if objetivo.id == admin.id:
        # Evita que el último administrador se quite el rol o se desactive por error.
        raise HTTPException(status_code=400, detail="No puedes cambiar tu propio rol ni desactivar tu propia cuenta")
    if data.rol is not None:
        objetivo.rol = data.rol
    if data.activo is not None:
        objetivo.activo = data.activo
    db.commit()
    db.refresh(objetivo)
    return objetivo
