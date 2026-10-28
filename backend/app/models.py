"""
Modelo de datos de SecureScan.

Jerarquía (según el ER definido en el Documento 1.5 - Definición de Proyecto):

Usuario --- Rol
Proyecto --- Activo --- Evaluacion --- Hallazgo --- Vulnerabilidad/Severidad/Recomendacion
Proyecto --- Reporte
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Enum, Float, ForeignKey, Integer, String, Text, Uuid
)
from sqlalchemy.orm import relationship

from app.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class RolUsuario(str, enum.Enum):
    """RBAC: qué puede hacer cada usuario dentro de la plataforma."""
    ADMIN = "admin"
    ANALISTA = "analista"
    USUARIO = "usuario"


class EstadoEvaluacion(str, enum.Enum):
    PENDIENTE = "pendiente"
    EN_PROGRESO = "en_progreso"
    COMPLETADA = "completada"
    FALLIDA = "fallida"


class SeveridadHallazgo(str, enum.Enum):
    """Niveles de severidad derivados del puntaje CVSS."""
    CRITICA = "critica"
    ALTA = "alta"
    MEDIA = "media"
    BAJA = "baja"
    INFORMATIVA = "informativa"


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    nombre = Column(String(120), nullable=False)
    email = Column(String(160), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    rol = Column(Enum(RolUsuario), nullable=False, default=RolUsuario.USUARIO)
    activo = Column(Boolean, nullable=False, default=True)  # una cuenta desactivada no puede iniciar sesión
    creado_en = Column(DateTime, default=datetime.utcnow)

    proyectos = relationship("Proyecto", back_populates="propietario")


class Proyecto(Base):
    """Agrupa los activos (aplicaciones) de una organización/contexto."""
    __tablename__ = "proyectos"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    nombre = Column(String(150), nullable=False)
    descripcion = Column(Text, nullable=True)
    propietario_id = Column(Uuid(as_uuid=False), ForeignKey("usuarios.id"), nullable=False)
    creado_en = Column(DateTime, default=datetime.utcnow)

    propietario = relationship("Usuario", back_populates="proyectos")
    activos = relationship("Activo", back_populates="proyecto", cascade="all, delete-orphan")
    reportes = relationship("Reporte", back_populates="proyecto", cascade="all, delete-orphan")


class Activo(Base):
    """Una aplicación/sistema registrado para ser evaluado."""
    __tablename__ = "activos"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    proyecto_id = Column(Uuid(as_uuid=False), ForeignKey("proyectos.id"), nullable=False)
    nombre = Column(String(150), nullable=False)
    url_objetivo = Column(String(255), nullable=False)
    descripcion = Column(Text, nullable=True)
    creado_en = Column(DateTime, default=datetime.utcnow)

    proyecto = relationship("Proyecto", back_populates="activos")
    evaluaciones = relationship("Evaluacion", back_populates="activo", cascade="all, delete-orphan")


class Evaluacion(Base):
    """Una ejecución de escaneo de seguridad sobre un activo."""
    __tablename__ = "evaluaciones"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    activo_id = Column(Uuid(as_uuid=False), ForeignKey("activos.id"), nullable=False)
    estado = Column(Enum(EstadoEvaluacion), default=EstadoEvaluacion.PENDIENTE)
    iniciada_en = Column(DateTime, default=datetime.utcnow)
    finalizada_en = Column(DateTime, nullable=True)
    detalle_error = Column(Text, nullable=True)  # motivo si la evaluación falló
    progreso = Column(Integer, nullable=True)    # 0-100 mientras corre; permite mostrar avance en vivo
    etapa = Column(String(80), nullable=True)    # "Validando el objetivo", "Escaneando puertos"...

    activo = relationship("Activo", back_populates="evaluaciones")
    hallazgos = relationship("Hallazgo", back_populates="evaluacion", cascade="all, delete-orphan")


class Hallazgo(Base):
    """Una vulnerabilidad concreta detectada en una evaluación."""
    __tablename__ = "hallazgos"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    evaluacion_id = Column(Uuid(as_uuid=False), ForeignKey("evaluaciones.id"), nullable=False)

    nombre_vulnerabilidad = Column(String(200), nullable=False)
    categoria_owasp = Column(String(120), nullable=True)   # ej. "A05:2021 - Security Misconfiguration"
    cvss_score = Column(Float, nullable=True)               # 0.0 - 10.0
    severidad = Column(Enum(SeveridadHallazgo), nullable=False, default=SeveridadHallazgo.INFORMATIVA)
    evidencia = Column(Text, nullable=True)                 # ej. "Puerto 80/TCP abierto"
    recomendacion = Column(Text, nullable=True)
    herramienta_origen = Column(String(60), nullable=True)  # "nmap" | "owasp_zap"
    corregido = Column(String(10), default="no")            # simple flag "si"/"no" para seguimiento

    evaluacion = relationship("Evaluacion", back_populates="hallazgos")


class Reporte(Base):
    """Reporte PDF generado a partir de una o más evaluaciones de un proyecto."""
    __tablename__ = "reportes"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    proyecto_id = Column(Uuid(as_uuid=False), ForeignKey("proyectos.id"), nullable=False)
    titulo = Column(String(200), nullable=True)
    nombre_archivo = Column(String(255), nullable=False)    # nombre amigable al descargar
    generado_en = Column(DateTime, default=datetime.utcnow)
    generado_por = Column(String(120), nullable=True)
    evaluacion_ids = Column(JSON, nullable=True)             # evaluaciones incluidas en el informe
    tamano_kb = Column(Integer, nullable=True)

    proyecto = relationship("Proyecto", back_populates="reportes")


class Configuracion(Base):
    """Ajustes de la plataforma (clave -> JSON). Hoy hay una sola clave: "escaneo"."""
    __tablename__ = "configuracion"

    clave = Column(String(60), primary_key=True)
    valor = Column(JSON, nullable=False)
    actualizado_en = Column(DateTime, default=datetime.utcnow)
