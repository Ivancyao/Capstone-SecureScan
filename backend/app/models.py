"""
Modelo de datos de SecureScan.

Jerarquía (según el ER definido en el Documento 1.5 - Definición de Proyecto):

Usuario --- Rol
Proyecto --- Activo --- Evaluacion --- Hallazgo --- Vulnerabilidad/Severidad/Recomendacion
Proyecto --- Reporte
"""
import enum
import uuid

from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Enum, Float, ForeignKey, Integer, String, Text, Uuid
)
from sqlalchemy.orm import relationship

from app.database import Base
from app.tiempo import ahora_utc


# Uso UUID como id (en vez de 1, 2, 3...) para que nadie pueda adivinar ids de otros usuarios cambiando un número en la URL.
def gen_uuid():
    return str(uuid.uuid4())


# Los tres roles de la plataforma. Ojo: hoy el backend trata a "analista" igual que "usuario"; solo ADMIN tiene permisos extra.
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


# Tabla de usuarios. Nunca guardo la contraseña, solo su hash (password_hash).
class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    nombre = Column(String(120), nullable=False)
    email = Column(String(160), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    rol = Column(Enum(RolUsuario), nullable=False, default=RolUsuario.USUARIO)
    activo = Column(Boolean, nullable=False, default=True)  # una cuenta desactivada no puede iniciar sesión
    creado_en = Column(DateTime, default=ahora_utc)

    proyectos = relationship("Proyecto", back_populates="propietario")


# Un proyecto pertenece a un usuario (propietario). Es lo que usa el sistema para decidir quién ve qué.
class Proyecto(Base):
    """Agrupa los activos (aplicaciones) de una organización/contexto."""
    __tablename__ = "proyectos"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    nombre = Column(String(150), nullable=False)
    descripcion = Column(Text, nullable=True)
    propietario_id = Column(Uuid(as_uuid=False), ForeignKey("usuarios.id"), nullable=False)
    creado_en = Column(DateTime, default=ahora_utc)

    propietario = relationship("Usuario", back_populates="proyectos")
    activos = relationship("Activo", back_populates="proyecto", cascade="all, delete-orphan")
    reportes = relationship("Reporte", back_populates="proyecto", cascade="all, delete-orphan")


# Los activos cuelgan de un proyecto. Si borro el proyecto, se borran sus activos, evaluaciones y hallazgos (cascade).
class Activo(Base):
    """Una aplicación/sistema registrado para ser evaluado."""
    __tablename__ = "activos"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    proyecto_id = Column(Uuid(as_uuid=False), ForeignKey("proyectos.id"), nullable=False)
    nombre = Column(String(150), nullable=False)
    url_objetivo = Column(String(255), nullable=False)
    descripcion = Column(Text, nullable=True)
    creado_en = Column(DateTime, default=ahora_utc)

    proyecto = relationship("Proyecto", back_populates="activos")
    evaluaciones = relationship("Evaluacion", back_populates="activo", cascade="all, delete-orphan")


# Cada vez que se escanea un activo se crea una evaluación. Guarda el estado y el avance para mostrarlo en vivo en la pantalla.
class Evaluacion(Base):
    """Una ejecución de escaneo de seguridad sobre un activo."""
    __tablename__ = "evaluaciones"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    activo_id = Column(Uuid(as_uuid=False), ForeignKey("activos.id"), nullable=False)
    estado = Column(Enum(EstadoEvaluacion), default=EstadoEvaluacion.PENDIENTE)
    iniciada_en = Column(DateTime, default=ahora_utc)
    finalizada_en = Column(DateTime, nullable=True)
    detalle_error = Column(Text, nullable=True)  # motivo si la evaluación falló
    progreso = Column(Integer, nullable=True)    # 0-100 mientras corre; permite mostrar avance en vivo
    etapa = Column(String(80), nullable=True)    # "Validando el objetivo", "Escaneando puertos"...

    activo = relationship("Activo", back_populates="evaluaciones")
    hallazgos = relationship("Hallazgo", back_populates="evaluacion", cascade="all, delete-orphan")


# Un hallazgo es un problema concreto encontrado (puerto abierto, cabecera faltante, etc.), con su severidad y recomendación.
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


# En la BD solo guardo los datos del reporte (nombre, fecha, evaluaciones incluidas). El PDF en sí queda como archivo en disco (carpeta REPORTS_DIR).
class Reporte(Base):
    """Reporte PDF generado a partir de una o más evaluaciones de un proyecto."""
    __tablename__ = "reportes"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    proyecto_id = Column(Uuid(as_uuid=False), ForeignKey("proyectos.id"), nullable=False)
    titulo = Column(String(200), nullable=True)
    nombre_archivo = Column(String(255), nullable=False)    # nombre amigable al descargar
    generado_en = Column(DateTime, default=ahora_utc)
    generado_por = Column(String(120), nullable=True)
    evaluacion_ids = Column(JSON, nullable=True)             # evaluaciones incluidas en el informe
    tamano_kb = Column(Integer, nullable=True)

    proyecto = relationship("Proyecto", back_populates="reportes")


# Guarda los ajustes como pares clave-valor en JSON, para poder agregar opciones sin cambiar la tabla.
class Configuracion(Base):
    """Ajustes de la plataforma (clave -> JSON). Hoy hay una sola clave: "escaneo"."""
    __tablename__ = "configuracion"

    clave = Column(String(60), primary_key=True)
    valor = Column(JSON, nullable=False)
    actualizado_en = Column(DateTime, default=ahora_utc)


# Es el módulo de análisis rápido: revisa una URL o un archivo con VirusTotal. Del archivo no guardo el contenido, solo su huella SHA-256.
class Analisis(Base):
    """
    Análisis rápido de una URL o de un archivo: reputación en VirusTotal + señales locales.
    No guarda el contenido del archivo, solo su huella SHA-256 y el resultado.
    """
    __tablename__ = "analisis"

    id = Column(Uuid(as_uuid=False), primary_key=True, default=gen_uuid)
    usuario_id = Column(Uuid(as_uuid=False), ForeignKey("usuarios.id"), nullable=False)
    tipo = Column(String(10), nullable=False)               # "url" | "archivo"
    objetivo = Column(String(2048), nullable=False)          # la URL o el nombre del archivo
    sha256 = Column(String(64), nullable=True)               # huella del archivo
    tamano_bytes = Column(Integer, nullable=True)
    estado = Column(String(12), default="pendiente")         # pendiente | completado | error
    veredicto = Column(String(12), nullable=True)            # limpio | sospechoso | malicioso | sin_datos
    resumen = Column(Text, nullable=True)                    # frase para mostrar al usuario
    detalle = Column(JSON, nullable=True)                    # virustotal, señales, cabeceras
    creado_en = Column(DateTime, default=ahora_utc)
    finalizado_en = Column(DateTime, nullable=True)
