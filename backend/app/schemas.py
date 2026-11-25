"""
Esquemas Pydantic: definen y validan qué datos entran y salen de la API.
Validar la entrada es parte de la seguridad (evita datos malformados).
"""
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models import EstadoEvaluacion, RolUsuario, SeveridadHallazgo


# ---------- Auth / Usuarios ----------
# Lo que se exige al registrarse: nombre de 2 a 120 caracteres, correo válido (EmailStr) y contraseña de mínimo 8.
# Pydantic rechaza solo lo que no cumple, con un 422, antes de llegar a mi código.
class UsuarioCreate(BaseModel):
    nombre: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


# Lo que la API devuelve de un usuario. Ojo: acá NO está el password_hash, por eso nunca sale hacia el frontend.
class UsuarioOut(BaseModel):
    id: str
    nombre: str
    email: EmailStr
    rol: RolUsuario
    activo: bool = True
    creado_en: Optional[datetime] = None

    model_config = {"from_attributes": True}


# Respuesta del login.
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PerfilUpdate(BaseModel):
    nombre: str = Field(min_length=2, max_length=120)


# Para cambiar la contraseña mando la actual y la nueva (mínimo 8).
class PasswordCambio(BaseModel):
    actual: str = Field(min_length=1, max_length=128)
    nueva: str = Field(min_length=8, max_length=128)


# Alta de usuario hecha por un admin.
class UsuarioAdminCreate(BaseModel):
    """Alta de una cuenta por un administrador. Si no se indica contraseña, se genera una temporal."""
    nombre: str = Field(min_length=2, max_length=120)
    email: EmailStr
    rol: RolUsuario = RolUsuario.USUARIO
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)


# Hereda de UsuarioOut y agrega la contraseña temporal, que solo se muestra esa vez.
class UsuarioCreado(UsuarioOut):
    password_temporal: Optional[str] = None  # solo se devuelve una vez, al crearla


# Un admin solo puede cambiar el rol o activar/desactivar. Nada más.
class UsuarioUpdate(BaseModel):
    rol: Optional[RolUsuario] = None
    activo: Optional[bool] = None


# ---------- Proyectos ----------
# Entradas y salidas de proyectos y activos. Separo "Create" (lo que recibo) de "Out" (lo que devuelvo).
class ProyectoCreate(BaseModel):
    nombre: str = Field(min_length=2, max_length=150)
    descripcion: Optional[str] = None


class ProyectoOut(BaseModel):
    id: str
    nombre: str
    descripcion: Optional[str]
    propietario_id: Optional[str] = None
    creado_en: datetime

    model_config = {"from_attributes": True}


# ---------- Activos ----------
class ActivoCreate(BaseModel):
    nombre: str = Field(min_length=2, max_length=150)
    url_objetivo: str = Field(min_length=4, max_length=255)
    descripcion: Optional[str] = None


class ActivoOut(BaseModel):
    id: str
    proyecto_id: str
    nombre: str
    url_objetivo: str
    descripcion: Optional[str]
    creado_en: datetime

    model_config = {"from_attributes": True}


# ---------- Evaluaciones / Hallazgos ----------
class HallazgoOut(BaseModel):
    id: str
    evaluacion_id: str
    nombre_vulnerabilidad: str
    categoria_owasp: Optional[str]
    cvss_score: Optional[float]
    severidad: SeveridadHallazgo
    evidencia: Optional[str]
    recomendacion: Optional[str]
    herramienta_origen: Optional[str]
    corregido: str

    model_config = {"from_attributes": True}


# Lo único que se puede editar de un hallazgo es si está corregido ("si" o "no"). Literal rechaza cualquier otro valor.
class HallazgoUpdate(BaseModel):
    corregido: Literal["si", "no"]


class EvaluacionOut(BaseModel):
    id: str
    activo_id: str
    estado: EstadoEvaluacion
    iniciada_en: datetime
    finalizada_en: Optional[datetime]
    detalle_error: Optional[str] = None
    progreso: Optional[int] = None
    etapa: Optional[str] = None
    hallazgos: List[HallazgoOut] = []

    model_config = {"from_attributes": True}


# ---------- Reportes ----------
# Un reporte se arma con la lista de evaluaciones que el usuario eligió (entre 1 y 50).
class ReporteCreate(BaseModel):
    titulo: Optional[str] = Field(default=None, max_length=200)
    evaluacion_ids: List[str] = Field(min_length=1, max_length=50)


class ReporteOut(BaseModel):
    id: str
    proyecto_id: str
    titulo: Optional[str]
    nombre_archivo: str
    generado_en: datetime
    generado_por: Optional[str]
    evaluacion_ids: List[str] = []
    tamano_kb: Optional[int]

    model_config = {"from_attributes": True}

    @field_validator("evaluacion_ids", mode="before")
    # Si el reporte no tiene evaluaciones guardadas devuelvo lista vacía en vez de None, para que el frontend no falle.
    @classmethod
    def _lista(cls, lista):
        return lista or []


# ---------- Configuración ----------
# Validación de la configuración: el timeout tiene un mínimo y un máximo para que nadie ponga valores absurdos.
class NmapConfig(BaseModel):
    activo: bool
    puertos: Literal["predeterminado", "rapido", "completo"]
    timeout_s: int = Field(ge=30, le=3600)
    detectar_versiones: bool


class MotorExterno(BaseModel):
    activo: bool = False


# El escaneo activo de ZAP manda ataques de prueba, por eso parte apagado.
class ZapConfig(BaseModel):
    activo: bool = False
    escaneo_activo: bool = False  # el escaneo activo envía ataques de prueba: apagado por defecto
    timeout_s: int = Field(default=600, ge=60, le=7200)
    disponible: Optional[bool] = None  # calculado por el servidor; se acepta y se ignora


class Motores(BaseModel):
    nmap: NmapConfig
    zap: ZapConfig = ZapConfig()
    nikto: MotorExterno = MotorExterno()


# Los campos calculados (rangos y candado del servidor) se aceptan pero se ignoran; el servidor los vuelve a calcular.
class Alcance(BaseModel):
    permitir_publicas: bool
    # rangos y publicas_permitidas_por_servidor son calculados: se aceptan y se ignoran
    rangos: Optional[List[str]] = None
    publicas_permitidas_por_servidor: Optional[bool] = None


class ConfiguracionIn(BaseModel):
    motores: Motores
    alcance: Alcance
    retencion_dias: int = Field(ge=0, le=3650)


# ---------- Análisis de URL / archivo ----------
# Para el análisis rápido solo acepto URLs que empiecen con http:// o https://.
class AnalisisUrlIn(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

    @field_validator("url")
    @classmethod
    def _http(cls, url: str) -> str:
        url = url.strip()
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("La URL debe empezar con http:// o https://")
        return url


class AnalisisOut(BaseModel):
    id: str
    tipo: str
    objetivo: str
    sha256: Optional[str] = None
    tamano_bytes: Optional[int] = None
    estado: str
    veredicto: Optional[str] = None
    resumen: Optional[str] = None
    detalle: Optional[dict] = None
    creado_en: datetime
    finalizado_en: Optional[datetime] = None

    model_config = {"from_attributes": True}


# Le dice al frontend si VirusTotal está configurado y el tamaño máximo de archivo.
class AnalisisEstado(BaseModel):
    virustotal: bool
    max_mb: int
