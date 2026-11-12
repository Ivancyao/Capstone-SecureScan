"""Señal de cancelación compartida por el orquestador, Nmap y ZAP."""


class EvaluacionCancelada(Exception):
    """El usuario canceló (o eliminó) la evaluación mientras se ejecutaba en segundo plano."""


# La cancelación se guarda como estado FALLIDA + etapa "Cancelada": no exige cambiar el tipo
# enumerado de la base de datos (en PostgreSQL habría que migrarlo) y la interfaz la muestra aparte.
ETAPA_CANCELADA = "Cancelada"
