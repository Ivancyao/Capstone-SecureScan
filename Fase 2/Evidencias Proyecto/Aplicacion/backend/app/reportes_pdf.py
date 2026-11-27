"""
Generación del informe PDF (ReportLab). Recibe datos ya cargados desde la BD y devuelve bytes.

Estructura: portada con resumen ejecutivo, activos evaluados, hallazgos priorizados,
recomendaciones y limitaciones. La severidad siempre va con texto (no solo color).
"""
import io
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, List
# ReportLab interpreta un mini-HTML dentro de los párrafos; por eso todo texto que viene de la BD pasa por escape() antes de insertarlo (así un nombre con "<" no rompe ni inyecta nada en el PDF).
from xml.sax.saxutils import escape  # nosec B406

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

# En la BD todo está en UTC; en el PDF muestro la hora de Chile (o la zona de APP_TZ). Si el sistema no tiene la base de zonas horarias, uso UTC-3 fijo.
def _hora_local(fecha_hora: datetime) -> datetime:
    """Convierte una fecha guardada en UTC (sin zona) a la hora local (APP_TZ, por defecto America/Santiago)."""
    if fecha_hora.tzinfo is None:
        fecha_hora = fecha_hora.replace(tzinfo=timezone.utc)
    try:
        from zoneinfo import ZoneInfo
        return fecha_hora.astimezone(ZoneInfo(os.getenv("APP_TZ", "America/Santiago")))
    except Exception:  # sin base de zonas horarias: UTC-3 fijo (horario de verano de Chile)
        return fecha_hora.astimezone(timezone(timedelta(hours=-3)))


# Orden de gravedad que uso para ordenar y contar. Los colores de fondo son suaves, y además cada severidad va escrita en texto (no depende solo del color, por accesibilidad).
ORDEN = ["critica", "alta", "media", "baja", "informativa"]
ETIQUETA = {"critica": "Crítica", "alta": "Alta", "media": "Media", "baja": "Baja", "informativa": "Informativa"}
FONDO = {
    "critica": colors.HexColor("#fce9e7"), "alta": colors.HexColor("#fdecdf"),
    "media": colors.HexColor("#fcf3d3"), "baja": colors.HexColor("#e3f3ea"),
    "informativa": colors.HexColor("#eaeef3"),
}
TINTA = colors.HexColor("#14202e")
SUAVE = colors.HexColor("#5b6b7e")
ACENTO = colors.HexColor("#08657f")
LINEA = colors.HexColor("#d5dde6")


# Todo texto del usuario o de la BD pasa por acá antes de entrar al PDF.
def _escapar(texto) -> str:
    return escape(str(texto)) if texto is not None else ""


# Estilos de texto del informe (título, subtítulo, celdas de tabla, etc.).
def _estilos():
    base = getSampleStyleSheet()
    return {
        "titulo": ParagraphStyle("titulo", parent=base["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=TINTA, alignment=TA_LEFT, spaceAfter=4),
        "sub": ParagraphStyle("sub", parent=base["Normal"], fontSize=10, textColor=SUAVE, leading=14),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=14, textColor=TINTA, spaceBefore=16, spaceAfter=6),
        "p": ParagraphStyle("p", parent=base["Normal"], fontSize=10, leading=14, textColor=TINTA),
        "celda": ParagraphStyle("celda", parent=base["Normal"], fontSize=8.5, leading=11, textColor=TINTA),
        "celda_b": ParagraphStyle("celda_b", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=TINTA),
        "cab": ParagraphStyle("cab", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.white),
        "peq": ParagraphStyle("peq", parent=base["Normal"], fontSize=8.5, leading=12, textColor=SUAVE),
    }


# Tabla genérica con encabezado de color que se repite en cada página. Las otras funciones solo le pasan filas y anchos.
def _tabla(filas, anchos, estilo_extra=None):
    tabla = Table(filas, colWidths=anchos, repeatRows=1)
    estilo_tabla = [
        ("BACKGROUND", (0, 0), (-1, 0), ACENTO),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINEA),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    tabla.setStyle(TableStyle(estilo_tabla + (estilo_extra or [])))
    return tabla


# Pie de página con el nombre del sistema y el número de página.
def _pie(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(SUAVE)
    canvas.drawString(20 * mm, 12 * mm, "SecureScan · Informe de evaluación de vulnerabilidades")
    canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Página {doc.page}")
    canvas.restoreState()


# Recibe datos simples (diccionarios), no objetos de la BD, para que esta función no dependa de la base y sea fácil de probar.
# Secciones del informe: resumen ejecutivo, activos evaluados, hallazgos priorizados, recomendaciones y limitaciones.
def generar_pdf(proyecto: Dict, titulo: str, generado_por: str, evaluaciones: List[Dict]) -> bytes:
    """
    `evaluaciones`: lista de dicts {activo: {nombre, url_objetivo}, iniciada_en, hallazgos: [dict...]}.
    Cada hallazgo: nombre_vulnerabilidad, severidad (str), cvss_score, categoria_owasp, evidencia,
    recomendacion, corregido.
    """
    estilos = _estilos()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=20 * mm, title=titulo, author="SecureScan")
    ancho = A4[0] - 40 * mm
    elementos = []

    # Junto los hallazgos de todas las evaluaciones y separo los "abiertos" (los que no están marcados como corregidos).
    todos = []
    for evaluacion in evaluaciones:
        for hallazgo in evaluacion["hallazgos"]:
            todos.append({**hallazgo, "activo": evaluacion["activo"]["nombre"]})
    abiertos = [hallazgo for hallazgo in todos if hallazgo.get("corregido") != "si"]
    cuenta = Counter(hallazgo["severidad"] for hallazgo in abiertos)

    # ---- Portada y resumen ejecutivo ----
    elementos.append(Paragraph(_escapar(titulo), estilos["titulo"]))
    elementos.append(Paragraph(f"Proyecto: <b>{_escapar(proyecto['nombre'])}</b>", estilos["sub"]))
    elementos.append(Paragraph(f"Generado el {_hora_local(datetime.now(timezone.utc)):%d/%m/%Y %H:%M} por {_escapar(generado_por)} · {len(evaluaciones)} evaluación(es) incluida(s)", estilos["sub"]))

    elementos.append(Paragraph("Resumen ejecutivo", estilos["h2"]))
    # El resumen cambia según haya o no hallazgos abiertos. Aunque no haya ninguno, aclaro que eso no garantiza que el sistema sea seguro.
    if not abiertos:
        resumen = "En las evaluaciones incluidas no hay hallazgos abiertos. Esto no garantiza la ausencia de vulnerabilidades: solo refleja lo que detectaron las herramientas usadas (ver Limitaciones)."
    else:
        # Priorizo: cuento los críticos y altos, que son los que conviene corregir primero.
        graves = cuenta.get("critica", 0) + cuenta.get("alta", 0)
        prioridad = (
            f"Hay <b>{graves}</b> hallazgo(s) de severidad crítica o alta que conviene corregir primero."
            if graves else "No hay hallazgos críticos ni altos; se recomienda revisar los de severidad media."
        )
        resumen = f"Se encontraron <b>{len(abiertos)}</b> hallazgo(s) abiertos en {len(evaluaciones)} evaluación(es). {prioridad}"
    elementos.append(Paragraph(resumen, estilos["p"]))
    elementos.append(Spacer(1, 8))

    filas = [[Paragraph("Severidad", estilos["cab"]), Paragraph("Hallazgos abiertos", estilos["cab"])]]
    extra = []
    for i, sev in enumerate(ORDEN, start=1):
        filas.append([Paragraph(ETIQUETA[sev], estilos["celda_b"]), Paragraph(str(cuenta.get(sev, 0)), estilos["celda"])])
        extra.append(("BACKGROUND", (0, i), (0, i), FONDO[sev]))
    elementos.append(_tabla(filas, [ancho * 0.4, ancho * 0.6], extra))

    # ---- Activos evaluados ----
    elementos.append(Paragraph("Activos evaluados", estilos["h2"]))
    filas = [[Paragraph(texto, estilos["cab"]) for texto in ("Activo", "Objetivo", "Evaluación", "Hallazgos abiertos", "Mayor severidad")]]
    for evaluacion in evaluaciones:
        abiertos_de_la_evaluacion = [hallazgo for hallazgo in evaluacion["hallazgos"] if hallazgo.get("corregido") != "si"]
        mayor = next((ETIQUETA[severidad] for severidad in ORDEN if any(hallazgo["severidad"] == severidad for hallazgo in abiertos_de_la_evaluacion)), "—")
        filas.append([
            Paragraph(_escapar(evaluacion["activo"]["nombre"]), estilos["celda_b"]),
            Paragraph(_escapar(evaluacion["activo"]["url_objetivo"]), estilos["celda"]),
            Paragraph(f"{_hora_local(evaluacion['iniciada_en']):%d/%m/%Y %H:%M}", estilos["celda"]),
            Paragraph(str(len(abiertos_de_la_evaluacion)), estilos["celda"]),
            Paragraph(mayor, estilos["celda"]),
        ])
    elementos.append(_tabla(filas, [ancho * 0.24, ancho * 0.28, ancho * 0.18, ancho * 0.14, ancho * 0.16]))

    # ---- Hallazgos priorizados ----
    elementos.append(Paragraph("Hallazgos priorizados", estilos["h2"]))
    if not todos:
        elementos.append(Paragraph("No se registraron hallazgos.", estilos["p"]))
    else:
        # Ordeno de más grave a menos grave y, dentro de la misma severidad, por CVSS de mayor a menor.
        ordenados = sorted(todos, key=lambda hallazgo: (ORDEN.index(hallazgo["severidad"]), -(hallazgo.get("cvss_score") or 0)))
        filas = [[Paragraph(texto, estilos["cab"]) for texto in ("Severidad", "Hallazgo", "Activo", "CVSS*", "Estado")]]
        extra = []
        for i, hallazgo in enumerate(ordenados, start=1):
            filas.append([
                Paragraph(ETIQUETA[hallazgo["severidad"]], estilos["celda_b"]),
                Paragraph(f"<b>{_escapar(hallazgo['nombre_vulnerabilidad'])}</b><br/>{_escapar(hallazgo.get('evidencia'))}", estilos["celda"]),
                Paragraph(_escapar(hallazgo["activo"]), estilos["celda"]),
                Paragraph("—" if hallazgo.get("cvss_score") is None else f"{hallazgo['cvss_score']:.1f}", estilos["celda"]),
                Paragraph("Corregido" if hallazgo.get("corregido") == "si" else "Abierto", estilos["celda"]),
            ])
            extra.append(("BACKGROUND", (0, i), (0, i), FONDO[hallazgo["severidad"]]))
        elementos.append(_tabla(filas, [ancho * 0.14, ancho * 0.44, ancho * 0.2, ancho * 0.09, ancho * 0.13], extra))
        # Aclaro en el propio informe que el CVSS es estimado (así no se confunde con un puntaje oficial).
        elementos.append(Paragraph("* CVSS estimado por reglas según el servicio expuesto; no es un cálculo vectorial completo.", estilos["peq"]))

    # ---- Recomendaciones ----
    elementos.append(Paragraph("Recomendaciones", estilos["h2"]))
    # Las recomendaciones pueden repetirse entre hallazgos del mismo tipo; con este set muestro cada una solo una vez.
    vistas = set()
    hay = False
    for hallazgo in sorted(abiertos, key=lambda hallazgo: (ORDEN.index(hallazgo["severidad"]), -(hallazgo.get("cvss_score") or 0))):
        if not hallazgo.get("recomendacion") or hallazgo["nombre_vulnerabilidad"] in vistas:
            continue
        vistas.add(hallazgo["nombre_vulnerabilidad"])
        hay = True
        elementos.append(KeepTogether([
            Paragraph(f"<b>{_escapar(hallazgo['nombre_vulnerabilidad'])}</b> — {ETIQUETA[hallazgo['severidad']]}", estilos["p"]),
            Paragraph(_escapar(hallazgo["recomendacion"]), estilos["p"]),
            Spacer(1, 6),
        ]))
    if not hay:
        elementos.append(Paragraph("No hay recomendaciones pendientes.", estilos["p"]))

    # ---- Limitaciones ----
    elementos.append(Paragraph("Limitaciones", estilos["h2"]))
    # Sección de limitaciones: es honesto dejar claro hasta dónde llega el informe.
    for texto in (
        "Este informe refleja el estado de los sistemas en el momento de cada escaneo.",
        "Las evaluaciones usan Nmap (puertos y servicios expuestos) y, cuando está activado, OWASP ZAP (análisis de aplicaciones web). Ninguna herramienta automática detecta todas las vulnerabilidades; el escaneo activo de ZAP está apagado por defecto.",
        "El puntaje CVSS es una estimación por reglas, útil para priorizar pero no equivalente a un puntaje CVSS v3.1 calculado con su vector completo.",
        "SecureScan solo evalúa ambientes de laboratorio o con autorización expresa del propietario.",
    ):
        elementos.append(Paragraph("• " + _escapar(texto), estilos["p"]))

    # El PDF se arma en memoria (BytesIO) y devuelvo los bytes; quien llama decide dónde guardarlos.
    doc.build(elementos, onFirstPage=_pie, onLaterPages=_pie)
    return buf.getvalue()
