"""
Generación del informe PDF (ReportLab). Recibe datos ya cargados desde la BD y devuelve bytes.

Estructura: portada con resumen ejecutivo, activos evaluados, hallazgos priorizados,
recomendaciones y limitaciones. La severidad siempre va con texto (no solo color).
"""
import io
from collections import Counter
from datetime import datetime
from typing import Dict, List
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

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


def _e(texto) -> str:
    return escape(str(texto)) if texto is not None else ""


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


def _tabla(filas, anchos, estilo_extra=None):
    t = Table(filas, colWidths=anchos, repeatRows=1)
    st = [
        ("BACKGROUND", (0, 0), (-1, 0), ACENTO),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINEA),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    t.setStyle(TableStyle(st + (estilo_extra or [])))
    return t


def _pie(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(SUAVE)
    canvas.drawString(20 * mm, 12 * mm, "SecureScan · Informe de evaluación de vulnerabilidades")
    canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Página {doc.page}")
    canvas.restoreState()


def generar_pdf(proyecto: Dict, titulo: str, generado_por: str, evaluaciones: List[Dict]) -> bytes:
    """
    `evaluaciones`: lista de dicts {activo: {nombre, url_objetivo}, iniciada_en, hallazgos: [dict...]}.
    Cada hallazgo: nombre_vulnerabilidad, severidad (str), cvss_score, categoria_owasp, evidencia,
    recomendacion, corregido.
    """
    est = _estilos()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=20 * mm, title=titulo, author="SecureScan")
    ancho = A4[0] - 40 * mm
    h = []

    todos = []
    for ev in evaluaciones:
        for x in ev["hallazgos"]:
            todos.append({**x, "activo": ev["activo"]["nombre"]})
    abiertos = [x for x in todos if x.get("corregido") != "si"]
    cuenta = Counter(x["severidad"] for x in abiertos)

    # ---- Portada y resumen ejecutivo ----
    h.append(Paragraph(_e(titulo), est["titulo"]))
    h.append(Paragraph(f"Proyecto: <b>{_e(proyecto['nombre'])}</b>", est["sub"]))
    h.append(Paragraph(f"Generado el {datetime.now():%d/%m/%Y %H:%M} por {_e(generado_por)} · {len(evaluaciones)} evaluación(es) incluida(s)", est["sub"]))

    h.append(Paragraph("Resumen ejecutivo", est["h2"]))
    if not abiertos:
        resumen = "En las evaluaciones incluidas no hay hallazgos abiertos. Esto no garantiza la ausencia de vulnerabilidades: solo refleja lo que detectaron las herramientas usadas (ver Limitaciones)."
    else:
        graves = cuenta.get("critica", 0) + cuenta.get("alta", 0)
        prioridad = (
            f"Hay <b>{graves}</b> hallazgo(s) de severidad crítica o alta que conviene corregir primero."
            if graves else "No hay hallazgos críticos ni altos; se recomienda revisar los de severidad media."
        )
        resumen = f"Se encontraron <b>{len(abiertos)}</b> hallazgo(s) abiertos en {len(evaluaciones)} evaluación(es). {prioridad}"
    h.append(Paragraph(resumen, est["p"]))
    h.append(Spacer(1, 8))

    filas = [[Paragraph("Severidad", est["cab"]), Paragraph("Hallazgos abiertos", est["cab"])]]
    extra = []
    for i, sev in enumerate(ORDEN, start=1):
        filas.append([Paragraph(ETIQUETA[sev], est["celda_b"]), Paragraph(str(cuenta.get(sev, 0)), est["celda"])])
        extra.append(("BACKGROUND", (0, i), (0, i), FONDO[sev]))
    h.append(_tabla(filas, [ancho * 0.4, ancho * 0.6], extra))

    # ---- Activos evaluados ----
    h.append(Paragraph("Activos evaluados", est["h2"]))
    filas = [[Paragraph(t, est["cab"]) for t in ("Activo", "Objetivo", "Evaluación", "Hallazgos abiertos", "Mayor severidad")]]
    for ev in evaluaciones:
        ab = [x for x in ev["hallazgos"] if x.get("corregido") != "si"]
        mayor = next((ETIQUETA[s] for s in ORDEN if any(x["severidad"] == s for x in ab)), "—")
        filas.append([
            Paragraph(_e(ev["activo"]["nombre"]), est["celda_b"]),
            Paragraph(_e(ev["activo"]["url_objetivo"]), est["celda"]),
            Paragraph(f"{ev['iniciada_en']:%d/%m/%Y %H:%M}", est["celda"]),
            Paragraph(str(len(ab)), est["celda"]),
            Paragraph(mayor, est["celda"]),
        ])
    h.append(_tabla(filas, [ancho * 0.24, ancho * 0.28, ancho * 0.18, ancho * 0.14, ancho * 0.16]))

    # ---- Hallazgos priorizados ----
    h.append(Paragraph("Hallazgos priorizados", est["h2"]))
    if not todos:
        h.append(Paragraph("No se registraron hallazgos.", est["p"]))
    else:
        ordenados = sorted(todos, key=lambda x: (ORDEN.index(x["severidad"]), -(x.get("cvss_score") or 0)))
        filas = [[Paragraph(t, est["cab"]) for t in ("Severidad", "Hallazgo", "Activo", "CVSS*", "Estado")]]
        extra = []
        for i, x in enumerate(ordenados, start=1):
            filas.append([
                Paragraph(ETIQUETA[x["severidad"]], est["celda_b"]),
                Paragraph(f"<b>{_e(x['nombre_vulnerabilidad'])}</b><br/>{_e(x.get('evidencia'))}", est["celda"]),
                Paragraph(_e(x["activo"]), est["celda"]),
                Paragraph("—" if x.get("cvss_score") is None else f"{x['cvss_score']:.1f}", est["celda"]),
                Paragraph("Corregido" if x.get("corregido") == "si" else "Abierto", est["celda"]),
            ])
            extra.append(("BACKGROUND", (0, i), (0, i), FONDO[x["severidad"]]))
        h.append(_tabla(filas, [ancho * 0.14, ancho * 0.44, ancho * 0.2, ancho * 0.09, ancho * 0.13], extra))
        h.append(Paragraph("* CVSS estimado por reglas según el servicio expuesto; no es un cálculo vectorial completo.", est["peq"]))

    # ---- Recomendaciones ----
    h.append(Paragraph("Recomendaciones", est["h2"]))
    vistas = set()
    hay = False
    for x in sorted(abiertos, key=lambda x: (ORDEN.index(x["severidad"]), -(x.get("cvss_score") or 0))):
        if not x.get("recomendacion") or x["nombre_vulnerabilidad"] in vistas:
            continue
        vistas.add(x["nombre_vulnerabilidad"])
        hay = True
        h.append(KeepTogether([
            Paragraph(f"<b>{_e(x['nombre_vulnerabilidad'])}</b> — {ETIQUETA[x['severidad']]}", est["p"]),
            Paragraph(_e(x["recomendacion"]), est["p"]),
            Spacer(1, 6),
        ]))
    if not hay:
        h.append(Paragraph("No hay recomendaciones pendientes.", est["p"]))

    # ---- Limitaciones ----
    h.append(Paragraph("Limitaciones", est["h2"]))
    for t in (
        "Este informe refleja el estado de los sistemas en el momento de cada escaneo.",
        "Las evaluaciones usan Nmap (puertos y servicios expuestos). El análisis de aplicaciones web con OWASP ZAP aún no está integrado, por lo que no se detectan fallos propios de la aplicación (inyecciones, XSS, etc.).",
        "El puntaje CVSS es una estimación por reglas, útil para priorizar pero no equivalente a un puntaje CVSS v3.1 calculado con su vector completo.",
        "SecureScan solo evalúa ambientes de laboratorio o con autorización expresa del propietario.",
    ):
        h.append(Paragraph("• " + _e(t), est["p"]))

    doc.build(h, onFirstPage=_pie, onLaterPages=_pie)
    return buf.getvalue()
