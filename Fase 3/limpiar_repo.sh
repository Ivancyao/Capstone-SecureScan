#!/usr/bin/env bash
# Limpieza del repositorio antes de la presentación. Déjalo FUERA del repo y ejecútalo parado en la raíz del repo:  bash RUTA/limpiar_repo.sh
# Revisa cada línea: usa "git rm", así que todo queda en el historial y se puede recuperar.
set -e

# Instrucciones de copiado del paquete anterior (no son parte del proyecto)
git rm -qf --ignore-unmatch LEEME_APLICAR.txt

# Archivos sobrantes
git rm -q --ignore-unmatch LEEME.txt
git rm -q --ignore-unmatch "Fase 2/README.md"
git rm -q --ignore-unmatch "Fase 2/Grupales/2.4_GuiaEstudiante_Fase2_DesarrolloProyecto_APT.docx"
git rm -q --ignore-unmatch "Fase 2/Grupales/2.6_GuiaEstudiante_Fase2_InformeFinal_APT_BORRADOR_v4.docx"

# El informe 2.6 queda en un solo lugar: Fase 2/Grupales (la versión corregida va en el paquete)
git rm -q --ignore-unmatch "Fase 2/2.6_GuiaEstudiante_Fase2_InformeFinal_APT_actualizada.docx"

# Diagramas viejos duplicados (la serie numerada 01 a 11 es la vigente y la que usa el README)
D="Fase 2/Evidencias Proyecto/Evidencias de documentacion/diagramas"
for f in arquitectura casos_de_uso er seq_evaluacion seq_login seq_reporte; do
  git rm -q --ignore-unmatch "$D/$f.png"
done

git add -A
git status --short
echo
echo "Listo. Si todo se ve bien:"
echo '  git commit -m "Documentos v1.4, 138 pruebas, README con enlaces corregidos y limpieza del repositorio"'
echo "  git push"
