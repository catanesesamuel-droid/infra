#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# run_full_analysis.sh
# Pipeline completo IEC 62443-3-3: collect → analyze → report
# Uso: bash scripts/run_full_analysis.sh
# ─────────────────────────────────────────────────────────────

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$ROOT/output"
VENV="$ROOT/venv/bin/python3"
PYTHON=$([ -f "$VENV" ] && echo "$VENV" || echo "python3")

mkdir -p "$OUTPUT"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   IEC 62443-3-3 Compliance Analyzer          ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Paso 1: Collector ──
echo "[1/3] Recolectando datos del sistema..."
sudo "$PYTHON" "$ROOT/src/collector/collector.py" \
  --output "$OUTPUT/collection_output.json" \
  --pretty

# ── Paso 2: Analyzer ──
echo ""
echo "[2/3] Analizando cumplimiento IEC 62443-3-3..."
"$PYTHON" "$ROOT/src/analyzer/analyzer.py" \
  --input  "$OUTPUT/collection_output.json" \
  --output "$OUTPUT/analysis_report.json" \
  --summary

# ── Paso 3: Reporter ──
echo ""
echo "[3/3] Generando informe PDF..."
"$PYTHON" "$ROOT/src/reporter/reporter.py" \
  --input  "$OUTPUT/analysis_report.json" \
  --output "$OUTPUT/compliance_report.pdf"

echo ""
echo "✓ Pipeline completado. Archivos generados en: $OUTPUT"
echo "  · collection_output.json"
echo "  · analysis_report.json"
echo "  · compliance_report.pdf"
echo ""
echo "  Dashboard: abre frontend/dashboard.html en el navegador"
echo "             y carga output/analysis_report.json"
echo ""
