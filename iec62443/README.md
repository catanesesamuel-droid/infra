# IEC 62443-3-3 Compliance Analyzer

Herramienta de análisis automático de cumplimiento de la norma **IEC 62443-3-3**
para sistemas operativos Linux (Ubuntu 22.04 / 23.xx / 24.xx / 25.xx, Kali Linux)
y otros sistemas objetivo (Windows 11, macOS).

## Estructura del proyecto

```
iec62443/
├── src/
│   ├── collector/
│   │   ├── __init__.py
│   │   └── collector.py        # Recolecta datos del SO (los 7 FR)
│   ├── analyzer/
│   │   ├── __init__.py
│   │   └── analyzer.py         # Mapea datos a SRs y calcula SL alcanzado
│   └── reporter/
│       ├── __init__.py
│       └── reporter.py         # Genera informe PDF
├── frontend/
│   └── dashboard.html          # Dashboard web (sin dependencias de servidor)
├── output/                     # Archivos generados (JSON, PDF) — ignorados por git
├── tests/
│   └── test_analyzer.py        # Tests de validación
├── docs/
│   └── fr_sr_mapping.md        # Referencia de SRs implementados
├── scripts/
│   └── run_full_analysis.sh    # Pipeline completo en un solo comando
├── requirements.txt
├── .gitignore
└── README.md
```

## Instalación

```bash
# Clonar o copiar el proyecto
cd iec62443

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

## Uso rápido

```bash
# Pipeline completo (requiere sudo para leer configs del sistema)
bash scripts/run_full_analysis.sh

# O paso a paso:
sudo python3 src/collector/collector.py  --output output/collection_output.json --pretty
python3      src/analyzer/analyzer.py   --input  output/collection_output.json  --output output/analysis_report.json --summary
python3      src/reporter/reporter.py   --input  output/analysis_report.json    --output output/compliance_report.pdf

# Abrir dashboard en el navegador
xdg-open frontend/dashboard.html
# → Cargar output/analysis_report.json
```

## Security Levels

| SL | Descripción |
|----|-------------|
| SL0 | Sin protección |
| SL1 | Protección contra errores accidentales |
| SL2 | Protección contra atacantes con medios simples *(objetivo mínimo recomendado)* |
| SL3 | Protección contra atacantes con conocimiento específico del sistema |
| SL4 | Protección contra atacantes con recursos y motivación extrema |

## Foundational Requirements cubiertos

| FR | Nombre | SRs implementados |
|----|--------|-------------------|
| FR1 | Identificación y autenticación | SR 1.1, 1.3, 1.7, 1.8 |
| FR2 | Control de uso | SR 2.1, 2.6, 2.7 |
| FR3 | Integridad del sistema | SR 3.2, 3.3, 3.4 |
| FR4 | Confidencialidad de datos | SR 4.1, 4.2 |
| FR5 | Flujo restringido de datos | SR 5.1, 5.3 |
| FR6 | Respuesta oportuna a eventos | SR 6.1, 6.2 |
| FR7 | Disponibilidad de recursos | SR 7.1, 7.2, 7.3, 7.7 |
