"""Ejecuta todas las comprobaciones sin dependencias externas.

    py tools/check_all.py
"""

import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
CHECKS = (
    ("Regla de dependencia", "check_architecture.py"),
    ("Dominio de validacion", "smoke_check.py"),
    ("Cadena completa", "smoke_chain.py"),
    ("Experimentacion y tecnicos", "smoke_experiment.py"),
)

failed = []
for label, script in CHECKS:
    print(f"\n{'=' * 60}\n{label}\n{'=' * 60}")
    result = subprocess.run([sys.executable, str(TOOLS / script)], check=False)
    if result.returncode != 0:
        failed.append(label)

print(f"\n{'=' * 60}")
if failed:
    print("FALLARON: " + ", ".join(failed))
    sys.exit(1)
print("Todas las comprobaciones pasaron.")
