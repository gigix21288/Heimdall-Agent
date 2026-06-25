"""
SecureCheck Agent — Build script multi-piattaforma.
Genera l'eseguibile per Windows (.exe), Linux o macOS.
Zero dipendenze esterne richieste oltre a PyInstaller.

Uso:
    python build.py          # build per la piattaforma corrente
    python build.py --clean  # pulisce e ricostruisce
"""

import os
import platform
import shutil
import subprocess
import sys

AGENT_SCRIPT = "vallia_agent_enhanced.py"
DATA_FILES = [
    ("trackers.json", "."),
    ("ip_orgs.json", "."),
    ("device_privacy.json", "."),
]
NAME = "securecheck-agent"
DIST_DIR = "dist"

def get_add_data_args():
    """Costruisce gli argomenti --add-data per PyInstaller."""
    sep = ";" if platform.system() == "Windows" else ":"
    args = []
    for src, dst in DATA_FILES:
        if os.path.exists(src):
            args.extend(["--add-data", f"{src}{sep}{dst}"])
        else:
            print(f"WARN: File dati mancante: {src}")
    return args

def build():
    system = platform.system()
    print(f"Build per: {system} ({platform.machine()})")
    print(f"   Python:  {sys.version.split()[0]}")
    print(f"   Script:  {AGENT_SCRIPT}")
    print()

    if not os.path.exists(AGENT_SCRIPT):
        print(f"ERR: Script non trovato: {AGENT_SCRIPT}")
        sys.exit(1)

    if "--clean" in sys.argv:
        for d in ["build", "dist", "__pycache__"]:
            if os.path.exists(d):
                shutil.rmtree(d)
        spec_file = f"{NAME}.spec"
        if os.path.exists(spec_file):
            os.remove(spec_file)
        print("Pulizia completata.\n")

    output_name = f"{NAME}.exe" if system == "Windows" else NAME

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", NAME,
        "--clean",
        "--noconfirm",
        *get_add_data_args(),
        AGENT_SCRIPT,
    ]

    print(f"> {subprocess.list2cmdline(cmd)}")
    print()

    result = subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))
    if result.returncode != 0:
        print(f"\nERR: Build fallita (exit {result.returncode})")
        sys.exit(result.returncode)

    output_path = os.path.join(DIST_DIR, output_name)
    if os.path.exists(output_path):
        size_mb = os.path.getsize(output_path) / (1024 * 1024)
        print(f"\nBuild completata!")
        print(f"   File: {output_path}")
        print(f"   Size: {size_mb:.1f} MB")
        print(f"\nPer testare:")
        if system == "Windows":
            print(f"   {output_path} --port 8766")
        else:
            print(f"   chmod +x {output_path}")
            print(f"   ./{output_name} --port 8766")
    else:
        print(f"\nERR: Output non trovato: {output_path}")
        sys.exit(1)

if __name__ == "__main__":
    build()
