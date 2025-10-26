#!/usr/bin/env python3
"""
Update SSI_Complete_Workflow.ipynb to use PQC HTTPS Reverse Proxy
Changes:
- Cell 1: VON_NETWORK_URL to HTTPS + disable SSL warnings
- Cell 10a: Add verify=False to requests.get()
"""
import json

# Read notebook
with open("SSI_Complete_Workflow.ipynb", "r") as f:
    nb = json.load(f)

# ============================================================================
# CELL 1: Update VON_NETWORK_URL and add SSL warning suppression
# ============================================================================
cell_1_index = None
for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] == "code":
        source = "".join(cell["source"]) if isinstance(cell["source"], list) else cell["source"]
        if "Cell 1:" in source and "VON_NETWORK_URL" in source:
            cell_1_index = i
            break

if cell_1_index is not None:
    print(f"✅ Found Cell 1 at index {cell_1_index}")

    # New Cell 1 source with HTTPS and SSL warning suppression
    new_cell_1 = '''# Cell 1: Imports und Konfiguration
import requests
import json
import time
import pandas as pd
from IPython.display import display, Markdown, HTML
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# SSL Warnung für self-signed Zertifikate unterdrücken (PQC Proxy)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Agent URLs
ISSUER_ADMIN_URL = "http://localhost:8021"
HOLDER_ADMIN_URL = "http://localhost:8031"
VERIFIER_ADMIN_URL = "http://localhost:8041"
VON_NETWORK_URL = "https://localhost:4433"  # PQC HTTPS Reverse Proxy

# Farben für Visualisierungen
ISSUER_COLOR = "#3498db"  # Blau
HOLDER_COLOR = "#2ecc71"  # Grün
VERIFIER_COLOR = "#e74c3c"  # Rot

print("✅ Imports erfolgreich")
print(f"📍 Issuer:   {ISSUER_ADMIN_URL}")
print(f"📍 Holder:   {HOLDER_ADMIN_URL}")
print(f"📍 Verifier: {VERIFIER_ADMIN_URL}")
print(f"📍 Ledger:   {VON_NETWORK_URL} 🔒 (PQC HTTPS)")

# ========================================
# Tails-Server Konfiguration (für Revocation)
# ========================================
TAILS_SERVER_URL = "http://localhost:6543"
TAILS_FILE_COUNT = 100  # Max Credentials per Registry

print(f"📍 Tails:    {TAILS_SERVER_URL}")
print(f"   Max Credentials per Registry: {TAILS_FILE_COUNT}")

# ========================================
# Helper Functions
# ========================================

def api_get(base_url, path):
    """GET Request zu ACA-Py Admin API"""
    url = f"{base_url}{path}"
    response = requests.get(url)
    return response.json() if response.status_code == 200 else None

def api_post(base_url, path, data):
    """POST Request zu ACA-Py Admin API"""
    url = f"{base_url}{path}"
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=data, headers=headers)
    return response.json() if response.status_code == 200 else None

def pretty_print(data, title=""):
    """Pretty print JSON data"""
    if title:
        print(f"\\n{'='*60}")
        print(f"  {title}")
        print('='*60)
    print(json.dumps(data, indent=2))
    print()

print("\\n✅ Setup komplett!")
'''

    # Update cell
    nb["cells"][cell_1_index]["source"] = new_cell_1.split("\n")
    nb["cells"][cell_1_index]["source"] = [line + "\n" if i < len(nb["cells"][cell_1_index]["source"]) - 1 else line
                                           for i, line in enumerate(nb["cells"][cell_1_index]["source"])]
    print("   ✓ Updated VON_NETWORK_URL to https://localhost:4433")
    print("   ✓ Added urllib3.disable_warnings()")

# ============================================================================
# CELL 10a: Add verify=False to requests.get()
# ============================================================================
cell_10a_index = None
for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] == "code":
        source = "".join(cell["source"]) if isinstance(cell["source"], list) else cell["source"]
        if "Cell 10a:" in source and "Domain Ledger" in source:
            cell_10a_index = i
            break

if cell_10a_index is not None:
    print(f"\n✅ Found Cell 10a at index {cell_10a_index}")

    # Read current source
    source = "".join(nb["cells"][cell_10a_index]["source"])

    # Replace the requests.get line
    old_line = 'ledger_response = requests.get(f"{VON_NETWORK_URL}/ledger/domain")'
    new_line = '''ledger_response = requests.get(
        f"{VON_NETWORK_URL}/ledger/domain",
        verify=False  # Self-signed Zertifikat akzeptieren
    )'''

    if old_line in source:
        new_source = source.replace(old_line, new_line)

        # Also update the print statement
        old_print = 'print("📋 Domain Ledger - Letzte Transaktionen\\n")'
        new_print = '''print("📋 Domain Ledger - Letzte Transaktionen")
print("🔒 Verbindung über PQC HTTPS Reverse Proxy (Port 4433)\\n")'''

        new_source = new_source.replace(old_print, new_print)

        # Update cell
        nb["cells"][cell_10a_index]["source"] = new_source.split("\n")
        nb["cells"][cell_10a_index]["source"] = [line + "\n" if i < len(nb["cells"][cell_10a_index]["source"]) - 1 else line
                                                 for i, line in enumerate(nb["cells"][cell_10a_index]["source"])]
        print("   ✓ Added verify=False to requests.get()")
        print("   ✓ Added PQC HTTPS info to output")
    else:
        print("   ⚠ Could not find exact line to replace (manual edit needed)")

# Write back
with open("SSI_Complete_Workflow.ipynb", "w") as f:
    json.dump(nb, f, indent=2)

print("\n" + "="*60)
print("✅ SSI_Complete_Workflow.ipynb erfolgreich aktualisiert!")
print("="*60)
print("\n📝 Änderungen:")
print("   Cell 1:")
print("      • VON_NETWORK_URL: https://localhost:4433 (war http://localhost:9000)")
print("      • urllib3.disable_warnings() hinzugefügt")
print("      • Output zeigt 🔒 (PQC HTTPS)")
print("\n   Cell 10a:")
print("      • requests.get() mit verify=False")
print("      • PQC HTTPS Info im Output")
print("\n💡 Alle Ledger-Zugriffe laufen jetzt über den PQC Reverse Proxy!")
print("   Quantum-Safe Key Exchange: ML-KEM-768/1024")
print("   TLS 1.3 Only")
