import sys
import subprocess
import os
import time
from src.extraction import extraction_flux_rss, extraction_CVE

while True:

    # --- PARTIE 1 : RSS ---
    print("1. Lancement de l'extraction RSS")
    extraction_flux_rss()

    # --- PARTIE 2 : CVE ---
    print("\n2. Lancement de l'extraction des CVEs")
    extraction_CVE()

    # --- PARTIE 3 : ENRICHISSEMENT ---
    print("\n3. Lancement de l'enrichissement des CVEs")
    script_enrichissement = os.path.join("src", "enrichissement.py")
    subprocess.run([sys.executable, script_enrichissement], check=True)

    # --- PARTIE 6 : EMAILS ---
    print("\n3. Lancement de l'envoi des emails")
    script_mail = os.path.join("src", "mail.py")
    subprocess.run([sys.executable, script_mail], check=True)
    
    time.sleep(86400) # 86 400 s = 1 journée

