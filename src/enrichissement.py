import pandas as pd
import ast
import requests
import time
import sys

INPUT_FILE = "../data/avis_avec_cve.csv"
OUTPUT_FILE = "../data/avis_avec_cve_enrichis.csv"
MITRE_API = "https://cveawg.mitre.org/api/cve/"
EPSS_API = "https://api.first.org/data/v1/epss"

session = requests.Session()

def get_bulletin_type(row):
    """Déduit le type avis ou alerte"""
    url = str(row.get('Lien', ''))
    titre = str(row.get('Titre', ''))
    if 'AVI' in url or 'avis' in titre.lower():
        return 'Avis'
    if 'ALE' in url or 'alerte' in titre.lower():
        return 'Alerte'
    return 'Autre'

def get_cve_data(cve_id):
    """Récupère données (CVSS, Vendor, Product, Versions)."""
    data = {
        'Description_CVE': 'Non disponible',
        'CVSS': None,
        'BaseSeverity': 'Non défini',
        'CWE': 'Non disponible',
        'Vendor': 'Inconnu',
        'Product': 'Inconnu',
        'Versions': 'Non spécifié'
    }
    
    try:
        response = session.get(f"{MITRE_API}{cve_id}", timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            cna = json_data.get("containers", {}).get("cna", {})
            
            # Description
            description = cna.get("descriptions", [])
            if description:
                data['Description_CVE'] = description[0].get("value", "Non disponible")
            
            # CVSS
            metrics = cna.get("metrics", [])
            for m in metrics:
                if "cvssV3_1" in m:
                    data['CVSS'] = m["cvssV3_1"].get("baseScore")
                    data['BaseSeverity'] = m["cvssV3_1"].get("baseSeverity")
                    break
                elif "cvssV3_0" in m:
                    data['CVSS'] = m["cvssV3_0"].get("baseScore")
                    data['BaseSeverity'] = m["cvssV3_0"].get("baseSeverity")
                    break
                elif "cvssV2_0" in m:
                    data['CVSS'] = m["cvssV2_0"].get("baseScore")
                    data['BaseSeverity'] = m["cvssV2_0"].get("baseSeverity", "Non défini")
                    break

            affected = cna.get("affected", [])
            vendors = set()
            products = set()
            versions_list = set()
            
            for item in affected:
                v = item.get("vendor", "n/a")
                p = item.get("product", "n/a")
                if v and v not in ["n/a", "N/A"]: vendors.add(v)
                if p and p not in ["n/a", "N/A"]: products.add(p)
                
                for ver in item.get("versions", []):
                    status = ver.get("status", "")
                    val = ver.get("version", "")
                    if status == "affected" and val and val not in ["n/a", "unspecified"]:
                        versions_list.add(val)

            if vendors: data['Vendor'] = ", ".join(vendors)
            if products: data['Product'] = ", ".join(products)
            if versions_list: 
                v_str = ", ".join(list(versions_list))
                data['Versions'] = (v_str[:250] + '...') if len(v_str) > 250 else v_str

            # CWE
            probs = cna.get("problemTypes", [])
            if probs:
                d = probs[0].get("descriptions", [])
                if d: data['CWE'] = d[0].get("cweId", "Non disponible")

    except Exception as e:
        print(f" Err {cve_id}: {e}")
        
    return data

def get_epss(cve_id):
    try:
        response = session.get(EPSS_API, params={'cve': cve_id}, timeout=5)
        if response.status_code == 200:
            d = response.json().get("data", [])
            if d: return float(d[0].get("epss", 0))
    except:
        pass
    return None

def parse_cves(x):
    try:
        return [i['name'] for i in ast.literal_eval(x)]
    except:
        return []

print(f"Chargement de {INPUT_FILE}")
df = pd.read_csv(INPUT_FILE, sep=';')

df['CVE_List'] = df['CVES'].apply(parse_cves)
df_exploded = df.explode('CVE_List').rename(columns={'CVE_List': 'CVE_ID'})
df_exploded = df_exploded.dropna(subset=['CVE_ID'])

unique_cves = df_exploded['CVE_ID'].unique()

enrichment_map = {}
print(f"Début enrichissement pour {len(unique_cves)} CVEs")

for i, cve in enumerate(unique_cves):
    info = get_cve_data(cve)
    info['EPSS'] = get_epss(cve)
    enrichment_map[cve] = info
    
    sys.stdout.write(f"\rTraitement {i+1}/{len(unique_cves)} - {cve}")
    sys.stdout.flush()
    time.sleep(2)

print("\nConsolidation :")
df_enrichis = pd.DataFrame.from_dict(enrichment_map, orient='index').reset_index()
df_enrichis.rename(columns={'index': 'CVE_ID'}, inplace=True)

final_df = pd.merge(df_exploded, df_enrichis, on='CVE_ID', how='inner') # on garde que ce qu'on a enrichi

# Nettoyage final
final_df['Type'] = final_df.apply(get_bulletin_type, axis=1)
final_df['Date'] = pd.to_datetime(final_df['Date'], utc=True)

cols = ['Titre', 'Type', 'Date', 'Lien', 'CVE_ID', 'CVSS', 'BaseSeverity', 
        'EPSS', 'CWE', 'Vendor', 'Product', 'Versions', 'Description_CVE']

#  si certaines colonnes ont des problèmes
existing_cols = [c for c in cols if c in final_df.columns]
final_df = final_df[existing_cols]

final_df.to_csv(OUTPUT_FILE, index=False, sep=';')
print(f"\nFichier généré : {OUTPUT_FILE}")