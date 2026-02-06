import feedparser
import pandas as pd
import requests
import ssl
import time

# On ignore les erreurs de vérification de certificat
if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

# On génère un 1er fichier csv pour "capturer" les avis et les alertes afin de faire une seule requête d'extraction de la data
def extraction_flux_rss(): 

    sources = {
        "Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
        "Alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/"
    }

    data_rss = []
    
    for url in sources.values():
        time.sleep(1)
        rss_feed = feedparser.parse(url)

        # Boucle pour extraire les données
        for entry in rss_feed.entries:
            # On crée un dictionnaire pour chaque entrée (une ligne du csv)
            line = {
            "Titre": entry.title,
            "Description": entry.description,
            "Lien": entry.link,
            "Date": entry.published
            }
            data_rss.append(line)

    df = pd.DataFrame(data_rss)

    # Export vers un fichier CSV
    df.to_csv("../data/avis.csv", sep=';', index=False, encoding='utf-8')
    
def extraction_CVE():
    
    df_rss = pd.read_csv('../data/avis.csv', sep=';')
    
    data_with_cves = []
    
    for i, row in df_rss.iterrows():
    
        lien = row['Lien']
        url_json = lien + "json/"
        cves_data = []
        
        try:
            
            time.sleep(1) # pour éviter d'être bloqué
            
            response = requests.get(url_json, timeout=10)
            
            if response.status_code == 200:
                
                data_json = response.json()
                
                if "cves" in data_json:
                    cves_data = data_json["cves"]
                
        except Exception:
            pass
        
        # On copie la ligne originale
        new_row = row.to_dict()
                  
        if len(cves_data) > 0:
            # On stocke pour chaque avis/alertes la liste des CVE via une nouvelle colonne nommé "CVES"
            new_row['CVES'] = cves_data
            data_with_cves.append(new_row)
        else:
            # Si aucun CVE n'est trouvée
            new_row['CVES'] = []
            data_with_cves.append(new_row)        


    df_final = pd.DataFrame(data_with_cves)
    
    # Sauvegarde du fichier
    fichier_final = "../data/avis_avec_cve.csv"
    df_final.to_csv(fichier_final, sep=';', index=False, encoding='utf-8')
    print(f"Fichier généré : {fichier_final} ({len(df_final)} lignes)")
    
# Pour lancer les fonctions depuis main.py
if __name__ == "__main__":
    extraction_flux_rss()
    extraction_CVE()

#help(requests.get)



