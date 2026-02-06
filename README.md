# Projet Python - Analyse des vulnérabilités publiées par l'ANSSI

## Description du projet

L'objectif est d'automatiser la veille en cybersécurité en récupérant les données brutes sur l'ANSSI. Ensuite on les enrichis avec les APIs MITRE et FIRST pour produire des visualisations exploitables sur un Notebook.

Voici la liste des étapes :
1.  **Extraction** : Récupération automatique des flux RSS (Avis et Alertes) de l'ANSSI.
2.  **Traitement** : Identification des codes CVE et extraction des URLs associées.
3.  **Enrichissement** : Utilisation des API MITRE et FIRST pour récupérer :
    * Les scores CVSS (Gravité).
    * Les scores EPSS (Probabilité d'exploitation).
    * Les produits et versions affectés (Vendor/Product).
    * Le type de faille (CWE).
4.  **Visualisation** : Analyse graphique des données via un Notebook Jupyter.

---

## Architecture du projet

```text
│
├── data/                   # Stockage des données (CSV)
│   ├── avis.csv                    # Données brutes issues du RSS (Avis & Alertes)
│   ├── avis_avec_cve.csv           # Avis & Alertes + CVEs
│   └── avis_avec_cve_enrichis.csv  # Données finales enrichies (API MITRE & FIRST) et consolidées
│
├── src/                    # Code source des modules
│   ├── extraction.py       # Récupère les données de l'ANSSI
│   ├── enrichissement.py   # Enrichis les données CVE
│   └── mail.py             # Gestion des notifications
│
├── main.py                 # Lance l'extraction puis l'enrichissement
├── Notebook.ipynb          # Visualisation des données (Graphiques CVSS, CWE...)
├── requirements.txt        # Liste des librairies Python nécessaires
└── README.md               # Documentation du projet
# Projet-Python-3A
