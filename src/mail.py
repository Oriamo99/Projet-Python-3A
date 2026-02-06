import smtplib
import pandas as pd
from email.mime.text import MIMEText
from datetime import date


#%% Récupération des données

ajd = date.today()
#print(ajd)

df = pd.read_csv('../data/avis_avec_cve_enrichis.csv',sep=";")
columns=df.columns
df["Date"] = pd.to_datetime(df["Date"], utc=True).dt.date
#print(df["Date"])

donnees=list(df["Date"]==date(2023, 10, 17)) #ajd
print(donnees)

c=donnees.count(True)
'''
for d in df["Date"]:
    print(d)
    if d == date(2026, 1, 2):
        print("yess")
    else:
        print("no")
'''
print("Nombre de vulnérabilités détectées aujourd'hui : ", c)
indexes = df[df["Date"] == date(2023, 10, 17)].index  #ajd    date(2026, 1, 2)
print(indexes)
#print(columns)

#%% Fonction d'envoi

def send_email(to_email, subject, body):
    from_email = "u3921308154@gmail.com"
    password = "xfye duzc mwnr dtla" #ikJ!EM%$Gka>'3}
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()
    
#↨send_email("binopa1489@cucadas.com", "Alerte CVE critique", "Mettez à jour votre serveur Apache immédiatement.")

#%% Critères d'envoi et envoi

for i in indexes:
    
    Titre=df.iloc[i,0]
    print(i,"=",Titre)
    
    Lien=df.iloc[i,3]
    print(i,"=",Lien)
    
    Identifiant=df.iloc[i,4]
    print(i,"=",Identifiant)
    
    CWE=df.iloc[i,8]
    print(i,"=",CWE)
    
    Vendor=df.iloc[i,9]
    print(i,"=",Vendor)
    
    Product=df.iloc[i,10]
    print(i,"=",Product)
    
    Versions=df.iloc[i,11]
    print(i,"=",Versions)
    
    Détails=df.iloc[i,12]
    print(i,"=",Détails)
    
    BaseSeverity=df.iloc[i, 6]
    match BaseSeverity:
        case "LOW":
            BaseSeverity='MINEURE'
        case "MEDIUM":
            BaseSeverity='IMPORTANTE'
        case "HIGH":
            BaseSeverity='MAJEURE'
        case "CRITICAL":
            BaseSeverity="CRITIQUE"
    print(i,"=",BaseSeverity)
    
    
    match Vendor:
        case "Meta":
            if BaseSeverity=='MAJEURE' or BaseSeverity=="CRITIQUE":
                send_email("u3921308154+user1@gmail.com", 
                           f"Alerte CVE {BaseSeverity}", 
                           f"Bonjour,\n\n"
                           f"Une vulnérabilité a été détectée sur votre produit '{Product}' pour la/les version.s {Versions}.\n\n"
                           f"Description : {Titre}\n"
                           f"Identifiant : {Identifiant}\n"
                           f"Catégorie de la vulnérabilité : {CWE}\n"
                           f"Détails : {Détails}\n\n"
                           f"Pour plus d'informations, veuillez consulter ce lien {Lien}")
        case "Fortinet":
            if BaseSeverity=='MAJEURE' or BaseSeverity=="CRITIQUE":
                send_email("u3921308154+user2@gmail.com", 
                           f"Alerte CVE {BaseSeverity}", 
                           f"Bonjour,\n\n"
                           f"Une vulnérabilité a été détectée sur votre produit '{Product}' pour la/les version.s {Versions}.\n\n"
                           f"Description : {Titre}\n"
                           f"Identifiant : {Identifiant}\n"
                           f"Catégorie de la vulnérabilité : {CWE}\n"
                           f"Détails : {Détails}\n\n"
                           f"Pour plus d'informations, veuillez consulter ce lien {Lien}")
        case "Ivanti":
            if BaseSeverity=='MAJEURE' or BaseSeverity=="CRITIQUE":
                send_email("u3921308154+user3@gmail.com", 
                           f"Alerte CVE {BaseSeverity}", 
                           f"Bonjour,\n\n"
                           f"Une vulnérabilité a été détectée sur votre produit '{Product}' pour la/les version.s {Versions}.\n\n"
                           f"Description : {Titre}\n"
                           f"Identifiant : {Identifiant}\n"
                           f"Catégorie de la vulnérabilité : {CWE}\n"
                           f"Détails : {Détails}\n\n"
                           f"Pour plus d'informations, veuillez consulter ce lien {Lien}")
        case "Cisco":
            if BaseSeverity=='MAJEURE' or BaseSeverity=="CRITIQUE":
                send_email("u3921308154+user4@gmail.com", 
                           f"Alerte CVE {BaseSeverity}", 
                           f"Bonjour,\n\n"
                           f"Une vulnérabilité a été détectée sur votre produit '{Product}' pour la/les version.s {Versions}.\n\n"
                           f"Description : {Titre}\n"
                           f"Identifiant : {Identifiant}\n"
                           f"Catégorie de la vulnérabilité : {CWE}\n"
                           f"Détails : {Détails}\n\n"
                           f"Pour plus d'informations, veuillez consulter ce lien {Lien}")

#if df[(df["BaseSeverity"]=="HIGH") & (df["CVSS"]>=8)]:
#    send_email("binopa1489@cucadas.com", "Alerte CVE critique", "Mettez à jour votre serveur Apache immédiatement.")

        


