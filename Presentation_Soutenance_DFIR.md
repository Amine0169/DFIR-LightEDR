# Présentation de Stage — Design and Implementation of a Lightweight DFIR and Threat Hunting Framework for Endpoint Investigation

---

## Slide 1 — Contexte & Motivation : Pourquoi la DFIR aujourd'hui ?

- **Cybermenaces en explosion** : volume et sophistication croissants (ransomware, APT, supply chain)
- **Détection seule insuffisante** : un SIEM qui alerte ne dit pas *quoi s'est passé, comment, et jusqu'où*
- **Passage nécessaire de la détection → l'investigation** : reconstruire la chronologie, comprendre le comportement attaquant, contenir l'impact
- **Pénurie de compétences Blue Team** : les organisations ont besoin de profs capables de *chasser* les menaces, pas seulement d'attendre des alertes
- **Le Blue Team a besoin d'outils légers, automatisés, reproductibles** — pas de solutions lourdes inaccessibles

> *Transition : C'est exactement là que s'inscrit ce sujet de stage…*

---

## Slide 2 — Sujet du Stage : Le framework en une slide

> **Design and Implementation of a Lightweight DFIR and Threat Hunting Framework for Endpoint Investigation**

- **Objectif unique** : Concevoir et développer un framework automatisé, open-source et léger qui collecte les artefacts endpoints, détecte les IOC, cartographie les attaques via MITRE ATT&CK et produit des rapports d'investigation structurés
- **Cible** : Systèmes Windows et Linux
- **Approche** : outillage pratique + méthodologie d'investigation reproductible
- **Résultat** : un prototype fonctionnel ET un processus documenté

> *Transition : Pour y parvenir, nous avons défini 6 objectifs concrets…*

---

## Slide 3 — Objectifs Détaillés

1. **Collecte d'artefacts** — Extraire automatiquement processus, connexions réseau, tâches planifiées, clés de persistance Registry (Windows), journaux de sécurité et logs système
2. **Détection IOC via YARA / Sigma** — Intégrer YARA pour la détection de fichiers malveillants et Sigma pour la détection comportementale sur les logs
3. **Mapping MITRE ATT&CK** — Étiqueter chaque comportement détecté avec sa technique ATT&CK, reconstituer la chaîne d'attaque
4. **Génération de rapports automatisée** — Produire des rapports d'investigation clairs, avec niveaux de risque et actions recommandées
5. **Simulation d'attaques** — Valider les capacités de détection via des scénarios réalistes en laboratoire
6. **Threat Hunting proactif** — Développer des méthodes de chasse aux menaces transposables en environnement professionnel

> *Transition : Ces objectifs se concrétisent dans une architecture modulaire…*

---

## Slide 4 — Architecture du Framework

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │                  LIGHTWEIGHT DFIR FRAMEWORK                         │
 ├───────────────┬────────────────┬─────────────────┬──────────────────┤
 │   MODULE 1    │   MODULE 2     │    MODULE 3     │    MODULE 4      │
 │  COLLECTE     │  DÉTECTION &   │   MAPPING       │  REPORTING &     │
 │  D'ARTEFACTS  │  ANALYSE       │  MITRE ATT&CK   │  DASHBOARD       │
 ├───────────────┼────────────────┼─────────────────┼──────────────────┤
 │ • Processus   │ • YARA rules   │ • TTP tagging   │ • Rapport PDF    │
 │ • Connexions  │ • Sigma rules  │ • Reconstruction│ • Dashboard web  │
 │ • Tâches      │ • IOC          │   de la kill    │ • Niveau de      │
 │ • Registry    │   correlation  │   chain         │   risque         │
 │ • Event logs  │ • Corrélation  │ • Visualisation │ • Recommandations│
 ├───────────────┼────────────────┼─────────────────┼──────────────────┤
 │  Python       │  YARA / Sigma  │  MITRE ATT&CK   │  Flask/FastAPI   │
 │  Sysmon       │  IOC sources   │  JSON mapping   │  SQLite          │
 │  Agent custom │                │                 │  Chart.js        │
 └──────┬────────┴───────┬────────┴────────┬────────┴────────┬─────────┘
        │                │                 │                 │
        └──────► Données brutes ──► Comportements ──► Tactiques ──► Rapports
                 (logs, fichiers)   (IOC matchés)    (techniques)    (décision)
```

- **Flux de données** : Artefacts bruts → analyses YARA/Sigma → techniques ATT&CK identifiées → rapport consolidé
- **Stockage central** : SQLite — léger, embarqué, sans dépendance serveur
- **Interface** : Flask ou FastAPI — API REST + dashboard web léger

> *Transition : Ce framework est conçu pour reconstituer l'intégralité de la kill chain d'un attaquant…*

---

## Slide 5 — Kill Chain & Méthodologie de Détection

Basée sur la **Cyber Kill Chain** (Lockheed Martin) + **MITRE ATT&CK** :

| Phase Kill Chain | Traduction Technique | Artefacts / Règles | Techniques ATT&CK |
|-----------------|---------------------|-------------------|-------------------|
| **1. Reconnaissance** | Scan réseau, collecte d'infos | Logs réseau, connexions sortantes | T1592, T1595 |
| **2. Weaponization** | (Hors scope — phase pré-compromission) | — | — |
| **3. Delivery** | Téléchargement malveillant, phishing | YARA sur fichiers entrants, event logs | T1566, T1204 |
| **4. Exploitation** | Exécution de code, privilege escalation | Sigma sur Event ID 4688, 4672 | T1059, T1068 |
| **5. Installation** | Persistance (Registry, services, tasks) | Registry keys, scheduled tasks, services | T1547, T1053 |
| **6. C2 (Command & Control)** | Connexions sortantes, beaconing | Netstat, DNS logs, Sigma network rules | T1071, T1573 |
| **7. Actions on Objectives** | Exfiltration, chiffrement, impact | Sysmon ProcessAccess, file creation events | T1485, T1560, T1486 |

- Le framework **reconstitue la séquence temporelle** des techniques détectées
- Chaque phase correspond à des **règles YARA/Sigma spécifiques** dans la base
- Le mapping ATT&CK permet de **visualiser la progression** de l'attaque

> *Transition : Pour implémenter tout cela, nous utilisons une stack technique éprouvée…*

---

## Slide 6 — Outils & Technologies : Stack Technique

| Outil | Rôle dans le projet |
|-------|-------------------|
| **Python** | Langage central du framework — agent de collecte, moteur de détection, API, tout est en Python |
| **Sysmon** | Fournisseur de données clé — logs détaillés de processus, connexions réseau, création de fichiers (Event ID 1, 3, 11, etc.) |
| **YARA** | Détection de malwares et fichiers suspects — pattern matching binaire/signature sur les artefacts collectés |
| **Sigma** | Détection comportementale — règles génériques traduisibles en requêtes sur les logs Windows/Sysmon |
| **KAPE** | Concepts de collecte forensique — référence méthodologique pour savoir *quoi* collecter et *dans quel ordre* |
| **Velociraptor** | Concepts d'interrogation live — références architecturales pour l'agent de collecte |
| **MITRE ATT&CK** | Taxonomie de référence — mapping automatique technique → tactique pour contextualiser les alertes |
| **SQLite** | Base de données embarquée — stockage des artefacts, des résultats d'analyse, des rapports (zéro configuration) |
| **Flask / FastAPI** | Interface de visualisation — dashboard web léger pour consulter les résultats et générer les rapports |

> *Transition : Voici comment nous organiserons le travail dans le temps…*

---

## Slide 7 — Timeline / Phases du Projet

| Phase | Durée (indicative) | Activités | Livrable intermédiaire |
|-------|-------------------|-----------|----------------------|
| **Phase 1 : Foundations** | Semaine 1-2 | Étude artefacts Windows/Linux, configuration Sysmon, baseline comportement normal | Document de référence des artefacts + config Sysmon |
| **Phase 2 : Artifact Collection** | Semaine 3-5 | Développement de l'agent de collecte automatisé (processus, logs, Registry, réseau) | Moteur de collecte fonctionnel + tests unitaires |
| **Phase 3 : Detection Engineering** | Semaine 6-8 | Intégration YARA/Sigma, corrélation IOC, mapping MITRE ATT&CK | Moteur de détection + base de règles documentée |
| **Phase 4 : Reporting & Validation** | Semaine 9-10 | Dashboard, génération de rapports, simulation d'attaques en lab, documentation | Prototype final + rapport technique + soutenance |

> *Transition : Ces phases produisent 5 livrables concrets…*

---

## Slide 8 — Livrables Finaux Attendus

1. **Un prototype fonctionnel** du framework DFIR et Threat Hunting
2. **Une base de règles YARA et Sigma documentée**, taillée pour l'investigation endpoint
3. **Un rapport d'incident complet**, basé sur des scénarios d'attaque simulés, avec mapping MITRE ATT&CK
4. **Un rapport technique** décrivant la méthodologie, les résultats et les leçons apprises
5. **Une présentation de soutenance** — celle que vous êtes en train de voir

> *Transition : Pour conclure, ce stage n'est pas seulement un projet technique…*

---

## Slide 9 — Conclusion : Valeur Ajoutée & Compétences Démontrées

À l'issue du stage, le stagiaire aura démontré :

| Compétence | Preuve concrète |
|-----------|----------------|
| **Développement Python** | Framework complet, agent de collecte, API, dashboard |
| **Forensique endpoint** | Connaissance des artefacts Windows/Linux, analyse de logs |
| **Détection & Threat Hunting** | Règles YARA/Sigma écrites et validées, chasse proactive |
| **Cybersécurité offensive/défensive** | Simulation d'attaques, compréhension des TTP adversaires |
| **Cartographie MITRE ATT&CK** | Structuration d'alertes en intelligence actionnable |
| **Communication technique** | Rapports structurés, présentation orale, documentation |

- **Projet transférable** : le framework pourra être réutilisé, amélioré, et déployé
- **Double compétence** : développeur sécurité ET analyste Blue Team
- **Méthodologie professionnelle** : veille IOC, gestion de règles, documentation de processus

---

**Fin de la présentation — Questions ?**
