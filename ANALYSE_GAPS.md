# Analyse du Projet vs Cahier des Charges

## Résumé : 7/10 — Base solide, 3 points critiques à corriger

---

## État par Exigence du PDF

### 1. Collecte d'artefacts (PDF §4.1)
| Exigence | Statut | Preuve |
|----------|--------|--------|
| Processus | ✅ OK | `process_collector.py` — psutil, MD5/SHA256, flag processus suspects |
| Connexions réseau | ✅ OK | `network_collector.py` — ports, flags IP suspectes |
| Tâches planifiées | ✅ OK | `scheduled_tasks.py` — Windows schtasks + Linux crontab |
| Registry (Windows) | ✅ OK | `registry_collector.py` — Run, RunOnce, Winlogon, IFEO |
| Event Logs | ✅ OK | `eventlog_collector.py` — wevtutil + syslog |
| Linux | ✅ OK | `linux_collector.py` — /tmp, /dev/shm, users, SSH keys |
| **Sauvegarde en DB** | ❌ **NOK** | `_save_*` dans `collector_manager.py` sont vides (`pass`) |

### 2. Moteur de détection (PDF §4.2)
| Exigence | Statut | Preuve |
|----------|--------|--------|
| YARA | ✅ OK | `yara_engine.py` — compile .yar, scan fichiers + mémoire |
| Sigma | ✅ OK | `sigma_engine.py` — parse YAML, évalue conditions |
| IOC | ✅ OK | `ioc_engine.py` — hashs, IPs, domaines |
| Heuristique | ✅ OK | `heuristic_engine.py` — 150+ lignes, patterns suspects |
| **Fichiers YARA/Sigma/IOC sur disque** | ❌ **NOK** | Dossier `rules/` inexistant |

### 3. Mapping MITRE ATT&CK (PDF §4.3)
| Exigence | Statut | Preuve |
|----------|--------|--------|
| Tagging automatique | ✅ OK | `mapper.py` — map_alert() avec technique → tactic |
| Reconstruction kill chain | ⚠️ Partiel | timeline.py vide, pas de reconstitution temporelle |
| Visualisation | ✅ OK | `mitre.html` — grille tactique, coverage |
| Techniques JSON | ✅ OK | `techniques.json` — 30 techniques, 14 tactiques |

### 4. Reporting & Dashboard (PDF §4.4)
| Exigence | Statut | Preuve |
|----------|--------|--------|
| Dashboard web | ✅ OK | HTML + 1318 lignes CSS + Chart.js |
| Risk scoring | ✅ OK | `risk_scorer.py` — score 0-100, weighted |
| Rapport investigation | ⚠️ Partiel | `report_generator.py` existe mais données = [] |
| **API routes → vraies données** | ❌ **NOK** | Tous les endpoints retournent des données hardcodées |
| **Templates manquants** | ❌ **NOK** | hosts.html, investigations.html, reports.html, report_detail.html |
| **Export PDF** | ❌ **NOK** | weasyprint installé, route retourne "not implemented" |

### 5. Simulation d'attaques (PDF Objectif 5)
| Exigence | Statut | Preuve |
|----------|--------|--------|
| Scénarios réalistes | ❌ **NOK** | Aucun script d'attaque, aucun plan de test |
| Validation détection | ❌ **NOK** | Pas de lab automatisé |

### 6. Threat Hunting proactif (PDF Objectif 6)
| Exigence | Statut | Preuve |
|----------|--------|--------|
| Mode hunting | ⚠️ Partiel | HeuristicEngine peut servir de base |

### 7. Livrables (PDF §7)
| Livrable | Statut |
|----------|--------|
| Prototype fonctionnel | ⚠️ Partiel — tourne mais ne persiste pas les données |
| Règles YARA/Sigma documentées | ❌ Absent |
| Rapport d'incident MITRE | ❌ Absent |
| Rapport technique | ❌ Absent |
| Présentation soutenance | ✅ OK (Presentation_Soutenance_DFIR.md) |

---

## Synthèse des Gaps

### 🔴 Critiques (bloquent la démo fonctionnelle)

1. **Persistance DB vide** — Les collecteurs tournent, récupèrent les données, mais rien n'est écrit en base
2. **API routes hardcodées** — Le dashboard s'affiche mais avec des stats fictives
3. **Règles de détection absentes** — YARA, Sigma, IOC pointent vers des dossiers qui n'existent pas

### 🟡 Importants (pour un projet complet)

4. **Templates HTML manquants** — hosts.html, investigations.html, reports.html, report_detail.html
5. **Timeline d'attaque** — `timeline.py` retourne une liste vide
6. **Export PDF** — weasyprint installé mais pas branché

### 🟢 Options (pour impressionner)

7. **Scénarios d'attaque simulés** — scripts Kali Linux
8. **Mode temps réel** — WebSocket + collecte périodique
9. **IOC Feed automatique** — téléchargement depuis Abuse.ch/AlienVault

---

## Plan d'Action Prioritaire

### Étape 1 — Brancher la persistance DB (1 jour)
Implanter les méthodes `_save_processes()`, `_save_network()`, `_save_eventlogs()`, `_save_registry()`, `_save_scheduled_tasks()` dans `collector_manager.py` avec SQLAlchemy

### Étape 2 — Ajouter les règles de détection (1/2 jour)
```bash
mkdir rules\yara rules\sigma rules\iocs
# Télécharger les règles depuis GitHub
```

### Étape 3 — Connecter l'API à la DB (1 jour)
Remplacer les données hardcodées dans `app/api/routes/*.py` par des requêtes SQLAlchemy via `get_db()`

### Étape 4 — Créer les templates manquants (1/2 jour)
hosts.html, investigations.html, reports.html en copiant le style de dashboard.html

### Étape 5 — Tester avec un scénario d'attaque (1/2 jour)
Lancer PowerShell encodé, créer une clé de persistance, vérifier que le framework détecte
