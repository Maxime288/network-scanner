# PyNet-Scanner Pro

> Scanner réseau haute performance développé pour les labs de sécurité offensive.  
> Python 3 · Aucune dépendance · Kali Linux ready

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![Version](https://img.shields.io/badge/Version-2.1-00bcd4?style=flat-square)
![Category](https://img.shields.io/badge/Category-Reconnaissance-e74c3c?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-none-2ecc71?style=flat-square)

```
  _____                _   _      _
 |  __ \              | \ | |    | |
 | |__) |   _ _ __    |  \| | ___| |_
 |  ___/ | | | '_ \   | . ` |/ _ \ __|
 | |   | |_| | | | |  | |\  |  __/ |_
 |_|    \__, |_| |_|  |_| \_|\___|\__|
          __/ |        Network Scanner Pro
         |___/         v2.1 - Security Labs
```

---

## Description

Scanner réseau en Python pur conçu pour des environnements de pentest et CTF. Offre une alternative légère à Nmap pour les scénarios où seul Python est disponible, avec une interface terminal soignée et une détection d'OS croisée.

**Fonctionnalités :**

- 🌐 **Découverte d'hôtes** — ping sweep TCP multi-threadé sur plage CIDR
- ⚡ **Scan TCP haute performance** — jusqu'à 200+ threads simultanés
- 🏷️ **Banner grabbing** — identification de services par réponse brute
- 🖥️ **Détection OS avancée** — croisement TTL + heuristique par ports
- 🔎 **Résolution DNS inverse** — hostname pour chaque hôte actif
- 📊 **Barre de progression en temps réel** — affichage pourcentage + phase
- 🎨 **Couleurs 256 ANSI** — rapport coloré par type de service
- 📤 **Export JSON** — intégration dans des pipelines d'audit

---

## Installation

```bash
git clone https://github.com/Maxime288/network-scanner.git
cd network-scanner
python3 --version   # 3.10+ requis — aucune dépendance supplémentaire
```

---

## Utilisation

```bash
# Scan basique (ports courants)
python3 network_scanner.py -t 192.168.1.1

# Scan d'un réseau entier
python3 network_scanner.py -t 192.168.1.0/24

# Plage de ports personnalisée
python3 network_scanner.py -t 192.168.1.1 -p 1-1024
python3 network_scanner.py -t 192.168.1.1 -p 22,80,443,3306

# Export JSON
python3 network_scanner.py -t 192.168.1.1 --json > result.json

# Scan rapide sans discovery (cible directe)
python3 network_scanner.py -t 192.168.1.1 --no-discovery -p common

# Mode silencieux (sans couleurs ANSI)
python3 network_scanner.py -t 192.168.1.1 --no-color
```

### Paramètres

| Paramètre | Défaut | Description |
|---|---|---|
| `-t` / `--target` | *(requis)* | IP unique ou plage CIDR |
| `-p` / `--ports` | `common` | `1-1024`, `22,80,443`, `common` |
| `--threads` | `100` | Threads parallèles |
| `--timeout` | `1.0` | Timeout par port (secondes) |
| `--json` | `False` | Sortie JSON brute |
| `--no-discovery` | `False` | Ignorer le ping sweep |
| `--no-color` | `False` | Désactiver les couleurs ANSI |

---

## Exemple de sortie

```
  _____                _   _      _
 |  __ \              | \ | |    | |
 | |__) |   _ _ __    |  \| | ___| |_
 |  ___/ | | | '_ \   | . ` |/ _ \ __|
 | |   | |_| | | | |  | |\  |  __/ |_
 |_|    \__, |_| |_|  |_| \_|\___|\__|
          __/ |        Network Scanner Pro
         |___/         v2.1 - Security Labs

  Discovery       ▕━━━━━━━━━━━━━━━━━━━━▏ 100%
  Scan 192.168.1.1▕━━━━━━━━━━━━━━━━━━━━▏ 100%

  IP: 192.168.1.1
  Hostname : router.local
  OS Guess : 🐧 Linux/macOS
  ─────────────────────────────────────────────────────────────────
  PORT     SERVICE         LATENCE    BANNER
  22       SSH               3.2ms    » SSH-2.0-OpenSSH_9.2p1
  80       HTTP              1.8ms    » HTTP/1.1 200 OK
  443      HTTPS             2.1ms
  3306     MySQL             5.1ms

📊 Résumé du scan : 1 hôte(s) trouvé(s).
Terminé en 2.14s
```

---

## Détection d'OS

La détection repose sur deux méthodes croisées :

1. **Heuristique par ports** — présence de ports Windows spécifiques (135, 139, 445, 3389) → identification immédiate sans ambiguïté
2. **TTL fingerprinting** — lecture du TTL du paquet retour via `getsockopt` : ≤ 64 → Linux/macOS, ≤ 128 → Windows, > 128 → équipement réseau

---

## Comparaison avec Nmap

| Fonctionnalité | PyNet-Scanner | Nmap |
|---|:---:|:---:|
| Découverte d'hôtes TCP | ✅ | ✅ |
| Scan TCP connect | ✅ | ✅ |
| Banner grabbing | ✅ | ✅ avancé |
| Détection OS (TTL + ports) | ✅ | ✅ fingerprinting complet |
| Résolution DNS inverse | ✅ | ✅ |
| Export JSON natif | ✅ | ⚙️ via `-oJ` |
| Bannière ASCII + couleurs 256 | ✅ | ❌ |
| Barre de progression | ✅ | ❌ |
| Scan SYN furtif | ❌ | ✅ |
| Scan UDP | ❌ | ✅ |
| Scripts NSE | ❌ | ✅ |
| Dépendances externes | ❌ **aucune** | binaire natif |

---

## Architecture

Le script s'appuie exclusivement sur la bibliothèque standard Python :

- **`socket`** — connexions TCP, banner grabbing, TTL via `getsockopt`
- **`ipaddress`** — parsing et énumération des plages CIDR
- **`concurrent.futures.ThreadPoolExecutor`** — parallélisme du scan et du ping sweep
- **`argparse`** — interface CLI complète
- **`json`** — sérialisation des résultats

---

## ⚠️ Avertissement légal

Cet outil est destiné **exclusivement** à des usages légitimes dans des environnements contrôlés : labs isolés, CTF, audits internes autorisés, pentests contractuels.

> **Le scan de ports non autorisé est illégal.** N'utilise cet outil que sur des systèmes pour lesquels tu disposes d'une autorisation explicite.
