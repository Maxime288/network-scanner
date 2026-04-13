# 🔍 Mini Network Scanner

> Scanner réseau minimaliste développé pour des labs de sécurité offensive.  
> Reproduit les fonctionnalités essentielles de Nmap — **sans aucune dépendance externe**.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![Category](https://img.shields.io/badge/Category-Reconnaissance-e74c3c?style=flat-square)
![License](https://img.shields.io/badge/License-Educational%20Use-orange?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-none-2ecc71?style=flat-square)

---

## 📋 Description

Outil de reconnaissance réseau en Python pur, conçu pour des environnements de pentest et CTF. Il offre une alternative légère à Nmap pour les scénarios où seul Python est disponible.

**Fonctionnalités principales :**

- 🌐 **Découverte d'hôtes** — ping sweep TCP sur plage CIDR
- ⚡ **Scan TCP multi-threadé** — jusqu'à 200+ threads simultanés
- 🏷️ **Banner grabbing** — identification de services par signature
- 🖥️ **Fingerprinting OS** — heuristique basée sur le TTL
- 🔎 **Résolution DNS inverse** — hostname pour chaque hôte actif
- 📤 **Export JSON** — intégration dans des pipelines d'audit

---

## 📁 Structure du projet

```
Offensive-Security-Labs/
└── Pentest/
    └── docs/
        ├── README.md                ← ce fichier
        ├── Rapport_scanner.pdf      ← rapport technique complet
        └── network_scanner.py       ← script principal
```

---

## ⚙️ Installation & Utilisation

### Prérequis

```bash
python3 --version   # 3.10+ requis — aucune installation supplémentaire
```

### Cloner uniquement ce dossier (sparse-checkout)

```bash
git clone --no-checkout https://github.com/Maxime288/Offensive-Security-Labs.git
cd Offensive-Security-Labs
git sparse-checkout init --cone
git sparse-checkout set Pentest/docs
git checkout main

cd Pentest/docs/
python3 network_scanner.py --help
```

### Commandes

```bash
# Scan basique — ports courants
python3 network_scanner.py -t 192.168.1.1

# Scan d'un réseau entier
python3 network_scanner.py -t 192.168.1.0/24

# Plage de ports personnalisée
python3 network_scanner.py -t 192.168.1.1 -p 1-1024
python3 network_scanner.py -t 192.168.1.1 -p 22,80,443,3306,8080

# Export JSON
python3 network_scanner.py -t 192.168.1.1 --json > result.json

# Scan agressif (sudo recommandé sur Kali)
sudo python3 network_scanner.py -t 10.0.0.0/24 -p 1-1024 --threads 200 --timeout 0.5

# Ignorer le ping sweep (scan direct)
python3 network_scanner.py -t 192.168.1.1 --no-discovery -p common
```

### Paramètres

| Paramètre | Défaut | Description |
|---|---|---|
| `-t` / `--target` | *(requis)* | IP unique ou plage CIDR (ex: `192.168.1.0/24`) |
| `-p` / `--ports` | `common` | `1-1024`, `80,443`, `common` |
| `--threads` | `100` | Nombre de threads parallèles |
| `--timeout` | `1.0` | Timeout par port (secondes) |
| `--json` | `False` | Sortie au format JSON |
| `--no-discovery` | `False` | Ignorer le ping sweep initial |

---

## 🖥️ Exemple de sortie

```
═════════════════════════════════════════════════════════════════
  RAPPORT DE SCAN RÉSEAU
═════════════════════════════════════════════════════════════════

  Hôte   : 192.168.1.1  (router.local)
  OS     : Linux/macOS (TTL≤64)
  Scanné : 2025-04-13T14:32:01

  PORT     SERVICE            LATENCE  BANNER
  ────────────────────────────────────────────────────────────
  22       SSH                  3.2ms  SSH-2.0-OpenSSH_9.2p1
  80       HTTP                 1.8ms  HTTP/1.1 200 OK
  443      TLS/SSL              2.1ms
  3306     MySQL                5.1ms

═════════════════════════════════════════════════════════════════
  Résumé : 1 hôte(s) scanné(s), 4 port(s) ouvert(s)
═════════════════════════════════════════════════════════════════
```

---

## 🔬 Comparaison avec Nmap

| Fonctionnalité | Ce script | Nmap |
|---|:---:|:---:|
| Découverte d'hôtes TCP | ✅ | ✅ |
| Scan TCP connect | ✅ | ✅ |
| Banner grabbing | ✅ basique | ✅ avancé |
| Détection OS (TTL) | ✅ heuristique | ✅ fingerprinting complet |
| Résolution DNS inverse | ✅ | ✅ |
| Export JSON natif | ✅ | ⚙️ (via `-oJ`) |
| Scan SYN furtif | ❌ | ✅ |
| Scan UDP | ❌ | ✅ |
| Détection de versions | ❌ | ✅ |
| Scripts NSE | ❌ | ✅ |
| Dépendances externes | ❌ **aucune** | binaire natif |

---

## 🏗️ Architecture technique

Le script s'appuie exclusivement sur la bibliothèque standard Python :

- **`socket`** — connexions TCP, banner grabbing, TTL
- **`ipaddress`** — parsing et enumération des plages CIDR
- **`concurrent.futures.ThreadPoolExecutor`** — parallélisme du scan
- **`argparse`** — interface en ligne de commande
- **`json`** — sérialisation des résultats

La détection de service repose sur une table de signatures binaires (`SERVICE_SIGNATURES`) comparées aux premiers octets de la réponse brute. La découverte d'hôtes utilise un TCP connect sweep sur les ports 22, 80, 443 et 8080.

---

## 📄 Documentation

Le rapport technique complet est disponible dans [`Rapport_scanner.pdf`](Rapport_scanner.pdf).  
Il couvre l'architecture, les choix d'implémentation, les performances mesurées et les pistes d'évolution.

---

## ⚠️ Avertissement légal

Cet outil est destiné **exclusivement** à des usages légitimes dans des environnements contrôlés : labs isolés, CTF, audits internes autorisés, pentests contractuels.

> **Le scan de ports non autorisé est illégal.** N'utilise cet outil que sur des systèmes pour lesquels tu disposes d'une autorisation explicite.
