# 🔍 Mini Network Scanner

> Outil de reconnaissance réseau — Pentest / Offensive Security  
> Python 3 · Aucune dépendance · Kali Linux ready

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)
![Category](https://img.shields.io/badge/Category-Reconnaissance-red)
![Dependencies](https://img.shields.io/badge/Dependencies-none-brightgreen)

---

## 📋 Description

Scanner réseau minimaliste développé dans le cadre de labs de sécurité offensive. Reproduit les fonctionnalités essentielles de Nmap sans dépendance externe :

- **Découverte d'hôtes actifs** sur une plage CIDR via un balayage TCP.
- **Scan de ports TCP** multi-threadé pour une exécution rapide.
- **Banner grabbing** et identification de services (SSH, HTTP, FTP, Redis, etc.).
- **Estimation du système d'exploitation** via l'analyse du TTL (fingerprinting heuristique).
- **Résolution DNS inverse** (Hostname lookup).
- **Export JSON** pour intégration dans des rapports ou pipelines d'audit.

---

## 📁 Structure

```text
Offensive-Security-Labs/
└── Pentest/
    └── docs/
        ├── README.md                ← ce fichier
        └── network_scanner.py       ← script principal
⚙️ UtilisationPrérequisBashpython3 --version   # Python 3.10+ recommandé
# Aucune installation supplémentaire nécessaire (librairies standards uniquement)
InstallationBashgit clone [https://github.com/votre-repo/Offensive-Security-Labs.git](https://github.com/votre-repo/Offensive-Security-Labs.git)
cd Offensive-Security-Labs/Pentest/docs/
chmod +x network_scanner.py
CommandesBash# Scan basique (ports courants) sur une IP cible
python3 network_scanner.py -t 192.168.1.1

# Scan d'un réseau entier (CIDR)
python3 network_scanner.py -t 192.168.1.0/24

# Scan de ports personnalisés (plage ou liste)
python3 network_scanner.py -t 192.168.1.1 -p 1-1024
python3 network_scanner.py -t 192.168.1.1 -p 22,80,443,3306

# Export JSON
python3 network_scanner.py -t 192.168.1.1 --json > result.json

# Scan rapide (Threads augmentés et timeout réduit)
python3 network_scanner.py -t 10.0.0.0/24 -p 1-1024 --threads 200 --timeout 0.5
🛠️ ParamètresParamètreDéfautDescription-t / --target(requis)IP unique ou plage CIDR (ex: 192.168.1.0/24)-p / --portscommonPlage 1-1024, liste 80,443, ou common--threads100Nombre de threads en parallèle--timeout1.0Temps d'attente par port en secondes--json—Sortie brute au format JSON uniquement--no-discovery—Ignorer l'étape de ping sweep (scan direct)🖥️ Exemple de sortiePlaintext═════════════════════════════════════════════════════════════════
  RAPPORT DE SCAN RÉSEAU
═════════════════════════════════════════════════════════════════

  Hôte   : 192.168.1.1  (router.local)
  OS     : Linux/macOS (TTL≤64)
  Scanné : 2026-04-14T14:32:01

  PORT     SERVICE            LATENCE  BANNER
  ────────────────────────────────────────────────────────────
  22       SSH                  3.2ms  SSH-2.0-OpenSSH_9.2p1
  80       HTTP                 1.8ms  HTTP/1.1 200 OK
  443      TLS/SSL              2.1ms
  3306     MySQL                5.1ms

═════════════════════════════════════════════════════════════════
  Résumé : 1 hôte(s) scanné(s), 4 port(s) ouvert(s)
═════════════════════════════════════════════════════════════════
🔬 Comparaison avec NmapFonctionnalitéCe scriptNmapDécouverte d'hôtes TCP✅✅Scan TCP Connect✅✅Banner grabbing✅✅Détection OS (TTL)✅✅Scan SYN (Stealth)❌✅Scan UDP❌✅Dépendances externes❌✅⚠️ Avertissement légalCet outil est destiné exclusivement à des usages légitimes dans des environnements contrôlés (labs isolés, CTF, audits internes autorisés). Le scan de ports non autorisé est illégal. Utilisez cet outil uniquement sur des systèmes dont vous avez l'autorisation explicite.
