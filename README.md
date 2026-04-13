🔍 Mini Network ScannerOutil de reconnaissance réseau — Pentest / Offensive SecurityPython 3 · Aucune dépendance · Kali Linux ready📋 DescriptionScanner réseau minimaliste développé pour simuler les fonctionnalités essentielles de Nmap sans aucune dépendance externe. Le script utilise les bibliothèques standards de Python pour effectuer des opérations de reconnaissance rapide :Découverte d'hôtes : Identification des machines actives sur une plage CIDR via ping sweep TCP.Scan de ports : Analyse multi-threadée des ports TCP.Banner Grabbing : Récupération des bannières pour l'identification des services.Estimation d'OS : Détection heuristique du système d'exploitation basée sur le TTL.Résolution DNS : Identification des noms d'hôtes (Reverse DNS).Export flexible : Sortie console formatée ou export JSON structuré.⚙️ UtilisationPrérequisPython 3.10 ou supérieur.Droits administrateur (recommandé sur Kali pour une meilleure précision du TTL).InstallationBashgit clone https://github.com/votre-repo/network-scanner.git
cd network-scanner
chmod +x network_scanner.py
Commandes usuellesBash# Scan par défaut (ports communs) sur une cible unique
python3 network_scanner.py -t 192.168.1.1

# Scan complet d'un sous-réseau avec 200 threads
python3 network_scanner.py -t 192.168.1.0/24 --threads 200

# Scan d'une plage de ports spécifique
python3 network_scanner.py -t 192.168.1.1 -p 1-1024

# Export des résultats au format JSON
python3 network_scanner.py -t 192.168.1.1 --json > rapport.json
🛠️ ParamètresParamètreDéfautDescription-t, --target(requis)IP unique ou plage CIDR (ex: 192.168.1.0/24)-p, --portscommonPlage (1-1024), liste (22,80), ou common--threads100Nombre de threads simultanés--timeout1.0Délai d'attente par port en secondes--jsonFalseActive la sortie au format JSON--no-discoveryFalseScanne les ports sans vérifier si l'hôte répond au ping🖥️ Exemple de sortiePlaintext═════════════════════════════════════════════════════════════════
  RAPPORT DE SCAN RÉSEAU
═════════════════════════════════════════════════════════════════

  Hôte   : 192.168.1.15  (workstation.local)
  OS     : Linux/macOS (TTL≤64)
  Scanné : 2026-04-14T00:12:45

  PORT     SERVICE            LATENCE  BANNER
  ────────────────────────────────────────────────────────────
  22       SSH                  2.4ms  SSH-2.0-OpenSSH_8.9p1
  80       HTTP                 1.1ms  HTTP/1.1 200 OK
  443      HTTPS                1.5ms 
  6379     Redis                0.9ms  redis_version:7.0.5

═════════════════════════════════════════════════════════════════
  Résumé : 1 hôte(s) scanné(s), 4 port(s) ouvert(s)
═════════════════════════════════════════════════════════════════
🔬 Comparaison TechniqueFonctionnalitéCe ScriptNmapScan TCP Connect✅✅Banner Grabbing✅✅Détection OS (TTL)✅✅Multi-threading✅✅Scan furtif (SYN)❌✅Scripting Engine (NSE)❌✅⚠️ Avertissement légalCet outil est destiné exclusivement à des fins éducatives et à des audits de sécurité autorisés. L'utilisateur est seul responsable de l'usage fait de ce script. Le scan de réseaux sans autorisation est illégal.
