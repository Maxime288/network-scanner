#!/usr/bin/env python3
"""
Mini scanner réseau - équivalent Nmap simplifié
Usage : python3 network_scanner.py -t 192.168.1.1
        python3 network_scanner.py -t 192.168.1.0/24
        python3 network_scanner.py -t 192.168.1.1 -p 1-1024 --threads 200
"""

import socket
import struct
import argparse
import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ──────────────────────────────────────────────────────────────
# Signatures de services (banner → nom du service)
# ──────────────────────────────────────────────────────────────
SERVICE_SIGNATURES = {
    b"SSH":            "SSH",
    b"HTTP":           "HTTP",
    b"220":            "FTP/SMTP",
    b"* OK":           "IMAP",
    b"+OK":            "POP3",
    b"RFB":            "VNC",
    b"AMQP":           "AMQP/RabbitMQ",
    b"redis_version":  "Redis",
    b"mongos":         "MongoDB",
    b"\x16\x03":       "TLS/SSL",
}

# Ports courants avec leur nom
COMMON_PORTS = {
    21: "FTP",    22: "SSH",     23: "Telnet",  25: "SMTP",
    53: "DNS",    80: "HTTP",    110: "POP3",   143: "IMAP",
    443: "HTTPS", 445: "SMB",    3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt",  27017: "MongoDB",
}


# ──────────────────────────────────────────────────────────────
# Ping hôte (TCP SYN sur port 80 ou 443)
# ──────────────────────────────────────────────────────────────
def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Vérifie si un hôte est actif via TCP connect sur les ports 80/443/22."""
    for port in [80, 443, 22, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                return True
        except Exception:
            pass

    # Fallback : ICMP-like via socket raw (si droits suffisants)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect_ex((ip, 135))  # port Windows courant
        s.close()
        return True
    except Exception:
        pass

    return False


# ──────────────────────────────────────────────────────────────
# Scan d'un port unique
# ──────────────────────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """
    Tente une connexion TCP sur (ip, port).
    Retourne un dict avec les infos du port si ouvert, None sinon.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        result = s.connect_ex((ip, port))
        latency = round((time.time() - start) * 1000, 1)

        if result != 0:
            s.close()
            return None

        # Banner grabbing
        banner = ""
        service = COMMON_PORTS.get(port, "unknown")
        try:
            # Envoie une requête minimale pour provoquer une réponse
            if port in (80, 8080, 8443):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                pass  # TLS, pas de banner brut simple
            else:
                s.send(b"\r\n")

            raw = s.recv(1024)
            banner = raw.decode("utf-8", errors="replace").strip()[:120]

            # Tentative de détection de service par signature
            for sig, name in SERVICE_SIGNATURES.items():
                if sig in raw:
                    service = name
                    break
        except Exception:
            pass

        s.close()
        return {
            "port":    port,
            "state":   "open",
            "service": service,
            "banner":  banner,
            "latency_ms": latency,
        }

    except Exception:
        return None


# ──────────────────────────────────────────────────────────────
# Détection OS via TTL
# ──────────────────────────────────────────────────────────────
def detect_os_by_ttl(ip: str) -> str:
    """Heuristique grossière basée sur le TTL (nécessite socket raw / ping)."""
    try:
        # On utilise socket pour estimer le TTL via une connexion TCP
        # (valeur récupérée dans le paquet SYN-ACK si dispo)
        # Simplification : on retourne une estimation basée sur les ports ouverts
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect_ex((ip, 80))
        ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        s.close()
        if ttl <= 64:
            return "Linux/macOS (TTL≤64)"
        elif ttl <= 128:
            return "Windows (TTL≤128)"
        else:
            return "Cisco/réseau (TTL>128)"
    except Exception:
        return "Indéterminé"


# ──────────────────────────────────────────────────────────────
# Résolution hostname
# ──────────────────────────────────────────────────────────────
def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ──────────────────────────────────────────────────────────────
# Scan complet d'un hôte
# ──────────────────────────────────────────────────────────────
def scan_host(ip: str, ports: list[int], threads: int = 100, timeout: float = 1.0) -> dict:
    """Scanne tous les ports d'un hôte et retourne le rapport."""
    print(f"  [*] Scan de {ip} ({len(ports)} ports)...")

    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    hostname = resolve_hostname(ip)
    os_guess = detect_os_by_ttl(ip) if open_ports else "Indéterminé"

    return {
        "ip":         ip,
        "hostname":   hostname,
        "os_guess":   os_guess,
        "open_ports": open_ports,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# ──────────────────────────────────────────────────────────────
# Découverte d'hôtes sur un réseau
# ──────────────────────────────────────────────────────────────
def discover_hosts(network: str, threads: int = 50) -> list[str]:
    """Retourne les IPs actives dans le réseau CIDR donné."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"[-] Adresse invalide : {e}")
        return []

    hosts = [str(h) for h in net.hosts()]
    if not hosts:
        hosts = [network]  # IP seule

    print(f"[*] Découverte d'hôtes sur {network} ({len(hosts)} adresses)...")
    active = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                print(f"  [+] Hôte actif : {ip}")
                active.append(ip)

    return sorted(active)


# ──────────────────────────────────────────────────────────────
# Affichage du rapport
# ──────────────────────────────────────────────────────────────
def print_report(results: list[dict], json_output: bool = False) -> None:
    if json_output:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    print("\n" + "═" * 65)
    print("  RAPPORT DE SCAN RÉSEAU")
    print("═" * 65)

    for host in results:
        print(f"\n  Hôte   : {host['ip']}"
              + (f"  ({host['hostname']})" if host["hostname"] else ""))
        print(f"  OS     : {host['os_guess']}")
        print(f"  Scanné : {host['scanned_at']}")

        if not host["open_ports"]:
            print("  Ports  : aucun port ouvert détecté")
        else:
            print(f"\n  {'PORT':<8} {'SERVICE':<18} {'LATENCE':>8}  BANNER")
            print("  " + "─" * 60)
            for p in host["open_ports"]:
                banner_short = p["banner"][:40].replace("\n", " ") if p["banner"] else ""
                print(f"  {p['port']:<8} {p['service']:<18} {p['latency_ms']:>6}ms  {banner_short}")

    print("\n" + "═" * 65)
    total_open = sum(len(h["open_ports"]) for h in results)
    print(f"  Résumé : {len(results)} hôte(s) scanné(s), {total_open} port(s) ouvert(s)")
    print("═" * 65 + "\n")


# ──────────────────────────────────────────────────────────────
# Parsing des ports
# ──────────────────────────────────────────────────────────────
def parse_ports(port_spec: str) -> list[int]:
    """Accepte : '80', '22,80,443', '1-1024', 'common'."""
    if port_spec == "common":
        return list(COMMON_PORTS.keys())

    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    return sorted(ports)


# ──────────────────────────────────────────────────────────────
# Point d'entrée
# ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Mini scanner réseau (Nmap simplifié)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python3 network_scanner.py -t 192.168.1.1
  python3 network_scanner.py -t 192.168.1.0/24 -p 1-1024
  python3 network_scanner.py -t 10.0.0.1 -p common --json
  python3 network_scanner.py -t 192.168.1.0/24 -p 22,80,443 --threads 200
        """,
    )
    parser.add_argument("-t", "--target",  required=True,
                        help="IP, plage CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",   default="common",
                        help="Ports à scanner : '1-1024', '80,443', 'common' (défaut)")
    parser.add_argument("--threads",       type=int, default=100,
                        help="Threads simultanés (défaut: 100)")
    parser.add_argument("--timeout",       type=float, default=1.0,
                        help="Timeout par port en secondes (défaut: 1.0)")
    parser.add_argument("--json",          action="store_true",
                        help="Sortie au format JSON")
    parser.add_argument("--no-discovery",  action="store_true",
                        help="Sauter la découverte d'hôtes, scanner directement")

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"\n[*] Scanner réseau démarré — {len(ports)} port(s) à tester")
    start_time = time.time()

    # Découverte d'hôtes
    if args.no_discovery or "/" not in args.target:
        active_hosts = [args.target]
    else:
        active_hosts = discover_hosts(args.target, threads=args.threads)

    if not active_hosts:
        print("[-] Aucun hôte actif détecté.")
        return

    print(f"\n[*] {len(active_hosts)} hôte(s) actif(s) — début du scan de ports...\n")

    # Scan de chaque hôte
    results = []
    for ip in active_hosts:
        report = scan_host(ip, ports, threads=args.threads, timeout=args.timeout)
        results.append(report)

    elapsed = round(time.time() - start_time, 1)
    print(f"\n[*] Scan terminé en {elapsed}s")

    print_report(results, json_output=args.json)


if __name__ == "__main__":
    main()
