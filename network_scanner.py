#!/usr/bin/env python3
"""
🛡️ PyNet-Scanner Pro
Scanner réseau haute performance avec détection d'OS améliorée.
"""

import socket
import argparse
import ipaddress
import json
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ──────────────────────────────────────────────────────────────
# Couleurs ANSI & Style
# ──────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[38;5;196m"
    GREEN   = "\033[38;5;82m"
    YELLOW  = "\033[38;5;226m"
    BLUE    = "\033[38;5;45m"
    MAGENTA = "\033[38;5;171m"
    CYAN    = "\033[38;5;51m"
    WHITE   = "\033[38;5;231m"
    GRAY    = "\033[38;5;244m"
    ORANGE  = "\033[38;5;208m"
    BG_BLUE = "\033[48;5;24m"

    @staticmethod
    def disable():
        for attr in ["RESET","BOLD","DIM","RED","GREEN","YELLOW",
                     "BLUE","MAGENTA","CYAN","WHITE","GRAY", "ORANGE", "BG_BLUE"]:
            setattr(C, attr, "")

BANNER = f"""
{C.CYAN}  _____               {C.BLUE} _   _      _   {C.RESET}
{C.CYAN} |  __ \             {C.BLUE}| \ | |    | |  {C.RESET}
{C.CYAN} | |__) |   _ _ __   {C.BLUE}|  \| | ___| |_ {C.RESET}
{C.CYAN} |  ___/ | | | '_ \  {C.BLUE}| . ` |/ _ \ __|{C.RESET}
{C.CYAN} | |   | |_| | | | | {C.BLUE}| |\  |  __/ |_ {C.RESET}
{C.CYAN} |_|    \__, |_| |_| {C.BLUE}|_| \_|\___|\__|{C.RESET}
{C.CYAN}         __/ |       {C.GRAY}Network Scanner Pro{C.RESET}
{C.CYAN}        |___/        {C.GRAY}v2.1 - Security Labs{C.RESET}
"""

# ──────────────────────────────────────────────────────────────
# Configuration & Signatures
# ──────────────────────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Proxy", 27017: "MongoDB"
}

SERVICE_COLORS = {
    "SSH": C.GREEN, "HTTP": C.CYAN, "HTTPS": C.CYAN, "SMB": C.RED,
    "RDP": C.ORANGE, "FTP": C.YELLOW, "MySQL": C.MAGENTA, "Redis": C.MAGENTA
}

class Progress:
    def __init__(self, total: int, label: str = ""):
        self.total = total
        self.current = 0
        self.label = label
        self._lock = threading.Lock()
        self._start = time.time()

    def increment(self):
        with self._lock:
            self.current += 1
            self._render()

    def _render(self):
        if self.total == 0: return
        pct = self.current / self.total
        bar = "━" * int(20 * pct) + "─" * (20 - int(20 * pct))
        sys.stderr.write(f"\r  {C.GRAY}{self.label:<15}{C.RESET} {C.BLUE}▕{bar}▏{C.RESET} {C.BOLD}{int(pct*100)}%{C.RESET} ")
        sys.stderr.flush()
        if self.current >= self.total: sys.stderr.write("\n")

# ──────────────────────────────────────────────────────────────
# Logique de Scan et Détection
# ──────────────────────────────────────────────────────────────

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Vérifie si un hôte est actif via une tentative de connexion TCP."""
    for port in [80, 443, 22, 445]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0: return True
        except: pass
    return False

def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """Scan un port TCP et récupère la bannière de service."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            start = time.time()
            if s.connect_ex((ip, port)) == 0:
                latency = round((time.time() - start) * 1000, 1)
                banner = ""
                try:
                    s.send(b"\r\n")
                    banner = s.recv(1024).decode(errors='ignore').strip()[:50]
                except: pass
                return {
                    "port": port, "service": COMMON_PORTS.get(port, "unknown"),
                    "banner": banner, "latency": latency
                }
    except: pass
    return None

def detect_os(ip: str, open_ports: list) -> str:
    """Détection d'OS améliorée : croisement du TTL et des ports ouverts."""
    # 1. Analyse par ports spécifiques (très fiable pour Windows)
    port_nums = [p["port"] for p in open_ports]
    windows_indicators = {135, 139, 445, 3389}
    
    if any(p in windows_indicators for p in port_nums):
        return "🪟 Windows (via Services)"

    # 2. Heuristique par TTL
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            # On tente une connexion sur un port ouvert pour obtenir le TTL du paquet retour
            test_port = port_nums[0] if port_nums else 80
            s.connect_ex((ip, test_port))
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            if ttl <= 64: return "🐧 Linux/macOS"
            if ttl <= 128: return "🪟 Windows"
            return "🔌 Network Device"
    except: return "❓ Indéterminé"

# ──────────────────────────────────────────────────────────────
# Affichage du Rapport
# ──────────────────────────────────────────────────────────────

def print_pretty_report(results):
    for host in results:
        print(f"\n{C.BG_BLUE}{C.BOLD}  IP: {host['ip']:<45} {C.RESET}")
        print(f"  {C.BOLD}Hostname : {C.RESET}{C.WHITE}{host['hostname'] or 'N/A'}{C.RESET}")
        print(f"  {C.BOLD}OS Guess : {C.RESET}{host['os_guess']}")
        print(f"  {C.GRAY}─" * 65 + C.RESET)
        
        if not host["open_ports"]:
            print(f"  {C.RED}Aucun port ouvert détecté.{C.RESET}")
        else:
            print(f"  {C.BOLD}{'PORT':<8} {'SERVICE':<15} {'LATENCE':<10} {'BANNER'}{C.RESET}")
            for p in host["open_ports"]:
                color = SERVICE_COLORS.get(p["service"], C.WHITE)
                banner = f"{C.GRAY}» {p['banner']}{C.RESET}" if p['banner'] else ""
                print(f"  {C.BOLD}{p['port']:<8}{C.RESET} {color}{p['service']:<15}{C.RESET} {C.GRAY}{p['latency']:>5}ms{C.RESET}  {banner}")
    
    print(f"\n{C.BOLD}{C.CYAN}📊 Résumé du scan : {len(results)} hôte(s) trouvé(s).{C.RESET}\n")

# ──────────────────────────────────────────────────────────────
# Point d'entrée principal
# ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PyNet-Scanner Pro")
    parser.add_argument("-t", "--target", required=True, help="IP unique ou plage CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="common", help="Ports (ex: 22,80 ou 1-1024)")
    parser.add_argument("--threads", type=int, default=100, help="Nombre de threads (défaut: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout par port (défaut: 1.0)")
    parser.add_argument("--json", action="store_true", help="Sortie au format JSON")
    parser.add_argument("--no-discovery", action="store_true", help="Passer directement au scan de ports")
    parser.add_argument("--no-color", action="store_true", help="Désactiver les couleurs")
    args = parser.parse_args()

    if args.json or args.no_color: C.disable()
    else: print(BANNER)

    # Parsing des ports
    if args.ports == "common": target_ports = list(COMMON_PORTS.keys())
    elif "-" in args.ports:
        s, e = map(int, args.ports.split("-"))
        target_ports = list(range(s, e+1))
    else: target_ports = [int(p) for p in args.ports.split(",")]

    start_time = time.time()
    
    # Étape 1 : Découverte
    try:
        net_hosts = [str(ip) for ip in ipaddress.ip_network(args.target, strict=False).hosts()] if "/" in args.target else [args.target]
    except ValueError as e:
        print(f"{C.RED}[!] Erreur de cible : {e}{C.RESET}")
        return

    active_hosts = []
    if args.no_discovery:
        active_hosts = net_hosts
    else:
        prog_disc = Progress(len(net_hosts), "Discovery")
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(ping_host, ip, args.timeout): ip for ip in net_hosts}
            for f in as_completed(futures):
                prog_disc.increment()
                if f.result(): active_hosts.append(futures[f])

    if not active_hosts:
        print(f"{C.RED}[!] Aucun hôte actif détecté.{C.RESET}")
        return

    # Étape 2 : Scan de ports
    final_results = []
    for ip in active_hosts:
        prog_scan = Progress(len(target_ports), f"Scan {ip}")
        host_data = {"ip": ip, "hostname": "", "open_ports": []}
        
        # Résolution Hostname
        try: host_data["hostname"] = socket.gethostbyaddr(ip)[0]
        except: pass
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_port, ip, p, args.timeout): p for p in target_ports}
            for f in as_completed(futures):
                prog_scan.increment()
                res = f.result()
                if res: host_data["open_ports"].append(res)
        
        host_data["open_ports"].sort(key=lambda x: x["port"])
        # Détection d'OS basée sur les résultats du scan
        host_data["os_guess"] = detect_os(ip, host_data["open_ports"])
        final_results.append(host_data)

    # Étape 3 : Sortie
    if args.json:
        print(json.dumps(final_results, indent=2))
    else:
        print_pretty_report(final_results)
        print(f"{C.GRAY}Terminé en {time.time()-start_time:.2f}s{C.RESET}")

if __name__ == "__main__":
    main()
