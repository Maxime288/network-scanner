#!/usr/bin/env python3
"""
🛡️ PyNet-Scanner Pro
Un scanner réseau élégant et rapide pour la reconnaissance offensive.
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
{C.CYAN}         __/ |       {C.GRAY}Network Scanner{C.RESET}
{C.CYAN}        |___/        {C.GRAY}v2.0 - Security Labs{C.RESET}
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
        pct = self.current / self.total
        bar = "━" * int(20 * pct) + "─" * (20 - int(20 * pct))
        sys.stderr.write(f"\r  {C.GRAY}{self.label:<15}{C.RESET} {C.BLUE}▕{bar}▏{C.RESET} {C.BOLD}{int(pct*100)}%{C.RESET} ")
        sys.stderr.flush()
        if self.current >= self.total: sys.stderr.write("\n")

# ──────────────────────────────────────────────────────────────
# Logique de Scan
# ──────────────────────────────────────────────────────────────

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Vérifie si un hôte est en ligne via TCP."""
    for port in [80, 443, 22, 445]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0: return True
        except: pass
    return False

def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """Scan un port et tente de récupérer une bannière."""
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

def detect_os(ip: str) -> str:
    """Heuristique TTL simplifiée."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect_ex((ip, 80)) # Port générique pour forcer le paquet
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            if ttl <= 64: return "🐧 Linux/macOS"
            if ttl <= 128: return "🪟 Windows"
            return "🔌 Network Device"
    except: return "❓ Unknown"

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

def main():
    parser = argparse.ArgumentParser(description="PyNet-Scanner Pro")
    parser.add_argument("-t", "--target", required=True, help="Cible IP ou CIDR")
    parser.add_argument("-p", "--ports", default="common", help="Ports (ex: 22,80 or 1-1000)")
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.json: C.disable()
    else: print(BANNER)

    # Parsing des ports
    if args.ports == "common": target_ports = list(COMMON_PORTS.keys())
    elif "-" in args.ports:
        s, e = map(int, args.ports.split("-"))
        target_ports = list(range(s, e+1))
    else: target_ports = [int(p) for p in args.ports.split(",")]

    start_time = time.time()
    
    # Discovery
    net_hosts = [str(ip) for ip in ipaddress.ip_network(args.target, strict=False).hosts()] if "/" in args.target else [args.target]
    active_hosts = []
    
    prog_disc = Progress(len(net_hosts), "Discovery")
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in net_hosts}
        for f in as_completed(futures):
            prog_disc.increment()
            if f.result(): active_hosts.append(futures[f])

    if not active_hosts:
        print(f"{C.RED}[!] Aucun hôte en ligne.{C.RESET}")
        return

    # Scanning
    final_results = []
    for ip in active_hosts:
        prog_scan = Progress(len(target_ports), f"Scan {ip}")
        host_data = {"ip": ip, "hostname": "", "os_guess": detect_os(ip), "open_ports": []}
        try: host_data["hostname"] = socket.gethostbyaddr(ip)[0]
        except: pass
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_port, ip, p): p for p in target_ports}
            for f in as_completed(futures):
                prog_scan.increment()
                res = f.result()
                if res: host_data["open_ports"].append(res)
        
        host_data["open_ports"].sort(key=lambda x: x["port"])
        final_results.append(host_data)

    if args.json:
        print(json.dumps(final_results, indent=2))
    else:
        print_pretty_report(final_results)
        print(f"{C.GRAY}Terminé en {time.time()-start_time:.2f}s{C.RESET}")

if __name__ == "__main__":
    main()
