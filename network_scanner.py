#!/usr/bin/env python3
"""
Mini scanner réseau - équivalent Nmap simplifié
Usage : python3 network_scanner.py -t 192.168.1.1
        python3 network_scanner.py -t 192.168.1.0/24
        python3 network_scanner.py -t 192.168.1.1 -p 1-1024 --threads 200
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
# Couleurs ANSI
# ──────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    @staticmethod
    def disable():
        for attr in ["RESET","BOLD","DIM","RED","GREEN","YELLOW",
                     "BLUE","MAGENTA","CYAN","WHITE","GRAY"]:
            setattr(C, attr, "")


# ──────────────────────────────────────────────────────────────
# Signatures de services (banner → nom du service)
# ──────────────────────────────────────────────────────────────
SERVICE_SIGNATURES = {
    b"SSH":           "SSH",
    b"HTTP":          "HTTP",
    b"220":           "FTP/SMTP",
    b"* OK":          "IMAP",
    b"+OK":           "POP3",
    b"RFB":           "VNC",
    b"AMQP":          "AMQP/RabbitMQ",
    b"redis_version": "Redis",
    b"mongos":        "MongoDB",
    b"\x16\x03":      "TLS/SSL",
}

# Ports courants avec leur nom
COMMON_PORTS = {
    21: "FTP",    22: "SSH",     23: "Telnet",  25: "SMTP",
    53: "DNS",    80: "HTTP",    110: "POP3",   143: "IMAP",
    443: "HTTPS", 445: "SMB",    3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt",  27017: "MongoDB",
}

# Couleur par service
SERVICE_COLORS = {
    "SSH":         C.GREEN,
    "HTTP":        C.CYAN,
    "HTTPS":       C.CYAN,
    "TLS/SSL":     C.CYAN,
    "HTTP-Alt":    C.CYAN,
    "HTTPS-Alt":   C.CYAN,
    "FTP":         C.YELLOW,
    "FTP/SMTP":    C.YELLOW,
    "SMTP":        C.YELLOW,
    "SMB":         C.RED,
    "RDP":         C.RED,
    "Telnet":      C.RED,
    "MySQL":       C.MAGENTA,
    "PostgreSQL":  C.MAGENTA,
    "Redis":       C.MAGENTA,
    "MongoDB":     C.MAGENTA,
    "DNS":         C.BLUE,
    "IMAP":        C.BLUE,
    "POP3":        C.BLUE,
    "AMQP/RabbitMQ": C.BLUE,
    "VNC":         C.YELLOW,
}

# ──────────────────────────────────────────────────────────────
# Barre de progression (thread-safe)
# ──────────────────────────────────────────────────────────────
class Progress:
    def __init__(self, total: int, label: str = ""):
        self.total   = total
        self.current = 0
        self.label   = label
        self._lock   = threading.Lock()
        self._start  = time.time()

    def increment(self):
        with self._lock:
            self.current += 1
            self._render()

    def _render(self):
        pct   = self.current / self.total
        width = 30
        filled = int(width * pct)
        bar    = "█" * filled + "░" * (width - filled)
        elapsed = time.time() - self._start
        sys.stderr.write(
            f"\r  {C.GRAY}{self.label}{C.RESET} "
            f"{C.CYAN}[{bar}]{C.RESET} "
            f"{C.BOLD}{self.current}/{self.total}{C.RESET} "
            f"{C.GRAY}({elapsed:.1f}s){C.RESET}   "
        )
        sys.stderr.flush()
        if self.current >= self.total:
            sys.stderr.write("\n")
            sys.stderr.flush()


# ──────────────────────────────────────────────────────────────
# Ping hôte (TCP connect sur plusieurs ports courants)
# ──────────────────────────────────────────────────────────────
def ping_host(ip: str, timeout: float = 1.0) -> bool:
    for port in [80, 443, 22, 8080, 445, 135, 3389]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return True
            s.close()
        except Exception:
            pass
    return False


# ──────────────────────────────────────────────────────────────
# Scan d'un port unique
# ──────────────────────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start  = time.time()
        result = s.connect_ex((ip, port))
        latency = round((time.time() - start) * 1000, 1)

        if result != 0:
            s.close()
            return None

        banner  = ""
        service = COMMON_PORTS.get(port, "unknown")
        try:
            if port in (80, 8080, 8443):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                pass
            else:
                s.send(b"\r\n")

            raw    = s.recv(1024)
            banner = raw.decode("utf-8", errors="replace").strip()[:120]

            for sig, name in SERVICE_SIGNATURES.items():
                if sig in raw:
                    service = name
                    break
        except Exception:
            pass

        s.close()
        return {
            "port":       port,
            "state":      "open",
            "service":    service,
            "banner":     banner,
            "latency_ms": latency,
        }
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────
# Détection OS via TTL  (heuristique)
# ──────────────────────────────────────────────────────────────
def detect_os_by_ttl(ip: str, open_ports: list[dict]) -> str:
    """
    Essaie d'abord de lire le TTL réel ; sinon, utilise les ports
    ouverts comme heuristique secondaire.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect_ex((ip, 80))
        ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        s.close()
        if ttl <= 64:
            return "Linux / macOS"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Cisco / équipement réseau"
    except Exception:
        pass

    # Heuristique par ports ouverts
    port_nums = {p["port"] for p in open_ports}
    windows_ports = {135, 139, 445, 3389, 5985, 49152}
    linux_ports   = {22, 111, 2049}
    if port_nums & windows_ports:
        return "Windows (heuristique ports)"
    if port_nums & linux_ports:
        return "Linux (heuristique ports)"
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
    progress = Progress(len(ports), label=f"Scan {ip}")
    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            progress.increment()
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    hostname  = resolve_hostname(ip)
    os_guess  = detect_os_by_ttl(ip, open_ports)

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
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"{C.RED}[-] Adresse invalide : {e}{C.RESET}")
        return []

    hosts = [str(h) for h in net.hosts()] or [network]
    print(f"\n{C.BOLD}[*]{C.RESET} Découverte d'hôtes sur "
          f"{C.CYAN}{network}{C.RESET} ({len(hosts)} adresses)...")

    progress = Progress(len(hosts), label="Ping sweep")
    active   = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            progress.increment()
            if future.result():
                print(f"  {C.GREEN}[+]{C.RESET} Hôte actif : {C.BOLD}{ip}{C.RESET}")
                active.append(ip)

    return sorted(active)


# ──────────────────────────────────────────────────────────────
# Affichage du rapport
# ──────────────────────────────────────────────────────────────
def _latency_color(ms: float) -> str:
    if ms < 5:    return C.GREEN
    if ms < 50:   return C.YELLOW
    return C.RED

def _os_icon(os_str: str) -> str:
    s = os_str.lower()
    if "windows" in s: return "🪟"
    if "linux"   in s: return "🐧"
    if "macos"   in s: return "🍎"
    if "cisco"   in s: return "🔌"
    return "❓"

def print_report(results: list[dict], json_output: bool = False) -> None:
    if json_output:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    W = 68
    def hline(ch="═"): return C.GRAY + ch * W + C.RESET

    print()
    print(hline())
    print(f"  {C.BOLD}{C.WHITE}{'RAPPORT DE SCAN RÉSEAU':^{W-4}}{C.RESET}")
    print(hline())

    for host in results:
        hostname_str = f"  {C.DIM}({host['hostname']}){C.RESET}" if host["hostname"] else ""
        os_icon = _os_icon(host["os_guess"])

        print()
        print(f"  {C.CYAN}{'─'*62}{C.RESET}")
        print(f"  {C.BOLD}Hôte{C.RESET}    {C.WHITE}{host['ip']}{C.RESET}{hostname_str}")
        print(f"  {C.BOLD}OS{C.RESET}      {os_icon}  {host['os_guess']}")
        print(f"  {C.BOLD}Scanné{C.RESET}  {C.GRAY}{host['scanned_at']}{C.RESET}")
        print(f"  {C.CYAN}{'─'*62}{C.RESET}")

        if not host["open_ports"]:
            print(f"  {C.GRAY}Aucun port ouvert détecté.{C.RESET}")
        else:
            # En-tête tableau
            print(
                f"\n  {C.BOLD}{'PORT':<8} {'SERVICE':<18} {'ÉTAT':<8} {'LATENCE':>8}  BANNER{C.RESET}"
            )
            print(f"  {C.GRAY}{'─'*62}{C.RESET}")

            for p in host["open_ports"]:
                svc_color  = SERVICE_COLORS.get(p["service"], C.WHITE)
                lat_color  = _latency_color(p["latency_ms"])
                banner_str = p["banner"][:35].replace("\n", " ") if p["banner"] else ""
                state_str  = f"{C.GREEN}open{C.RESET}"

                print(
                    f"  {C.BOLD}{C.WHITE}{p['port']:<8}{C.RESET}"
                    f"{svc_color}{p['service']:<18}{C.RESET}"
                    f"{state_str:<8}  "          # 8 + "open" visible width
                    f"{lat_color}{p['latency_ms']:>6}ms{C.RESET}  "
                    f"{C.GRAY}{banner_str}{C.RESET}"
                )

        print()

    # Résumé final
    print(hline())
    total_hosts = len(results)
    total_open  = sum(len(h["open_ports"]) for h in results)
    elapsed_str = ""
    print(
        f"  {C.BOLD}Résumé{C.RESET}  "
        f"{C.CYAN}{total_hosts}{C.RESET} hôte(s) scanné(s)  ·  "
        f"{C.GREEN}{total_open}{C.RESET} port(s) ouvert(s)"
    )
    print(hline())
    print()


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
    parser.add_argument("-t", "--target",       required=True,
                        help="IP unique ou plage CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",        default="common",
                        help="Ports : '1-1024', '80,443', 'common' (défaut)")
    parser.add_argument("--threads",            type=int, default=100,
                        help="Threads simultanés (défaut: 100)")
    parser.add_argument("--timeout",            type=float, default=1.0,
                        help="Timeout par port en secondes (défaut: 1.0)")
    parser.add_argument("--json",               action="store_true",
                        help="Sortie au format JSON")
    parser.add_argument("--no-discovery",       action="store_true",
                        help="Sauter la découverte d'hôtes, scanner directement")
    parser.add_argument("--no-color",           action="store_true",
                        help="Désactiver les couleurs ANSI")

    args = parser.parse_args()

    if args.no_color or args.json:
        C.disable()

    ports = parse_ports(args.ports)

    print(f"\n{C.BOLD}[*]{C.RESET} Scanner réseau démarré  "
          f"— {C.CYAN}{len(ports)}{C.RESET} port(s) à tester  "
          f"| {C.CYAN}{args.threads}{C.RESET} threads  "
          f"| timeout {C.CYAN}{args.timeout}s{C.RESET}")

    start_time = time.time()

    # Découverte d'hôtes
    if args.no_discovery or "/" not in args.target:
        active_hosts = [args.target]
    else:
        active_hosts = discover_hosts(args.target, threads=args.threads)

    if not active_hosts:
        print(f"{C.RED}[-] Aucun hôte actif détecté.{C.RESET}")
        return

    print(f"\n{C.BOLD}[*]{C.RESET} {C.GREEN}{len(active_hosts)}{C.RESET} "
          f"hôte(s) actif(s) — début du scan de ports...\n")

    results = []
    for ip in active_hosts:
        report = scan_host(ip, ports, threads=args.threads, timeout=args.timeout)
        results.append(report)

    elapsed = round(time.time() - start_time, 1)
    print(f"{C.BOLD}[*]{C.RESET} Scan terminé en "
          f"{C.CYAN}{elapsed}s{C.RESET}")

    print_report(results, json_output=args.json)


if __name__ == "__main__":
    main()
