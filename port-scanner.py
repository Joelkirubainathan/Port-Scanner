#!/usr/bin/env python3
"""
Port Scanner
------------
A multi-threaded TCP/UDP port scanner for network reconnaissance and
security assessment. Includes banner grabbing on open ports.

⚠️  Legal notice: Only scan systems you own or have explicit written
    authorization to test. Unauthorized scanning may be illegal in your
    jurisdiction (e.g. under the U.S. Computer Fraud and Abuse Act or
    similar laws elsewhere).

Usage examples:
    python3 port_scanner.py 192.168.1.10 -p 1-1024
    python3 port_scanner.py example.com -p 22,80,443,8080 --udp
    python3 port_scanner.py 10.0.0.5 -p 1-65535 -t 200 --timeout 0.5 -o results.json
"""

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sys
import threading
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Common ports mapped to service names, used to label results and to build
# lightweight banner-grabbing probes for protocols that expect the client
# to speak first (e.g. HTTP).
# ---------------------------------------------------------------------------
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

print_lock = threading.Lock()


def parse_ports(port_spec: str):
    """Parse a port spec like '80', '1-1024', or '22,80,443,8000-8100'."""
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address (also validates literal IPs)."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise SystemExit(f"[!] Could not resolve host '{target}': {e}")


def grab_banner(sock: socket.socket, port: int) -> str:
    """Attempt to read a service banner, sending a small probe if needed."""
    try:
        sock.settimeout(1.5)
        # Protocols that stay silent until the client sends something.
        if port in (80, 8080, 8000, 8888):
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: scan\r\nConnection: close\r\n\r\n")
        elif port == 443 or port == 8443:
            return ""  # would need TLS handshake; skip for simplicity
        banner = sock.recv(1024)
        return banner.decode(errors="replace").strip().split("\n")[0][:120]
    except Exception:
        return ""


def tcp_scan_port(ip: str, port: int, timeout: float, do_banner: bool):
    """Attempt a TCP connect scan on a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(sock, port) if do_banner else ""
                service = COMMON_SERVICES.get(port, "unknown")
                return {"port": port, "protocol": "tcp", "state": "open",
                        "service": service, "banner": banner}
    except socket.error:
        pass
    return None


def udp_scan_port(ip: str, port: int, timeout: float):
    """
    Attempt a UDP scan on a single port.
    UDP is connectionless/stateless, so this uses a best-effort heuristic:
    - ICMP port-unreachable response  -> closed
    - A UDP response                  -> open
    - No response within timeout      -> open|filtered (ambiguous, common for UDP)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendto(b"\x00", (ip, port))
                data, _ = sock.recvfrom(1024)
                service = COMMON_SERVICES.get(port, "unknown")
                return {"port": port, "protocol": "udp", "state": "open",
                        "service": service, "banner": data[:64].decode(errors="replace")}
            except socket.timeout:
                service = COMMON_SERVICES.get(port, "unknown")
                return {"port": port, "protocol": "udp", "state": "open|filtered",
                        "service": service, "banner": ""}
            except ConnectionResetError:
                return None  # ICMP port unreachable -> closed
    except socket.error:
        pass
    return None


def scan(target: str, ports, threads: int, timeout: float,
          do_udp: bool, do_banner: bool, verbose: bool):
    ip = resolve_target(target)
    print(f"[*] Target:      {target} ({ip})")
    print(f"[*] Ports:       {len(ports)} port(s)")
    print(f"[*] Protocol(s): {'TCP + UDP' if do_udp else 'TCP'}")
    print(f"[*] Threads:     {threads}")
    print(f"[*] Started at:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    open_results = []
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for port in ports:
            futures[executor.submit(tcp_scan_port, ip, port, timeout, do_banner)] = ("tcp", port)
            if do_udp:
                futures[executor.submit(udp_scan_port, ip, port, timeout)] = ("udp", port)

        for future in concurrent.futures.as_completed(futures):
            proto, port = futures[future]
            try:
                result = future.result()
            except Exception as e:
                if verbose:
                    with print_lock:
                        print(f"[!] Error scanning {proto}/{port}: {e}")
                continue
            if result:
                open_results.append(result)
                with print_lock:
                    label = f"{result['port']}/{result['protocol']}"
                    line = f"[+] {label:<10} {result['state']:<14} {result['service']}"
                    if result["banner"]:
                        line += f"  -> {result['banner']}"
                    print(line)

    elapsed = time.time() - start
    print("-" * 60)
    print(f"[*] Scan completed in {elapsed:.2f}s — {len(open_results)} open port(s) found.")

    open_results.sort(key=lambda r: (r["protocol"], r["port"]))
    return {
        "target": target,
        "ip": ip,
        "scanned_ports": len(ports),
        "duration_seconds": round(elapsed, 2),
        "open_ports": open_results,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP/UDP port scanner for authorized security assessments.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Ports to scan, e.g. '80', '1-1024', '22,80,443'")
    parser.add_argument("-t", "--threads", type=int, default=100,
                         help="Number of concurrent threads")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Socket timeout in seconds per port")
    parser.add_argument("--udp", action="store_true",
                         help="Also scan UDP ports (slower, heuristic-based)")
    parser.add_argument("--no-banner", action="store_true",
                         help="Disable banner grabbing on open TCP ports")
    parser.add_argument("-o", "--output", help="Write JSON results to this file")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show verbose/error output")

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(str(e))

    print("=" * 60)
    print(" PORT SCANNER — for authorized security testing only")
    print("=" * 60)

    try:
        results = scan(
            target=args.target,
            ports=ports,
            threads=max(1, args.threads),
            timeout=args.timeout,
            do_udp=args.udp,
            do_banner=not args.no_banner,
            verbose=args.verbose,
        )
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results written to {args.output}")


if __name__ == "__main__":
    main()