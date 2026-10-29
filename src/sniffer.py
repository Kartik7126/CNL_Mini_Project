import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Generator

from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff

from config import get as cfg

WINDOW_SECONDS = cfg("network", "window_seconds", default=2)
SNIFF_FILTER   = cfg("network", "sniff_filter", default="ip")


@dataclass
class _Bucket:
    start: float
    first: float = 0.0  # timestamp of first packet received
    last: float = 0.0   # timestamp of most recent packet received
    packet_count: int = 0
    total_bytes: int = 0
    ports: set = field(default_factory=set)
    syn_count: int = 0

    def add(self, size: int, port: int, is_syn: bool = False):
        now = time.time()
        if self.packet_count == 0:
            self.first = now
        self.last = now
        self.packet_count += 1
        self.total_bytes += size
        if port:
            self.ports.add(port)
        if is_syn:
            self.syn_count += 1

    def to_features(self, window_duration: float = WINDOW_SECONDS) -> dict:
        if self.packet_count <= 1:
            elapsed = max(window_duration, 1.0)
        else:
            elapsed = max(self.last - self.first, 0.1)
        return {
            "packets_per_sec": self.packet_count / elapsed,
            "avg_packet_size": self.total_bytes / max(self.packet_count, 1),
            "unique_ports":    len(self.ports),
            "syn_ratio":       self.syn_count / max(self.packet_count, 1),
        }


class PacketSniffer:
    def __init__(self, interface: str | None = None, window: float = WINDOW_SECONDS):
        self.interface = interface
        self.window = window
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}
        self._callbacks: list = []

    def add_callback(self, fn):
        self._callbacks.append(fn)

    def _get_or_create(self, src_ip: str) -> _Bucket:
        now = time.time()
        bucket = self._buckets.get(src_ip)
        if bucket is None or (now - bucket.start) >= self.window:
            if bucket is not None:
                self._flush(src_ip, bucket)
            bucket = _Bucket(start=now)
            self._buckets[src_ip] = bucket
        return bucket

    def _flush(self, src_ip: str, bucket: _Bucket):
        if bucket.packet_count == 0:
            return
        features = bucket.to_features(self.window)
        features["src_ip"] = src_ip
        features["timestamp"] = bucket.start
        features["ports_set"] = set(bucket.ports)
        features["packet_count"] = bucket.packet_count
        features["syn_count"] = bucket.syn_count
        bucket.packet_count = 0  # prevent duplicate flush
        for cb in self._callbacks:
            try:
                cb(features)
            except Exception:
                pass

    def _process(self, pkt):
        if not self._running:
            return
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        size = len(pkt)
        port = 0
        is_syn = False
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            port = tcp.dport
            # SYN set (0x02) and ACK not set (0x10) represents a SYN request probe
            flags = int(tcp.flags)
            if (flags & 0x02) and not (flags & 0x10):
                is_syn = True
        elif pkt.haslayer(UDP):
            port = pkt[UDP].dport

        with self._lock:
            bucket = self._get_or_create(src_ip)
            bucket.add(size, port, is_syn=is_syn)
            now = time.time()
            if (now - bucket.start) >= self.window:
                self._flush(src_ip, bucket)
                del self._buckets[src_ip]

    def _flush_stale(self):
        """Periodic flush for buckets that haven't received new packets."""
        while self._running:
            time.sleep(self.window / 2)
            now = time.time()
            with self._lock:
                stale = [
                    (ip, b) for ip, b in self._buckets.items()
                    if (now - b.start) >= self.window
                ]
                for ip, bucket in stale:
                    self._flush(ip, bucket)
                    del self._buckets[ip]

    def start(self):
        self._running = True
        flusher = threading.Thread(target=self._flush_stale, daemon=True)
        flusher.start()
        while self._running:
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process,
                    store=False,
                    filter=SNIFF_FILTER,
                    timeout=2.0,
                    stop_filter=lambda p: not self._running,
                )
            except Exception as e:
                if not self._running:
                    break
                time.sleep(0.5)

    def stop(self):
        self._running = False


def stream_features(interface: str | None = None) -> Generator[dict, None, None]:
    """Yield feature dicts from a live sniff session (blocks the calling thread)."""
    import queue
    q: queue.Queue[dict] = queue.Queue()
    sniffer = PacketSniffer(interface=interface)
    sniffer.add_callback(q.put)

    t = threading.Thread(target=sniffer.start, daemon=True)
    t.start()

    try:
        while True:
            yield q.get()
    finally:
        sniffer.stop()
