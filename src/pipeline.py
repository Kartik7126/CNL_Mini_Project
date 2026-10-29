import logging
import os
import signal
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from collections import defaultdict
import contextlib
import ipaddress

import joblib

sys.path.insert(0, os.path.dirname(__file__))
from config import get as cfg, load_env
from sniffer import stream_features
from firewall import redirect_to_honeypot, flush_all_redirects
from alerts import dispatch
from honeypot import Honeypot

logging.basicConfig(
    level=getattr(logging, cfg("logging", "level", default="INFO").upper(), logging.INFO),
    format=cfg("logging", "format", default="%(asctime)s  %(levelname)-8s  %(message)s"),
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

MODEL_PATH   = cfg("classifier", "model_path", default="data/network_model.pkl")
DB_PATH      = cfg("honeypot", "db_path", default="data/live_events.db")
FEATURES     = cfg("classifier", "features", default=["packets_per_sec", "avg_packet_size", "unique_ports", "syn_ratio"])
ATTACK_LABELS = {0: "normal", 1: "port_scan", 2: "syn_flood"}
# Probability margin (top-1 minus top-2) required to act, instead of a flat
# confidence cutoff — adaptive to how decisive the classifier is.
CONFIDENCE_MARGIN = max(cfg("classifier", "confidence_margin", default=0.10), 0.0)
# Reject any prediction whose top class probability is below this floor.
MIN_CONFIDENCE = cfg("classifier", "confidence_threshold", default=0.70)
# Suppress redundant alerts + duplicate DB rows for a given source IP within
# this window. A sustained attacker re-alerts at most once per period.
ALERT_COOLDOWN = cfg("alerts", "cooldown_seconds", default=60)

_db_lock = threading.Lock()


def _is_whitelisted(ip: str) -> bool:
    wl_cfg = cfg("whitelist", default={})
    if not wl_cfg.get("enabled", True):
        return False
    wl_ips = set(wl_cfg.get("ips", []))
    if ip in wl_ips:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local:
            return True
        for subnet_str in wl_cfg.get("subnets", []):
            if addr in ipaddress.ip_network(subnet_str, strict=False):
                return True
    except ValueError:
        pass
    return False


class _AlertCooldown:
    """Per-(source-IP, attack_type) rate limiter for alerts and incident logging.

    ``allowed(ip, label)`` returns True if this IP has not triggered an alert
    for this specific attack type within the cooldown window.
    """

    __slots__ = ("cooldown", "_last", "_suppressed")

    def __init__(self, cooldown: float):
        self.cooldown = max(float(cooldown), 0.0)
        self._last: dict[tuple[str, int | str], float] = {}
        self._suppressed: dict[tuple[str, int | str], int] = {}

    def allowed(self, ip: str, label: int | str = 0, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        last = self._last.get((ip, label))
        return last is None or (now - last) >= self.cooldown

    def record(self, ip: str, label: int | str = 0, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        self._last[(ip, label)] = now
        self._suppressed[(ip, label)] = 0

    def note_suppressed(self, ip: str, label: int | str = 0) -> int:
        """Increment and return how many consecutive detections are suppressed for *(ip, label)*."""
        key = (ip, label)
        n = self._suppressed.get(key, 0) + 1
        self._suppressed[key] = n
        return n

    def suppressed_count(self, ip: str, label: int | str = 0) -> int:
        return self._suppressed.get((ip, label), 0)


class CumulativeScanTracker:
    """Tracks destination ports and SYN ratios per source IP across a rolling time window.

    Detects chunked / low-and-slow port scans where an attacker sends small batches
    (e.g., 10-20 ports at a time with delays) to evade single-window rate thresholds.
    """

    def __init__(
        self,
        history_seconds: float = 120.0,
        threshold_ports: int = 20,
        min_syn_ratio: float = 0.75,
        max_avg_pkt_size: float = 120.0,
        max_tracked_ips: int = 10000,
    ):
        self.history_seconds = max(float(history_seconds), 10.0)
        self.threshold_ports = int(threshold_ports)
        self.min_syn_ratio = float(min_syn_ratio)
        self.max_avg_pkt_size = float(max_avg_pkt_size)
        self.max_tracked_ips = int(max_tracked_ips)
        # ip -> list of (timestamp, set(ports), syn_count, packet_count, total_bytes)
        self._history: dict[str, list[tuple[float, set[int], int, int, float]]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_and_evaluate(
        self, src_ip: str, feat: dict, now: float | None = None
    ) -> tuple[bool, dict]:
        now = now if now is not None else time.time()
        ports_set = feat.get("ports_set")
        if ports_set is None:
            ports_set = set(range(int(feat.get("unique_ports", 0))))

        pkt_count = int(feat.get("packet_count", feat.get("packets_per_sec", 1)))
        syn_ratio = float(feat.get("syn_ratio", 0.0))
        syn_count = int(feat.get("syn_count", round(pkt_count * syn_ratio)))
        avg_size = float(feat.get("avg_packet_size", 60.0))
        total_bytes = pkt_count * avg_size

        with self._lock:
            # Memory cap: prune stale keys if tracking too many IPs
            if len(self._history) > self.max_tracked_ips:
                stale_cutoff = now - self.history_seconds
                to_delete = [
                    ip for ip, entries in self._history.items()
                    if not entries or entries[-1][0] < stale_cutoff
                ]
                for ip in to_delete:
                    del self._history[ip]

            # Prune old entries for this IP
            cutoff = now - self.history_seconds
            entries = [e for e in self._history[src_ip] if e[0] >= cutoff]
            entries.append((now, set(ports_set), syn_count, pkt_count, total_bytes))
            if len(entries) > 200:
                entries = entries[-200:]
            self._history[src_ip] = entries

            # Aggregate across the rolling window
            all_ports: set[int] = set()
            total_syns = 0
            total_pkts = 0
            total_b = 0.0
            oldest_ts = entries[0][0]

            for _, p_set, s_cnt, p_cnt, b_cnt in entries:
                all_ports.update(p_set)
                total_syns += s_cnt
                total_pkts += p_cnt
                total_b += b_cnt

            cum_unique_ports = len(all_ports)
            cum_syn_ratio = total_syns / max(total_pkts, 1)
            cum_avg_size = total_b / max(total_pkts, 1)
            elapsed = max(now - oldest_ts, 1.0)
            cum_pps = total_pkts / elapsed

            cum_feat = feat.copy()
            cum_feat["unique_ports"] = cum_unique_ports
            cum_feat["syn_ratio"] = cum_syn_ratio
            cum_feat["avg_packet_size"] = cum_avg_size
            cum_feat["packets_per_sec"] = cum_pps

            is_scan = (
                cum_unique_ports >= self.threshold_ports
                and cum_syn_ratio >= self.min_syn_ratio
                and cum_avg_size <= self.max_avg_pkt_size
            )

            return is_scan, cum_feat

    def reset(self, src_ip: str) -> None:
        with self._lock:
            self._history.pop(src_ip, None)


def _has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:

    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return any(row[1] == col for row in cur.fetchall())
    except Exception:
        return False


def _make_writable(path: str = DB_PATH):
    for ext in ("", "-wal", "-shm"):
        p = path + ext
        if os.path.exists(p):
            try:
                os.chmod(p, 0o666)
            except Exception:
                pass


def _init_db(conn: sqlite3.Connection):
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS incidents (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip       TEXT NOT NULL,
            attack_type  TEXT NOT NULL,
            confidence   REAL NOT NULL,
            pps          REAL,
            avg_pkt_size REAL,
            unique_ports INTEGER,
            syn_ratio    REAL DEFAULT 0.0,
            country      TEXT,
            city         TEXT,
            isp          TEXT,
            detected_at  TEXT NOT NULL
        );
    """)
    try:
        if not _has_column(conn, "incidents", "syn_ratio"):
            conn.execute("ALTER TABLE incidents ADD COLUMN syn_ratio REAL DEFAULT 0.0;")
            conn.commit()
    except Exception:
        pass
    _make_writable(DB_PATH)


@contextlib.contextmanager
def _manage_honeypot():
    """Start the honeypot in a background thread if enabled, and stop on exit."""
    if not cfg("honeypot", "enabled", default=True):
        yield None
        return

    hp = Honeypot()
    t = threading.Thread(target=hp.start, daemon=True, name="HoneypotDaemon")
    t.start()

    # Wait briefly to ensure it binds before we accept traffic
    timeout = cfg("honeypot", "start_timeout", default=5.0)
    start_t = time.time()
    while not hp._running and (time.time() - start_t) < timeout:
        time.sleep(0.1)

    try:
        yield hp
    finally:
        hp.stop()
        t.join(timeout=2.0)


@contextlib.contextmanager
def _graceful_shutdown(backend: str):
    """Ensure firewall rules flush on SIGINT, SIGTERM, or normal error."""
    _shutdown = threading.Event()

    def _handler(signum, frame):
        sig = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
        log.info("Received %s — shutting down cleanly...", sig)
        _shutdown.set()
        # Raise KeyboardInterrupt so the main loop unblocks and cleans up
        raise KeyboardInterrupt

    old_int = signal.signal(signal.SIGINT, _handler)
    old_term = signal.signal(signal.SIGTERM, _handler)

    try:
        yield _shutdown
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        log.info("Flushing firewall redirects...")
        flush_all_redirects(backend=backend)


def _log_incident(conn: sqlite3.Connection, features: dict, label: int, confidence: float, geo: dict):
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        if _has_column(conn, "incidents", "syn_ratio"):
            conn.execute(
                """INSERT INTO incidents
                   (src_ip, attack_type, confidence, pps, avg_pkt_size, unique_ports, syn_ratio,
                    country, city, isp, detected_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    features["src_ip"],
                    ATTACK_LABELS[label],
                    round(confidence, 4),
                    round(features["packets_per_sec"], 2),
                    round(features["avg_packet_size"], 2),
                    int(features["unique_ports"]),
                    round(features.get("syn_ratio", 0.0), 4),
                    geo.get("country", ""),
                    geo.get("city", ""),
                    geo.get("isp", ""),
                    now,
                ),
            )
        else:
            conn.execute(
                """INSERT INTO incidents
                   (src_ip, attack_type, confidence, pps, avg_pkt_size, unique_ports,
                    country, city, isp, detected_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    features["src_ip"],
                    ATTACK_LABELS[label],
                    round(confidence, 4),
                    round(features["packets_per_sec"], 2),
                    round(features["avg_packet_size"], 2),
                    int(features["unique_ports"]),
                    geo.get("country", ""),
                    geo.get("city", ""),
                    geo.get("isp", ""),
                    now,
                ),
            )
        conn.commit()
        _make_writable(DB_PATH)


def run(interface: str | list[str] | None = None, backend: str | None = None):
    load_env()  # load .env before touching configuration or credentials
    if backend is None:
        backend = cfg("firewall", "backend", default="iptables")
    if interface is None:
        interface = cfg("network", "interface", default=None)

    if isinstance(interface, str):
        if "," in interface:
            interface = [i.strip() for i in interface.split(",") if i.strip()]
        elif interface in ("all", "any"):
            interface = None
        else:
            try:
                from scapy.all import get_if_list
                if "lo" in get_if_list() and interface != "lo":
                    interface = [interface, "lo"]
                else:
                    interface = [interface]
            except Exception:
                interface = [interface]

    if interface in (None, "all", "any"):
        try:
            from scapy.all import get_if_list
            all_ifs = get_if_list()
            active = [i for i in ("wlan0", "eth0", "enp3s0", "lo") if i in all_ifs]
            interface = active if active else None
        except Exception:
            interface = None

    log.info("Loading model from %s", MODEL_PATH)
    clf = joblib.load(MODEL_PATH)

    os.makedirs("data", exist_ok=True)
    db_conn = sqlite3.connect(DB_PATH, timeout=15.0, check_same_thread=False)
    _init_db(db_conn)

    log.info("Pipeline started — sniffing on %s", interface or "default interface")

    cooldown = _AlertCooldown(ALERT_COOLDOWN)
    scan_tracker = CumulativeScanTracker(
        history_seconds=cfg("detection", "scan_window_seconds", default=120.0),
        threshold_ports=cfg("detection", "min_scan_ports", default=20),
        min_syn_ratio=cfg("detection", "min_syn_ratio", default=0.75),
        max_avg_pkt_size=cfg("detection", "max_scan_pkt_size", default=120.0),
    )

    with _manage_honeypot(), _graceful_shutdown(backend=backend) as shutdown_event:
        try:
            for feat in stream_features(interface=interface):
                if shutdown_event.is_set():
                    break

                src_ip = feat["src_ip"]
                if _is_whitelisted(src_ip):
                    continue

                is_cum_scan, cum_feat = scan_tracker.record_and_evaluate(src_ip, feat)

                X = [[feat.get(f, 0.0) for f in FEATURES]]

                proba = clf.predict_proba(X)[0]
                label = int(proba.argmax())
                confidence = float(proba[label])

                is_threat = (label != 0 and confidence >= MIN_CONFIDENCE)
                if is_threat:
                    # Adaptive threshold: act only when the classifier is decisive.
                    # A tight top-1/top-2 margin means the pick is ambiguous.
                    top2 = sorted((float(p) for p in proba), reverse=True)[:2]
                    if top2[1] and (top2[0] - top2[1]) < CONFIDENCE_MARGIN:
                        is_threat = False

                # If single-window did not trigger, check multi-window cumulative scan tracker
                if not is_threat and is_cum_scan:
                    label = 1  # port_scan
                    X_cum = [[cum_feat.get(f, 0.0) for f in FEATURES]]
                    cum_proba = clf.predict_proba(X_cum)[0]
                    confidence = max(float(cum_proba[1]), 0.90)
                    feat = cum_feat
                    is_threat = True
                    scan_tracker.reset(src_ip)

                if not is_threat:
                    continue

                # Redirect always (idempotent — keeps protection on during a flood).
                redirect_to_honeypot(src_ip, backend=backend)

                # Rate-limit alerts + DB rows per (source IP, attack type).
                if not cooldown.allowed(src_ip, label):
                    n = cooldown.note_suppressed(src_ip, label)
                    log.debug(
                        "Suppressed duplicate detection for src=%-15s type=%s (%d%s) — "
                        "cooldown %.0fs not elapsed",
                        src_ip,
                        ATTACK_LABELS[label],
                        n,
                        " consecutive" if n > 1 else "",
                        cooldown.cooldown,
                    )
                    continue

                cooldown.record(src_ip, label)

                log.warning(
                    "THREAT DETECTED  src=%-15s  type=%-10s  confidence=%.0f%%  "
                    "pps=%.1f  pktsize=%.0f  ports=%d  syn_ratio=%.2f",
                    src_ip,
                    ATTACK_LABELS[label],
                    confidence * 100,
                    feat["packets_per_sec"],
                    feat["avg_packet_size"],
                    feat["unique_ports"],
                    feat.get("syn_ratio", 0.0),
                )

                geo = dispatch(src_ip, label, confidence)
                _log_incident(db_conn, feat, label, confidence, geo)

        except KeyboardInterrupt:
            pass
        finally:
            db_conn.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Autonomous Network Shield pipeline")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff")
    parser.add_argument("--backend", "-b", default=None, choices=["iptables", "nftables"])
    args = parser.parse_args()

    run(interface=args.interface, backend=args.backend)
