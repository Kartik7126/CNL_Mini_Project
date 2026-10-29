import json
import logging
import re
import subprocess
import sys

from config import get as cfg

log = logging.getLogger(__name__)

HONEYPOT_PORT = cfg("honeypot", "port", default=2222)
_LINUX = sys.platform.startswith("linux")


def _run(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        log.warning("firewall command failed: %s", e.stderr.decode().strip())
        return False


def _run_output(cmd: list[str]) -> tuple[bool, str]:
    try:
        res = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True, res.stdout
    except (subprocess.CalledProcessError, OSError) as e:
        stderr = e.stderr.strip() if hasattr(e, "stderr") and e.stderr else str(e)
        log.warning("firewall command failed %s: %s", cmd, stderr)
        return False, ""


# --- iptables backend ---

def _ipt_redirect(ip: str) -> bool:
    return _run([
        "iptables", "-t", "nat", "-I", "PREROUTING", "1",
        "-s", ip,
        "-p", "tcp",
        "-m", "conntrack", "--ctstate", "NEW",
        "-j", "REDIRECT", "--to-port", str(HONEYPOT_PORT),
    ])


def _ipt_remove(ip: str) -> bool:
    return _run([
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-s", ip,
        "-p", "tcp",
        "-m", "conntrack", "--ctstate", "NEW",
        "-j", "REDIRECT", "--to-port", str(HONEYPOT_PORT),
    ])


def _ipt_flush() -> bool:
    return _run(["iptables", "-t", "nat", "-F", "PREROUTING"])


# --- nftables backend ---

def _nft_redirect(ip: str) -> bool:
    rule = (
        f"add rule ip nat PREROUTING ip saddr {ip} "
        f"ct state new tcp dport != {HONEYPOT_PORT} redirect to :{HONEYPOT_PORT}"
    )
    return _run(["nft", rule])


def _nft_remove(ip: str) -> bool:
    """Remove redirect rule for *ip* in nftables by querying rule handles."""
    handles: list[str] = []

    # 1. Try JSON listing first (nftables >= 0.9.0)
    ok, stdout = _run_output(["nft", "-j", "list", "chain", "ip", "nat", "PREROUTING"])
    if ok and stdout.strip():
        try:
            data = json.loads(stdout)
            for item in data.get("nftables", []):
                rule = item.get("rule", {})
                if rule.get("chain") != "PREROUTING":
                    continue
                exprs = rule.get("expr", [])
                for expr in exprs:
                    match = expr.get("match", {})
                    right = match.get("right")
                    if right == ip or (isinstance(right, dict) and right.get("value") == ip):
                        if "handle" in rule:
                            handles.append(str(rule["handle"]))
        except Exception as e:
            log.debug("nftables JSON parse fallback to text: %s", e)

    # 2. Fallback to text listing with handles (-a) if JSON yielded no handle
    if not handles:
        ok, stdout = _run_output(["nft", "-a", "list", "chain", "ip", "nat", "PREROUTING"])
        if ok and stdout.strip():
            pattern = re.compile(r"ip\s+saddr\s+" + re.escape(ip) + r"\b.*?#\s*handle\s+(\d+)")
            handles = pattern.findall(stdout)

    if not handles:
        log.debug("No nftables rule handle found for IP %s", ip)
        return True

    success = True
    for handle in handles:
        cmd = ["nft", "delete", "rule", "ip", "nat", "PREROUTING", "handle", handle]
        if not _run(cmd):
            success = False
            log.warning("Failed to delete nftables rule handle %s for IP %s", handle, ip)

    return success


def _nft_flush() -> bool:
    return _run(["nft", "flush", "chain", "ip", "nat", "PREROUTING"])


# --- public API ---

_active_redirects: set[str] = set()


def redirect_to_honeypot(ip: str, backend: str = "iptables") -> bool:
    if not _LINUX:
        log.info("[stub] would redirect %s -> honeypot:%d", ip, HONEYPOT_PORT)
        _active_redirects.add(ip)
        return True

    if ip in _active_redirects:
        return True

    ok = _ipt_redirect(ip) if backend == "iptables" else _nft_redirect(ip)
    if ok:
        _active_redirects.add(ip)
        log.info("Redirected %s to honeypot (port %d)", ip, HONEYPOT_PORT)
    return ok


def remove_redirect(ip: str, backend: str = "iptables") -> bool:
    if not _LINUX:
        log.info("[stub] would remove redirect for %s", ip)
        _active_redirects.discard(ip)
        return True

    ok = _ipt_remove(ip) if backend == "iptables" else _nft_remove(ip)
    if ok:
        _active_redirects.discard(ip)
        log.info("Removed redirect for %s", ip)
    return ok


def flush_all_redirects(backend: str = "iptables") -> bool:
    if not _LINUX:
        log.info("[stub] would flush all PREROUTING redirects (%d active)", len(_active_redirects))
        _active_redirects.clear()
        return True

    ok = _ipt_flush() if backend == "iptables" else _nft_flush()
    if ok:
        _active_redirects.clear()
        log.info("Flushed all PREROUTING redirect rules")
    return ok


def active_redirects() -> set[str]:
    return frozenset(_active_redirects)
