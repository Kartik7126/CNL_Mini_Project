import ipaddress
import logging
import os
import time

import requests

from config import get as cfg, load_env

# Ensure .env is loaded before any credential is read (idempotent).
load_env()

log = logging.getLogger(__name__)

TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"

# Credential env-var names come from config.yaml (alerts.telegram section).
_tele_cfg      = cfg("alerts", "telegram", default={})
_ALERTS_ENABLED = _tele_cfg.get("enabled", True)
_BOT_TOKEN_ENV = _tele_cfg.get("bot_token_env", "TELEGRAM_BOT_TOKEN")
_CHAT_ID_ENV   = _tele_cfg.get("chat_id_env", "TELEGRAM_CHAT_ID")

_missing_creds_warned = False


def telegram_configured() -> bool:
    """True when Telegram credentials are present in the environment."""
    return bool(os.environ.get(_BOT_TOKEN_ENV, "") and os.environ.get(_CHAT_ID_ENV, ""))


def _warn_missing_credentials(ip: str) -> None:
    """Log a clear warning the first time credentials are found missing."""
    global _missing_creds_warned
    if not _missing_creds_warned:
        log.warning(
            "Telegram alerting unavailable: set %s and %s in the environment "
            "(copy .env.example to .env, or export them) — skipping alert for %s",
            _BOT_TOKEN_ENV, _CHAT_ID_ENV, ip,
        )
        _missing_creds_warned = True

_geo_cache: dict[str, dict] = {}
_GEO_TTL = 3600  # seconds


_PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def geolocate(ip: str) -> dict:
    if _is_private(ip):
        return {
            "country": "Local/Private Network",
            "city":    "",
            "region":  "",
            "isp":     "",
            "lat":     0.0,
            "lon":     0.0,
        }

    cached = _geo_cache.get(ip)
    if cached and (time.time() - cached["_ts"]) < _GEO_TTL:
        return {k: v for k, v in cached.items() if k != "_ts"}

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,isp,lat,lon"},
            timeout=4,
        )
        data = resp.json()
    except Exception as e:
        log.warning("Geolocation request failed for %s: %s", ip, e)
        return {"country": "Unknown", "city": "", "region": "", "isp": "", "lat": 0.0, "lon": 0.0}

    if data.get("status") != "success":
        return {"country": "Unknown", "city": "", "region": "", "isp": "", "lat": 0.0, "lon": 0.0}

    result = {
        "country": data.get("country", ""),
        "city":    data.get("city", ""),
        "region":  data.get("regionName", ""),
        "isp":     data.get("isp", ""),
        "lat":     data.get("lat", 0.0),
        "lon":     data.get("lon", 0.0),
    }
    _geo_cache[ip] = {**result, "_ts": time.time()}
    return result


_ATTACK_LABELS = {
    0: "Normal",
    1: "Port Scan",
    2: "SYN Flood",
}


def _format_message(ip: str, attack_type: int, confidence: float, geo: dict) -> str:
    label = _ATTACK_LABELS.get(attack_type, "Unknown")
    location_parts = filter(None, [geo.get("city"), geo.get("region"), geo.get("country")])
    location = ", ".join(location_parts) or "Unknown"
    isp = geo.get("isp") or "Unknown"

    return (
        f"*[NETWORK ALERT]* Threat Detected\n\n"
        f"*Attacker IP:* `{ip}`\n"
        f"*Attack Type:* {label}\n"
        f"*Confidence:* {confidence:.1%}\n"
        f"*Location:* {location}\n"
        f"*ISP:* {isp}\n"
        f"*Action:* Redirected to honeypot"
    )


def send_telegram_alert(ip: str, attack_type: int, confidence: float, geo: dict) -> bool:
    if not _ALERTS_ENABLED:
        log.debug("Telegram alerts disabled in config — skipping alert for %s", ip)
        return False

    # Read credentials lazily so the value reflects the loaded environment.
    bot_token = os.environ.get(_BOT_TOKEN_ENV, "")
    chat_id   = os.environ.get(_CHAT_ID_ENV, "")
    if not bot_token or not chat_id:
        _warn_missing_credentials(ip)
        return False

    message = _format_message(ip, attack_type, confidence, geo)
    url = TELEGRAM_API_URL.format(token=bot_token)

    try:
        resp = requests.post(
            url,
            json={
                "chat_id":    chat_id,
                "text":       message,
                "parse_mode": "Markdown",
            },
            timeout=6,
        )
        if resp.status_code == 200:
            log.info("Telegram alert sent for %s (%s)", ip, _ATTACK_LABELS.get(attack_type))
            return True
        log.warning("Telegram API error %d: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        log.warning("Failed to send Telegram alert: %s", e)

    return False


def dispatch(ip: str, attack_type: int, confidence: float):
    geo = geolocate(ip)
    send_telegram_alert(ip, attack_type, confidence, geo)
    return geo
