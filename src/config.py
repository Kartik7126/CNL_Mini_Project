"""Centralized configuration loader.

Reads ``config.yaml`` from the project root once, caches the result, and
exposes every section via ``get()`` with safe fallback defaults.  If the
file is missing or malformed the defaults keep the system running.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Any

log = logging.getLogger(__name__)

import yaml

# Resolve project root relative to this file (src/config.py -> project root)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_CONFIG = os.path.join(_PROJECT_ROOT, "config.yaml")

# --------------------------------------------------------------------------- #
#  Hard-coded fallbacks — mirrors every value in config.yaml
# --------------------------------------------------------------------------- #
_DEFAULTS: dict[str, Any] = {
    "network": {
        "interface": None,
        "sniff_filter": "ip",
        "window_seconds": 2,
    },
    "honeypot": {
        "enabled": True,
        "port": 2222,
        "db_path": "data/live_events.db",
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "start_timeout": 5.0,
    },
    "classifier": {
        "model_path": "data/network_model.pkl",
        "confidence_threshold": 0.70,
        "features": ["packets_per_sec", "avg_packet_size", "unique_ports"],
    },
    "firewall": {
        "backend": "iptables",
        "auto_flush_on_exit": True,
    },
    "alerts": {
        "telegram": {
            "enabled": True,
            "bot_token_env": "TELEGRAM_BOT_TOKEN",
            "chat_id_env": "TELEGRAM_CHAT_ID",
        },
    },
    "geo": {
        "provider": "ip-api.com",
        "cache_ttl_seconds": 3600,
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s  %(levelname)-8s  %(message)s",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning a new dict."""
    merged = base.copy()
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


@lru_cache(maxsize=1)
def _load(path: str = _DEFAULT_CONFIG) -> dict:
    """Load and cache config.yaml, merged on top of _DEFAULTS."""
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            user = yaml.safe_load(fh) or {}
        if isinstance(user, dict):
            return _deep_merge(_DEFAULTS, user)
    return _deep_merge(_DEFAULTS, {})


# --------------------------------------------------------------------------- #
#  Environment (.env) loading
# --------------------------------------------------------------------------- #

_env_loaded = False


def load_env(path: str | None = None) -> bool:
    """Load variables from a ``.env`` file into ``os.environ``.

    Safe to call from any entry point; the file is processed only once.
    Shell-supplied variables always win (``override=False``).

    Returns ``True`` if a file was loaded, ``False`` if none was found or
    ``python-dotenv`` is unavailable (env is then expected from the shell).
    """
    global _env_loaded
    if _env_loaded:
        return True

    loaded = False
    try:
        from dotenv import load_dotenv, find_dotenv
        search = path or find_dotenv() or os.path.join(_PROJECT_ROOT, ".env")
        loaded = bool(load_dotenv(search, override=False))
        if not loaded:
            log.debug("No .env file found at %s — using shell environment", search)
    except ImportError:
        log.debug("python-dotenv not installed — using shell environment only")
    except Exception as e:  # pragma: no cover - defensive
        log.warning("Could not load .env file: %s", e)

    _env_loaded = True
    return loaded


# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #

def get(section: str, key: str | None = None, *, default: Any = None) -> Any:
    """Read a config value.

    ``get("network", "window_seconds")``  -> ``2``
    ``get("network")``                     -> full section dict

    Falls back to *default* (or ``None``) when the key / section is absent.
    """
    cfg = _load()
    section_cfg = cfg.get(section, {})
    if key is None:
        return section_cfg if section_cfg else default
    return section_cfg.get(key, default)


def reload(path: str | None = None) -> dict:
    """Force-reload the config (useful in tests).  Returns the new tree."""
    _load.cache_clear()
    if path:
        return _load(path)
    return _load()
