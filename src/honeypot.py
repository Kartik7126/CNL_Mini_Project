import socket
import sqlite3
import threading
import time
import logging
from datetime import datetime, timezone

from config import get as cfg

log = logging.getLogger(__name__)

HONEYPOT_PORT = cfg("honeypot", "port", default=2222)
DB_PATH       = cfg("honeypot", "db_path", default="data/live_events.db")

_banner_str   = cfg("honeypot", "banner", default="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
BANNER        = (_banner_str + "\r\n").encode()
SHELL_PROMPT = b"root@ubuntu:~# "
FAKE_AUTH_PROMPT = b"Password: "

_db_lock = threading.Lock()


def _make_writable(path: str = DB_PATH):
    import os
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
        CREATE TABLE IF NOT EXISTS connections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip      TEXT NOT NULL,
            src_port    INTEGER NOT NULL,
            connected_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            conn_id     INTEGER REFERENCES connections(id),
            username    TEXT,
            password    TEXT,
            captured_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS keystrokes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            conn_id     INTEGER REFERENCES connections(id),
            data        TEXT,
            captured_at TEXT NOT NULL
        );
    """)
    conn.commit()
    _make_writable(DB_PATH)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_connection(conn: sqlite3.Connection, src_ip: str, src_port: int) -> int:
    with _db_lock:
        cur = conn.execute(
            "INSERT INTO connections (src_ip, src_port, connected_at) VALUES (?, ?, ?)",
            (src_ip, src_port, _now()),
        )
        conn.commit()
        return cur.lastrowid


def _log_credentials(conn: sqlite3.Connection, conn_id: int, username: str, password: str):
    with _db_lock:
        conn.execute(
            "INSERT INTO credentials (conn_id, username, password, captured_at) VALUES (?, ?, ?, ?)",
            (conn_id, username, password, _now()),
        )
        conn.commit()


def _log_keystrokes(conn: sqlite3.Connection, conn_id: int, data: str):
    with _db_lock:
        conn.execute(
            "INSERT INTO keystrokes (conn_id, data, captured_at) VALUES (?, ?, ?)",
            (conn_id, data, _now()),
        )
        conn.commit()


def _recv_line(sock: socket.socket, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            ch = sock.recv(1)
            if not ch or ch in (b"\n", b"\r"):
                break
            if ch == b"\x7f" and buf:  # backspace
                buf = buf[:-1]
            elif ch >= b" ":
                buf += ch
    except (socket.timeout, ConnectionResetError):
        pass
    return buf


def _handle_client(client: socket.socket, addr: tuple, db_conn: sqlite3.Connection):
    src_ip, src_port = addr
    log.info("Honeypot connection from %s:%d", src_ip, src_port)
    conn_id = _log_connection(db_conn, src_ip, src_port)

    try:
        client.sendall(BANNER)

        # Fake credential prompt — capture up to 3 attempts
        for attempt in range(3):
            client.sendall(b"login: ")
            username = _recv_line(client).decode(errors="replace").strip()
            client.sendall(FAKE_AUTH_PROMPT)
            password = _recv_line(client).decode(errors="replace").strip()

            if username or password:
                _log_credentials(db_conn, conn_id, username, password)
                log.info("Captured creds from %s — user=%r pass=%r", src_ip, username, password)

            client.sendall(b"\r\nAuthentication failure.\r\n")

        # Drop to fake shell after exhausting auth (simulates misconfigured system)
        client.sendall(b"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n\r\n")
        client.sendall(SHELL_PROMPT)

        while True:
            client.settimeout(30.0)
            try:
                data = client.recv(256)
            except socket.timeout:
                break
            if not data:
                break

            decoded = data.decode(errors="replace").strip()
            if decoded:
                _log_keystrokes(db_conn, conn_id, decoded)
                log.debug("Keystroke from %s: %r", src_ip, decoded)

            # Plausible-looking responses to common recon commands
            response = _fake_response(decoded)
            client.sendall(response + SHELL_PROMPT)

    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.warning("Honeypot session error (%s): %s", src_ip, e)
    finally:
        client.close()


_FAKE_RESPONSES: dict[str, bytes] = {
    "whoami":   b"root\r\n",
    "id":       b"uid=0(root) gid=0(root) groups=0(root)\r\n",
    "uname -a": b"Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n",
    "ls":       b"bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n",
    "pwd":      b"/root\r\n",
    "ifconfig": b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.2.15  netmask 255.255.255.0\r\n",
    "exit":     b"logout\r\n",
}


def _fake_response(cmd: str) -> bytes:
    return _FAKE_RESPONSES.get(cmd.lower(), b"bash: " + cmd.encode() + b": command not found\r\n")


class Honeypot:
    def __init__(self, port: int = HONEYPOT_PORT, db_path: str = DB_PATH):
        self.port = port
        self.db_path = db_path
        self._running = False

    def start(self):
        db_conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        _init_db(db_conn)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", self.port))
        server.listen(32)
        self._running = True
        log.info("Honeypot listening on port %d", self.port)

        try:
            while self._running:
                server.settimeout(1.0)
                try:
                    client, addr = server.accept()
                except socket.timeout:
                    continue
                t = threading.Thread(
                    target=_handle_client,
                    args=(client, addr, db_conn),
                    daemon=True,
                )
                t.start()
        finally:
            server.close()
            db_conn.close()

    def stop(self):
        self._running = False
