import sqlite3
import time
import os
import sys

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from config import get as cfg
from utils import to_ist as _to_ist

DB_PATH = cfg("honeypot", "db_path", default=os.path.join(os.path.dirname(__file__), "..", "data", "live_events.db"))
REFRESH_INTERVAL = 5  # seconds

st.set_page_config(
    page_title="Autonomous Network Shield",
    page_icon="shield",
    layout="wide",
)

st.title("Autonomous Network Shield")
st.caption("Live intrusion detection and honeypot telemetry")

# --- Mobile Responsive CSS ---
st.markdown("""
<style>
@media (max-width: 768px) {
    /* Responsive padding */
    .block-container {
        padding-top: 1.5rem !important;
        padding-left: 0.75rem !important;
        padding-right: 0.75rem !important;
    }
    /* Touch-friendly metric cards */
    [data-testid="stMetric"] {
        background-color: rgba(128, 128, 128, 0.08);
        border: 1px solid rgba(128, 128, 128, 0.18);
        border-radius: 10px;
        padding: 8px 12px !important;
        margin-bottom: 8px;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.4rem !important;
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.85rem !important;
    }
    /* Full-width touch-friendly buttons */
    .stButton button {
        width: 100% !important;
        min-height: 42px !important;
        font-size: 0.95rem !important;
    }
    /* Smooth horizontal table scroll on touch screens */
    [data-testid="stDataFrame"] {
        overflow-x: auto !important;
        -webkit-overflow-scrolling: touch !important;
    }
    /* Typography scaling */
    h1 {
        font-size: 1.6rem !important;
    }
    h2, h3 {
        font-size: 1.25rem !important;
    }
}
</style>
""", unsafe_allow_html=True)



def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass
    return conn


def load_incidents(conn: sqlite3.Connection) -> pd.DataFrame:
    try:
        df = pd.read_sql_query(
            "SELECT * FROM incidents ORDER BY detected_at DESC LIMIT 500",
            conn,
        )
    except Exception:
        df = pd.DataFrame(columns=[
            "id", "src_ip", "attack_type", "confidence", "pps",
            "avg_pkt_size", "unique_ports", "country", "city", "isp", "detected_at",
        ])
    return df


def load_honeypot_sessions(conn: sqlite3.Connection) -> pd.DataFrame:
    try:
        df = pd.read_sql_query(
            """SELECT c.src_ip, c.connected_at,
                      cr.username, cr.password,
                      cr.captured_at AS cred_time
               FROM connections c
               LEFT JOIN credentials cr ON cr.conn_id = c.id
               ORDER BY c.connected_at DESC
               LIMIT 200""",
            conn,
        )
        if not df.empty:
            if "connected_at" in df.columns:
                df["connected_at"] = _to_ist(df["connected_at"])
            if "cred_time" in df.columns:
                df["cred_time"] = _to_ist(df["cred_time"])
    except Exception:
        df = pd.DataFrame()
    return df


def load_keystrokes(conn: sqlite3.Connection) -> pd.DataFrame:
    try:
        df = pd.read_sql_query(
            """SELECT c.src_ip, k.data, k.captured_at
               FROM keystrokes k
               JOIN connections c ON c.id = k.conn_id
               ORDER BY k.captured_at DESC
               LIMIT 100""",
            conn,
        )
        if not df.empty and "captured_at" in df.columns:
            df["captured_at"] = _to_ist(df["captured_at"])
    except Exception:
        df = pd.DataFrame()
    return df



def _clear_table(mode: str = "incidents"):
    conn = get_connection()
    try:
        if mode == "incidents":
            conn.execute("DELETE FROM incidents")
        else:
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM keystrokes")
            conn.execute("DELETE FROM credentials")
            conn.execute("DELETE FROM connections")
        conn.commit()
    except sqlite3.OperationalError:
        conn.close()
        # Fallback if files were locked or had root-only write permissions:
        # Directory is owned by current user, so remove and re-initialize cleanly
        for ext in ("", "-wal", "-shm"):
            p = DB_PATH + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass
        conn = get_connection()
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
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                connected_at TEXT
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conn_id INTEGER,
                username TEXT,
                password TEXT,
                captured_at TEXT
            );
            CREATE TABLE IF NOT EXISTS keystrokes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conn_id INTEGER,
                data TEXT,
                captured_at TEXT
            );
        """)
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        for ext in ("", "-wal", "-shm"):
            p = DB_PATH + ext
            if os.path.exists(p):
                try:
                    os.chmod(p, 0o666)
                except Exception:
                    pass


# --- sidebar controls ---
with st.sidebar:
    st.header("Settings")
    auto_refresh = st.toggle("Auto-refresh", value=True)
    refresh_rate = st.slider("Refresh interval (s)", 2, 30, REFRESH_INTERVAL)
    st.divider()
    st.markdown("**Attack labels**")
    st.markdown("- `port_scan` — horizontal port sweep")
    st.markdown("- `syn_flood` — volumetric TCP SYN attack")
    st.divider()
    if st.button("Force refresh now", use_container_width=True):
        st.rerun()
    st.divider()
    st.markdown("**Database Management**")
    if st.button("🗑️ Clear Incident Logs", help="Wipes recorded incidents from live_events.db", use_container_width=True):
        _clear_table("incidents")
        st.success("Incident logs cleared!")
        time.sleep(0.3)
        st.rerun()

    if st.button("🧹 Clear All Telemetry", help="Clears incidents, honeypot sessions, and keystrokes", use_container_width=True):
        _clear_table("all")
        st.success("All database logs cleared!")
        time.sleep(0.3)
        st.rerun()


conn = get_connection()
incidents_df = load_incidents(conn)
sessions_df  = load_honeypot_sessions(conn)
keystrokes_df = load_keystrokes(conn)
conn.close()

# --- KPI tiles ---
total_incidents = len(incidents_df)
unique_attackers = incidents_df["src_ip"].nunique() if not incidents_df.empty else 0
port_scans  = (incidents_df["attack_type"] == "port_scan").sum()  if not incidents_df.empty else 0
syn_floods  = (incidents_df["attack_type"] == "syn_flood").sum()  if not incidents_df.empty else 0

k1, k2, k3, k4 = st.columns(4)
k1.metric("Total Incidents",    total_incidents)
k2.metric("Unique Attackers",   unique_attackers)
k3.metric("Port Scans",         port_scans)
k4.metric("SYN Floods",         syn_floods)

st.divider()

# --- incident log ---
col_title, col_clear = st.columns([3, 1])
with col_title:
    st.subheader("Incident Log")
with col_clear:
    if st.button("🗑️ Clear Logs", key="clear_incidents_btn", use_container_width=True):
        _clear_table("incidents")
        st.success("Cleared!")
        time.sleep(0.3)
        st.rerun()

if incidents_df.empty:
    st.info("No incidents recorded yet. Start the pipeline to begin monitoring.")
else:
    has_syn = "syn_ratio" in incidents_df.columns
    base_cols = ["detected_at", "src_ip", "attack_type", "confidence", "pps", "avg_pkt_size", "unique_ports"]
    if has_syn:
        base_cols.append("syn_ratio")
    base_cols += ["country", "city", "isp"]
    display_cols = [c for c in base_cols if c in incidents_df.columns]
    display = incidents_df[display_cols].copy()
    display["detected_at"] = _to_ist(display["detected_at"])
    display["confidence"] = (display["confidence"] * 100).round(1).map("{:.1f}%".format)
    display["pps"] = display["pps"].round(1)
    display["avg_pkt_size"] = display["avg_pkt_size"].round(1)
    if has_syn:
        display["syn_ratio"] = (display["syn_ratio"].fillna(0.0) * 100).round(1).map("{:.1f}%".format)
    col_names = ["Time (IST)", "Src IP", "Attack", "Confidence", "Pkt/s", "Avg Pkt Size", "Ports"]
    if has_syn:
        col_names.append("SYN %")
    col_names += ["Country", "City", "ISP"]
    display.columns = col_names[:len(display.columns)]

    # Valid RGBA CSS injection
    attack_colors = {
        "port_scan": "rgba(255, 165, 0, 0.15)",
        "syn_flood": "rgba(255, 0, 0, 0.15)"
    }

    def highlight_attack(row):
        color = attack_colors.get(row["Attack"], "")
        return [f"background-color: {color}" if color else "" for _ in row]

    st.dataframe(
        display.style.apply(highlight_attack, axis=1),
        use_container_width=True,
        hide_index=True,
    )

st.divider()

# --- attack distribution chart ---
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Attack Breakdown")
    if not incidents_df.empty:
        breakdown = incidents_df["attack_type"].value_counts().to_frame("Count")
        breakdown.index.name = "Type"
        st.bar_chart(breakdown)
    else:
        st.caption("No data yet.")

with col_right:
    st.subheader("Top Attacking Countries")
    if not incidents_df.empty and "country" in incidents_df.columns:
        geo_counts = (
            incidents_df[incidents_df["country"] != ""]
            ["country"]
            .value_counts()
            .head(10)
            .to_frame("Incidents")
        )
        geo_counts.index.name = "Country"
        st.bar_chart(geo_counts)
    else:
        st.caption("No geolocation data yet.")

st.divider()

# --- honeypot sessions ---
st.subheader("Honeypot — Captured Credentials")

if sessions_df.empty:
    st.info("No honeypot connections recorded yet.")
else:
    sessions_disp = sessions_df.copy()
    col_map = {
        "src_ip": "Attacker IP",
        "connected_at": "Connected (IST)",
        "username": "Username",
        "password": "Password",
        "cred_time": "Captured (IST)",
    }
    sessions_disp.rename(columns=col_map, inplace=True)
    st.dataframe(sessions_disp, use_container_width=True, hide_index=True)

st.divider()

# --- live keystrokes ---
st.subheader("Honeypot — Live Keystrokes")

if keystrokes_df.empty:
    st.caption("No keystroke data captured yet.")
else:
    for _, row in keystrokes_df.iterrows():
        st.code(f"[{row['captured_at']}]  {row['src_ip']}  >  {row['data']}", language="bash")

# --- auto-refresh ---
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()