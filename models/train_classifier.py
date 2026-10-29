import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

LABEL_NORMAL = 0
LABEL_PORT_SCAN = 1
LABEL_SYN_FLOOD = 2

FEATURES = ["packets_per_sec", "avg_packet_size", "unique_ports", "syn_ratio"]

rng = np.random.default_rng(42)


def synthesize_normal(n=3500) -> pd.DataFrame:
    """Simulate diverse benign traffic: browsing, high-bandwidth streaming (YouTube), downloads, keepalives."""
    # 1. Standard web browsing, API calls, DNS (low-to-moderate PPS)
    n1 = int(n * 0.45)
    df1 = pd.DataFrame({
        "packets_per_sec": rng.normal(loc=15, scale=8, size=n1).clip(0.5, 60),
        "avg_packet_size": rng.normal(loc=450, scale=150, size=n1).clip(64, 1500),
        "unique_ports":    rng.integers(1, 8, size=n1),
        "syn_ratio":       rng.uniform(0.0, 0.15, size=n1),
        "label":           LABEL_NORMAL,
    })

    # 2. High-bandwidth media streaming (e.g. YouTube, Netflix) & large downloads
    # High PPS, large MTU packets (1000-1500 bytes), almost NO syn packets (established data transfer)
    n2 = int(n * 0.40)
    df2 = pd.DataFrame({
        "packets_per_sec": rng.uniform(60, 2500, size=n2),
        "avg_packet_size": rng.normal(loc=1150, scale=200, size=n2).clip(400, 1500),
        "unique_ports":    rng.integers(1, 5, size=n2),
        "syn_ratio":       rng.uniform(0.0, 0.03, size=n2),
        "label":           LABEL_NORMAL,
    })

    # 3. Idle / low-rate background connections (DNS, NTP, chat keepalives)
    n3 = n - n1 - n2
    df3 = pd.DataFrame({
        "packets_per_sec": rng.uniform(0.2, 5.0, size=n3),
        "avg_packet_size": rng.uniform(60, 250, size=n3),
        "unique_ports":    rng.integers(1, 3, size=n3),
        "syn_ratio":       rng.uniform(0.0, 0.10, size=n3),
        "label":           LABEL_NORMAL,
    })

    return pd.concat([df1, df2, df3], ignore_index=True)


def synthesize_port_scan(n=3000) -> pd.DataFrame:
    """Port scans: probe sweeps across many destination ports, small packets, high SYN ratio."""
    # 1. Moderate/stealth scans (5 to 120 PPS, 20 to 500 ports)
    n1 = int(n * 0.5)
    df1 = pd.DataFrame({
        "packets_per_sec": rng.uniform(5, 120, size=n1),
        "avg_packet_size": rng.normal(loc=60, scale=12, size=n1).clip(40, 100),
        "unique_ports":    rng.integers(20, 500, size=n1),
        "syn_ratio":       rng.uniform(0.80, 1.0, size=n1),
        "label":           LABEL_PORT_SCAN,
    })

    # 2. Fast/aggressive sweeps (120 to 2000 PPS, 50 to 1024 ports)
    n2 = n - n1
    df2 = pd.DataFrame({
        "packets_per_sec": rng.uniform(120, 2000, size=n2),
        "avg_packet_size": rng.normal(loc=54, scale=8, size=n2).clip(40, 90),
        "unique_ports":    rng.integers(50, 1024, size=n2),
        "syn_ratio":       rng.uniform(0.85, 1.0, size=n2),
        "label":           LABEL_PORT_SCAN,
    })

    return pd.concat([df1, df2], ignore_index=True)


def synthesize_syn_flood(n=2500) -> pd.DataFrame:
    """SYN floods: high volumetric or mid-rate floods of bare SYN packets to single/few target ports."""
    # Volumetric flood
    n_vol = int(n * 0.7)
    df_vol = pd.DataFrame({
        "packets_per_sec": rng.normal(loc=2500, scale=600, size=n_vol).clip(400, 8000),
        "avg_packet_size": rng.normal(loc=54, scale=8, size=n_vol).clip(40, 80),
        "unique_ports":    rng.integers(1, 4, size=n_vol),
        "syn_ratio":       rng.uniform(0.85, 1.0, size=n_vol),
        "label":           LABEL_SYN_FLOOD,
    })

    # Stealth / mid-rate flood
    n_mid = n - n_vol
    df_mid = pd.DataFrame({
        "packets_per_sec": rng.uniform(120, 500, size=n_mid),
        "avg_packet_size": rng.uniform(40, 80, size=n_mid),
        "unique_ports":    rng.integers(1, 5, size=n_mid),
        "syn_ratio":       rng.uniform(0.80, 1.0, size=n_mid),
        "label":           LABEL_SYN_FLOOD,
    })

    return pd.concat([df_vol, df_mid], ignore_index=True)


def load_real_baseline(csv_path="data/real_normal.csv") -> pd.DataFrame | None:
    if not os.path.exists(csv_path):
        return None
    try:
        df = pd.read_csv(csv_path)
        rename_map = {"pps": "packets_per_sec", "avg_pkt_size": "avg_packet_size"}
        df = df.rename(columns=rename_map)
        if "syn_ratio" not in df.columns:
            df["syn_ratio"] = 0.02
        if "label" in df.columns:
            df["label"] = df["label"].map({"normal": LABEL_NORMAL, 0: LABEL_NORMAL}).fillna(LABEL_NORMAL).astype(int)
        else:
            df["label"] = LABEL_NORMAL
        return df[FEATURES + ["label"]]
    except Exception as e:
        print(f"Warning: could not load real baseline from {csv_path}: {e}")
        return None


def build_dataset() -> pd.DataFrame:
    dfs = [
        synthesize_normal(3500),
        synthesize_port_scan(2000),
        synthesize_syn_flood(2500),
    ]
    real_df = load_real_baseline()
    if real_df is not None and len(real_df) > 0:
        print(f"Loaded {len(real_df)} real normal samples from data/real_normal.csv")
        dfs.append(real_df)

    dataset = pd.concat(dfs, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return dataset


def train(df: pd.DataFrame) -> RandomForestClassifier:
    X = df[FEATURES].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_leaf=4,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    label_names = ["normal", "port_scan", "syn_flood"]
    print("\nClassification Report on Test Split:")
    print(classification_report(y_test, y_pred, target_names=label_names))

    return clf


def main():
    os.makedirs("data", exist_ok=True)
    print("Generating enriched traffic dataset...")
    df = build_dataset()
    dataset_path = os.path.join("data", "traffic_dataset.csv")
    df.to_csv(dataset_path, index=False)
    print(f"Dataset saved -> {dataset_path} ({len(df)} samples)")

    print("\nTraining RandomForestClassifier...")
    clf = train(df)

    model_path = os.path.join("data", "network_model.pkl")
    joblib.dump(clf, model_path)
    print(f"\nModel saved -> {model_path}")


if __name__ == "__main__":
    main()