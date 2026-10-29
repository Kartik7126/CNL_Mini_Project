import pandas as pd
from scapy.all import rdpcap, IP, TCP
import math

print("Loading PCAP file...")
packets = rdpcap("data/real_baseline.pcap")

WINDOW_SECONDS = 2
windows = {}

print("Extracting features...")
for pkt in packets:
    if IP in pkt and TCP in pkt:
        # Group by 2-second time buckets based on packet timestamp
        bucket_time = math.floor(float(pkt.time) / WINDOW_SECONDS) * WINDOW_SECONDS
        
        if bucket_time not in windows:
            windows[bucket_time] = []
        windows[bucket_time].append(pkt)

features = []
for bucket, pkts in windows.items():
    pps = len(pkts) / WINDOW_SECONDS
    
    # Calculate average packet size
    total_size = sum(len(p) for p in pkts)
    avg_pkt_size = total_size / len(pkts) if pkts else 0
    
    # Calculate unique ports
    unique_ports = len(set(p[TCP].dport for p in pkts))

    syn_pkts = sum(1 for p in pkts if (int(p[TCP].flags) & 0x02) and not (int(p[TCP].flags) & 0x10))
    syn_ratio = syn_pkts / len(pkts) if pkts else 0.0

    features.append({
        "packets_per_sec": pps,
        "avg_packet_size": avg_pkt_size,
        "unique_ports": unique_ports,
        "syn_ratio": syn_ratio,
        "label": 0  # All traffic in this PCAP is legitimate (normal = 0)
    })

df = pd.DataFrame(features)
df.to_csv("data/real_normal.csv", index=False)
print(f"Extraction complete! Saved {len(df)} windows to data/real_normal.csv")
