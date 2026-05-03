from scapy.all import sniff, IP
import time
import numpy as np
from collections import defaultdict
from tensorflow.keras.models import load_model
import joblib
import threading
import json

# 🔥 AUTO CLEAR OLD LOGS
with open("alerts.json", "w") as f:
    f.write("[]")

# 🔹 Load model + scaler
model = load_model("model.h5", compile=False)
scaler = joblib.load("scaler.pkl")

THRESHOLD = 1.0  # 🔥 REDUCED ALERTS

flows = defaultdict(list)

print("🚀 Live detection started on eth0...")


# 🔹 Packet capture
def process_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto

    key = (src, dst, proto)

    flows[key].append((time.time(), len(pkt)))

    if len(flows[key]) % 50 == 0:
        print(f"📦 {len(flows[key])} packets in flow {key}")


# 🔹 Feature extraction (31 features)
def extract_features(pkts):
    if len(pkts) < 2:
        return None

    times = [p[0] for p in pkts]
    lengths = [p[1] for p in pkts]

    iats = np.diff(times)
    if len(iats) == 0:
        iats = [0]

    features = [
        0, 0, 0,
        len(pkts),
        0,
        np.mean(iats), np.mean(iats),
        np.std(iats), np.std(iats),
        np.min(iats), np.min(iats),
        np.max(iats), np.max(iats),
        0, 0,
        np.mean(lengths), 0,
        np.std(lengths), 0,
        np.min(lengths), 0,
        np.max(lengths), 0,
        sum(lengths),
        0,
        0, 0, 0, 0, 0, 0
    ]

    return features[:31]


# 🔥 STRICT ATTACK CLASSIFIER (REDUCED FALSE ALERTS)
def classify_attack(pkts, error, key):
    pkt_count = len(pkts)

    times = [p[0] for p in pkts]
    iats = np.diff(times)
    avg_iat = np.mean(iats) if len(iats) > 0 else 1

    proto = key[2]

    # 🔥 ICMP Flood (more strict)
    if proto == 1 and pkt_count > 200:
        return "ICMP Flood"

    # 🔥 Traffic Flood (more strict)
    elif pkt_count > 150 and avg_iat < 0.02:
        return "Traffic Flood"

    # 🔥 Port Scan
    elif pkt_count < 5 and error > THRESHOLD:
        return "Port Scan"

    # 🔥 Strong anomaly only
    elif error > THRESHOLD:
        return "Anomaly"

    else:
        return "Normal"


# 🔹 Save alerts
def log_alert(flow, error, attack_type):
    data = []

    try:
        with open("alerts.json", "r") as f:
            data = json.load(f)
    except:
        pass

    data.append({
        "time": time.strftime("%H:%M:%S"),
        "flow": str(flow),
        "error": round(error, 4),
        "type": attack_type
    })

    with open("alerts.json", "w") as f:
        json.dump(data[-50:], f)


# 🔹 Analyze flows every 8 sec
def analyze():
    while True:
        time.sleep(8)

        if not flows:
            continue

        print("\n🔍 Analyzing flows...\n")

        for key in list(flows.keys()):
            pkts = flows[key]

            features = extract_features(pkts)
            if features is None:
                continue

            X = np.array(features).reshape(1, -1)

            try:
                X_scaled = scaler.transform(X)
            except Exception as e:
                print("❌ SCALER ERROR:", e)
                continue

            pred = model.predict(X_scaled, verbose=0)
            error = np.mean((X_scaled - pred) ** 2)

            attack_type = classify_attack(pkts, error, key)

            print(f"🔥 FLOW: {key}")
            print(f"Packets: {len(pkts)}")
            print(f"Error: {round(error, 4)}")

            if attack_type != "Normal":
                print(f"🚨 {attack_type}")
                log_alert(key, error, attack_type)
            else:
                print("✅ Normal")

            print("-" * 50)

        flows.clear()


# 🔹 Start sniffing
threading.Thread(
    target=lambda: sniff(iface="eth0", prn=process_packet, store=False),
    daemon=True
).start()

# 🔹 Start detection
analyze()
