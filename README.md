# 🚀 AI-Based Network Intrusion Detection System with Real-Time Dashboard

## 📌 Overview
This project is an AI-powered Network Intrusion Detection System (IDS) that detects abnormal network traffic in real-time using machine learning. It captures live packets, analyzes traffic patterns, and displays detected attacks on a dynamic web dashboard.

## 🔥 Features
- Real-time packet capture using Scapy  
- AI-based anomaly detection using Autoencoder  
- Detection of common attacks:
  - ICMP Flood (DoS)
  - Traffic Flood
  - Port Scan
  - General Anomalies  
- Live dashboard built with Flask  
- Automatic alert logging (alerts.json)  
- Color-coded visualization (Normal vs Attack)  
- Adjustable detection threshold to reduce false positives  

## 🛠️ Technologies Used
- Python  
- Scapy  
- TensorFlow / Keras  
- NumPy & Pandas  
- Flask  
- Joblib  

## 📂 Project Structure
AI_IDS_Project/
│
├── live_detect.py        # Real-time packet capture & detection  
├── app.py                # Flask dashboard backend  
├── model.h5              # Trained autoencoder model  
├── scaler.pkl            # Feature scaler  
├── alerts.json           # Stores detected alerts  
│
├── templates/  
│   └── index.html        # Dashboard UI  
│
└── README.md  

## ⚙️ Installation
pip install scapy tensorflow flask numpy pandas joblib

## ▶️ How to Run
Step 1: Start Intrusion Detection  
sudo python live_detect.py  

Step 2: Start Dashboard  
python app.py  

Step 3: Open Browser  
http://127.0.0.1:5000  

## 🧪 Testing the System
Normal Traffic:
ping google.com  
Expected: Normal traffic (no alerts)

Attack Simulation:
ping -f 8.8.8.8  
Expected: Detected as ICMP Flood

## 📊 How It Works
1. Packets are captured in real-time using Scapy  
2. Traffic is grouped into flows (IP + Protocol)  
3. Features are extracted (31 features per flow)  
4. Data is scaled using a trained scaler  
5. Autoencoder reconstructs input  
6. Reconstruction error is calculated  
7. If error exceeds threshold → Attack detected  
8. Alerts are logged and displayed on dashboard  

## ⚠️ Notes
- Root privileges are required for packet sniffing  
- alerts.json updates in real-time  
- Dashboard refreshes every 2 seconds  
- Threshold tuning helps reduce false positives  

## 🚀 Future Improvements
- Add more attack detection (SYN Flood, DNS attacks)  
- Add graphs and analytics dashboard  
- Email/SMS alert system  
- Cloud deployment (AWS / Azure)  
- Improve model accuracy  



## ⭐ If you found this useful
Give this repo a star ⭐
