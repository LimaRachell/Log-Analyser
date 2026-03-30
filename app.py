import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

st.set_page_config(layout="wide")
st.title("🛡️ Cyber Attack Analyzer (Advanced SOC Dashboard)")

uploaded_file = st.file_uploader("Upload cybersecurity_attack.csv", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    df.columns = df.columns.str.strip()
    df.fillna(0, inplace=True)

    st.write("📌 Columns detected:", df.columns)

    # -------------------------
    # SAFE COLUMN HANDLER
    # -------------------------
    def get_col(name):
        return df[name] if name in df.columns else pd.Series([0]*len(df))

    # Convert numeric safely
    for col in ["Source Port", "Destination Port", "Packet Length", "Anomaly Scores"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    # -------------------------
    # BASIC FEATURES
    # -------------------------
    dest_port = get_col("Destination Port")
    packet_len = get_col("Packet Length")
    anomaly = get_col("Anomaly Scores")

    df["Suspicious_Port"] = dest_port.apply(lambda x: 1 if x in [22, 21, 23, 80, 443, 3389, 445] else 0)
    df["Large_Packet"] = packet_len.apply(lambda x: 1 if x > 1200 else 0)
    df["High_Anomaly"] = anomaly.apply(lambda x: 1 if x > 0.7 else 0)

    # -------------------------
    # ML MODEL
    # -------------------------
    features = [col for col in ["Packet Length", "Source Port", "Destination Port", "Anomaly Scores"] if col in df.columns]

    if len(features) >= 2:
        try:
            model = IsolationForest(contamination=0.05, random_state=42)
            df["ML_Anomaly"] = model.fit_predict(df[features])
            df["ML_Anomaly"] = df["ML_Anomaly"].apply(lambda x: 1 if x == -1 else 0)
        except:
            df["ML_Anomaly"] = 0
    else:
        df["ML_Anomaly"] = 0

    # -------------------------
    # ADVANCED LOG FEATURES
    # -------------------------
    if "Source IP Address" in df.columns:
        ip_counts = df["Source IP Address"].value_counts()
        df["Request_Count"] = df["Source IP Address"].map(ip_counts)
    else:
        df["Request_Count"] = 0

    if "Source IP Address" in df.columns and "Destination Port" in df.columns:
        df["Unique_Ports"] = df.groupby("Source IP Address")["Destination Port"].transform("nunique")
    else:
        df["Unique_Ports"] = 0

    if "Source IP Address" in df.columns and "Destination IP Address" in df.columns:
        df["Unique_Destinations"] = df.groupby("Source IP Address")["Destination IP Address"].transform("nunique")
    else:
        df["Unique_Destinations"] = 0

    # -------------------------
    # ATTACK DETECTION
    # -------------------------
    def detect_attack(row):
        port = row.get("Destination Port", 0)
        protocol = str(row.get("Protocol", "")).lower()
        malware = str(row.get("Malware Indicators", "")).lower()

        if row["ML_Anomaly"] == 1 and row["High_Anomaly"] == 1:
            return "Zero-Day Attack"
        if row["Unique_Ports"] > 10:
            return "Port Scanning"
        if row["Request_Count"] > 50:
            return "DDoS Attack"
        if row["Request_Count"] > 20 and port in [22, 21, 3389]:
            return "Brute Force Attack"
        if row["Unique_Destinations"] > 10:
            return "Lateral Movement"
        if "malware" in malware:
            return "Malware Communication"
        if protocol not in ["tcp", "udp", "icmp"] and protocol != "":
            return "Suspicious Protocol"
        if row["Large_Packet"] == 1 and row["High_Anomaly"] == 1:
            return "Data Exfiltration"
        if port == 22:
            return "SSH Attack"
        if port == 3389:
            return "RDP Attack"
        if port == 445:
            return "SMB Exploit"
        if port == 80:
            return "HTTP Flood"
        return "Normal"

    df["Attack_Type"] = df.apply(detect_attack, axis=1)

    # -------------------------
    # RISK SCORE + SEVERITY
    # -------------------------
    def risk_score(row):
        return (
            row["Suspicious_Port"]*2 +
            row["Large_Packet"]*2 +
            row["High_Anomaly"]*3 +
            row["ML_Anomaly"]*4 +
            (row["Request_Count"] > 50)*3 +
            (row["Unique_Ports"] > 10)*2
        )

    df["Risk_Score"] = df.apply(risk_score, axis=1)

    def severity(score):
        if score >= 8:
            return "Critical"
        elif score >= 5:
            return "High"
        elif score >= 3:
            return "Medium"
        else:
            return "Low"

    df["Severity"] = df["Risk_Score"].apply(severity)

    # -------------------------
    # DASHBOARD METRICS
    # -------------------------
    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Logs", len(df))
    c2.metric("🔴 Critical", (df["Severity"] == "Critical").sum())
    c3.metric("🟠 High", (df["Severity"] == "High").sum())
    c4.metric("🟢 Normal", (df["Severity"] == "Low").sum())

    # -------------------------
    # FILTERS
    # -------------------------
    st.subheader("🔍 Filters")

    sev_filter = st.multiselect("Severity", df["Severity"].unique(), default=df["Severity"].unique())
    atk_filter = st.multiselect("Attack Type", df["Attack_Type"].unique(), default=df["Attack_Type"].unique())

    filtered = df[(df["Severity"].isin(sev_filter)) & (df["Attack_Type"].isin(atk_filter))]

    # -------------------------
    # CHARTS
    # -------------------------
    st.subheader("📊 Severity Distribution")
    st.bar_chart(filtered["Severity"].value_counts())

    st.subheader("🎯 Attack Types")
    st.bar_chart(filtered["Attack_Type"].value_counts())

    # -------------------------
    # TIMELINE
    # -------------------------
    if "Timestamp" in filtered.columns:
        filtered["Timestamp"] = pd.to_datetime(filtered["Timestamp"], errors='coerce')
        timeline = filtered.groupby(filtered["Timestamp"].dt.hour)["Risk_Score"].count()
        st.subheader("📈 Attack Timeline")
        st.line_chart(timeline)

    # -------------------------
    # LOG VIEWER
    # -------------------------
    st.subheader("📜 Log Viewer")

    display_cols = [
        "Timestamp",
        "Source IP Address",
        "Destination IP Address",
        "Destination Port",
        "Protocol",
        "Attack_Type",
        "Severity",
        "Risk_Score"
    ]

    display_cols = [c for c in display_cols if c in filtered.columns]

    st.dataframe(filtered[display_cols], use_container_width=True)

else:
    st.info("Upload your dataset to begin analysis")
