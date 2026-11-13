import streamlit as st
import pandas as pd
import json
import time

st.set_page_config(page_title="SDN SOC Dashboard", layout="wide")
st.title("🛡️ SDN Security Operations Center (XAI-IDS)")

# Layout columns
col1, col2 = st.columns([2, 1])

def load_alerts():
    try:
        with open("alerts.json", "r") as f:
            data = [json.loads(line) for line in f.readlines()]
            return pd.DataFrame(data[-10:]) # Show last 10 alerts
    except (FileNotFoundError, json.JSONDecodeError):
        return pd.DataFrame(columns=["time", "ip", "type", "pps", "bps", "driver"])

placeholder = st.empty()

while True:
    df = load_alerts()
    with placeholder.container():
        if not df.empty:
            st.error("🚨 ACTIVE THREATS DETECTED")
            st.dataframe(df.style.highlight_max(axis=0, color='red'), use_container_width=True)
            
            # Simple bar chart of PPS
            st.subheader("Live Packets Per Second (PPS) Spike")
            st.bar_chart(df.set_index("time")["pps"])
        else:
            st.success("✅ Network Secure. No active anomalies.")
            
    time.sleep(2)