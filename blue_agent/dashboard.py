import streamlit as st
import pandas as pd
import plotly.express as px
import psutil
import time
import os

# --- PAGE SETUP ---
st.set_page_config(page_title="SentinelChain Dashboard", layout="wide", page_icon="🛡️")

# --- STYLING ---
st.markdown("""
    <style>
        .stApp { background-color: #0e1117; }
        section[data-testid="stSidebar"] { background-color: #161b22; }
        h1, h2, h3 { color: #00FF00; font-family: 'Courier New', monospace; }
        div[data-testid="stTable"] { border: 1px solid #30363d; }
    </style>
""", unsafe_allow_html=True)

# --- READ-ONLY FUNCTIONS ---

def get_live_processes():
    """Scans system for visualization only."""
    process_counts = {}
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name']
            if "python" in name: name = "python3"
            elif "chrome" in name: name = "web_browser"
            
            process_counts[name] = process_counts.get(name, 0) + 1
        except:
            pass
    return pd.DataFrame(list(process_counts.items()), columns=['Process', 'Count']).sort_values(by='Count', ascending=False).head(5)

def load_forensic_log():
    """Reads the CSV log file created by the backend."""
    log_file = "sentinel_forensic_log.csv"
    if os.path.exists(log_file):
        try:
            df = pd.read_csv(log_file)
            return df.sort_index(ascending=False) 
        except:
            pass
    return pd.DataFrame(columns=["TIMESTAMP", "TARGET", "PID", "ACTION", "STATUS"])

# --- DASHBOARD LAYOUT ---
st.sidebar.title("🛡️ SENTINEL NODE")
st.sidebar.success("✅ VISUALIZER ONLINE")

col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("💀 FORENSIC KILL CHAIN")
    df_logs = load_forensic_log()
    st.dataframe(df_logs, use_container_width=True, hide_index=True)

with col2:
    st.subheader("📊 LIVE METRICS")
    df_live = get_live_processes()
    
    # --- CUSTOM CYBER COLOR PALETTE ---
    # Green, Dark Green, Red (Threat), Blue (Net), Grey
    cyber_colors = ["#00FF00", "#008F11", "#FF0000", "#0088FF", "#808080"]
    
    fig = px.pie(
        df_live, 
        values='Count', 
        names='Process', 
        hole=0.5, 
        color_discrete_sequence=cyber_colors
    )
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color="#00FF00"))
    st.plotly_chart(fig, use_container_width=True)

# Auto-Refresh (Every 2 seconds)
time.sleep(2)
st.rerun()
