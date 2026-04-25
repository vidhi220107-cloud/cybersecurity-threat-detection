import streamlit as st
import pandas as pd
import numpy as np
import pickle


# -------------------------------
# PAGE CONFIG
# -------------------------------
st.set_page_config(page_title="Cyber Threat Detection", layout="wide")

# -------------------------------
# UI STYLE
# -------------------------------
st.markdown("""
<style>
.stApp {
    background-image: linear-gradient(rgba(0,0,0,0.8), rgba(0,0,0,0.9)),
                      url("https://images.unsplash.com/photo-1550751827-4bd374c3f58b");
    background-size: cover;
}

.card {
    background: rgba(0, 0, 0, 0.7);
    padding: 25px;
    border-radius: 15px;
    margin-bottom: 20px;
    border: 1px solid rgba(255,255,255,0.1);
}

.metric-box {
    background: rgba(255,255,255,0.08);
    padding: 20px;
    border-radius: 12px;
    text-align: center;
}

.center {
    text-align: center;
}

label {
    color: white !important;
}
</style>
""", unsafe_allow_html=True)

# -------------------------------
# LOAD MODEL
# -------------------------------
with open('notebook/model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('notebook/scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s'
]

# -------------------------------
# HEADER
# -------------------------------
st.markdown("<h1 class='center'>🔐 Cyber Threat Detection Dashboard</h1>", unsafe_allow_html=True)
st.markdown("<p class='center'>AI-powered network traffic analysis</p>", unsafe_allow_html=True)
st.info("This system detects cyber threats using Machine Learning on network traffic data.")
st.markdown("---")

# -------------------------------
# INPUT SECTION
# -------------------------------
st.markdown("<div class='card'>", unsafe_allow_html=True)
st.subheader("📥 Enter Network Traffic Data")

col1, col2, col3 = st.columns(3)

with col1:
    flow_duration = st.text_input("Flow Duration", value=5000.0)
    fwd_packets = st.text_input("Total Fwd Packets", value=20.0)

with col2:
    bwd_packets = st.text_input("Total Backward Packets", value=15.0)
    flow_bytes = st.text_input("Flow Bytes/s", value=3000.0)

with col3:
    flow_packets = st.text_input("Flow Packets/s", value=50.0)

st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------
# BUTTON
# -------------------------------
col_btn1, col_btn2, col_btn3 = st.columns([2,2,2])
with col_btn2:
    detect = st.button("🚨 Detect Threat", use_container_width=True)

# -------------------------------
# PREDICTION BLOCK
# -------------------------------
if detect:

    input_data = pd.DataFrame({
        'Flow Duration': [float(flow_duration)],
        'Total Fwd Packets': [float(fwd_packets)],
        'Total Backward Packets': [float(bwd_packets)],
        'Flow Bytes/s': [float(flow_bytes)],
        'Flow Packets/s': [float(flow_packets)]
    })

    input_data = input_data[FEATURES]
    input_scaled = scaler.transform(input_data)

    
    prediction = model.predict(input_scaled)
    prob = model.predict_proba(input_scaled)
    risk_score = np.max(prob) * 100
    flow_duration = float(flow_duration)
    fwd_packets = float(fwd_packets)
    bwd_packets = float(bwd_packets)
    flow_bytes = float(flow_bytes)
    flow_packets = float(flow_packets)
    
    rule_attack = (
        flow_duration > 1000000 or
        fwd_packets > 1000 or
        bwd_packets > 1000 or
        flow_bytes > 500000 or
        flow_packets > 5000
    )
    if rule_attack:
        status = "Attack"
        severity = "HIGH RISK"
        risk_score = 95.0
    else:
        if prediction[0] == 0:
            status = "Normal"
            severity = "SAFE"
            risk_score = 100 - risk_score
        else:
            status = "Attack"
            severity = "HIGH RISK"
    # -------------------------------
    # RESULT SECTION
    # -------------------------------
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("📊 Detection Results")

    if prediction[0] == 0:
        st.success("🟢 Normal Traffic Detected")
    else:
        st.error("🔴 Attack Detected! Immediate Action Required")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("<div class='metric-box'>", unsafe_allow_html=True)
        st.write("Traffic Status")
        st.write(f"**{status}**")
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown("<div class='metric-box'>", unsafe_allow_html=True)
        st.write("Severity Level")
        st.write(f"**{severity}**")
        st.markdown("</div>", unsafe_allow_html=True)

    with c3:
        st.markdown("<div class='metric-box'>", unsafe_allow_html=True)
        st.write("Risk Score")
        st.write(f"**{risk_score:.2f}%**")
        st.markdown("</div>", unsafe_allow_html=True)

    st.progress(int(risk_score))
    st.markdown("</div>", unsafe_allow_html=True)

    # -------------------------------
    # FEATURE GRAPH
    # -------------------------------
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("📊 Traffic Feature Analysis")

    df_graph = pd.DataFrame({
        "Feature": FEATURES,
        "Value": [
            flow_duration,
            fwd_packets,
            bwd_packets,
            flow_bytes,
            flow_packets
        ]
    })

    st.bar_chart(df_graph.set_index("Feature"))
    st.markdown("</div>", unsafe_allow_html=True)

    # ------------------------------
    # RISK GRAPH
    # -------------------------------
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("📈 Risk Level Indicator")

    risk_df = pd.DataFrame({
        "Category": ["Safe", "Risk"],
        "Value": [100 - risk_score, risk_score]
    })

    st.bar_chart(risk_df.set_index("Category"))
    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------
# EDA TOGGLE (FINAL CLEAN)
# -------------------------------
show_eda = st.toggle("📊 Show EDA Analysis")

if show_eda:

    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("📊 Exploratory Data Analysis")

    try:
        # Load dataset
        df = pd.read_csv("notebook/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

        # Fix column names
        df.columns = df.columns.str.strip()

        # Reduce size (important for performance)
        df = df.sample(min(1000, len(df)), random_state=42)

        # -------------------------------
        # DATA PREVIEW
        # -------------------------------
        st.write("### Dataset Preview")
        st.dataframe(df.head())

        # -------------------------------
        # TRAFFIC DISTRIBUTION (BAR CHART)
        # -------------------------------
        st.write("### Traffic Distribution")
        st.bar_chart(df['Label'].value_counts())

        # -------------------------------
        # FEATURE DISTRIBUTION (SMOOTH)
        # -------------------------------
        st.write("### Feature Trends")

        numeric_cols = df.select_dtypes(include=np.number).columns[:3]

        for col in numeric_cols:
            st.write(f"📌 {col}")
            normalized = (df[col] - df[col].min()) / (df[col].max() - df[col].min())
            st.line_chart(normalized.rolling(50).mean())

        # -------------------------------
        # CORRELATION MATRIX
        # -------------------------------
        st.write("### Correlation Matrix")
        corr = df[numeric_cols].corr()
        st.dataframe(corr)

    except Exception as e:
        st.error(f"EDA Error: {e}")

    st.markdown("</div>", unsafe_allow_html=True)
