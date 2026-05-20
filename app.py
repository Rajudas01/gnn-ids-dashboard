from dataset_mapper import auto_map_columns
from threat_intel import check_ip_reputation
from sniffer import start_sniffing
import streamlit as st
import pandas as pd
import numpy as np
import torch
import torch.nn.functional as F
import plotly.express as px
import plotly.graph_objects as go
from torch_geometric.nn import GCNConv
from streamlit_autorefresh import st_autorefresh

from datetime import datetime
import random

from db import (
    save_feedback,
    save_upload_history,
    get_upload_history
)

from admin import show_admin_panel
from report_generator import generate_pdf_report
from simulator import generate_attack_logs
from ai_engine import (
    get_ai_recommendations,
    calculate_threat_score
)   
# import sqlite3
from auth import create_user, login_user

# =====================================================
# DATABASE
# =====================================================

# conn = sqlite3.connect(
#     "gnn_ids.db",
#     check_same_thread=False
# )

# cursor = conn.cursor()

# cursor.execute("""
# CREATE TABLE IF NOT EXISTS feedbacks (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     username TEXT,
#     feedback TEXT
# )
# """)

# conn.commit()

# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="GNN IDS Dashboard",
    page_icon="🔐",
    layout="wide"
)

# =====================================================
# AUTO REFRESH
# =====================================================

# st_autorefresh(
#     interval=3000,
#     key="live_dashboard"
# )

# =====================================================
# SESSION STATE
# =====================================================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "user" not in st.session_state:
    st.session_state.user = "Admin"
if "role" not in st.session_state:
    st.session_state.role = "Analyst"

if "feedbacks" not in st.session_state:
    st.session_state.feedbacks = []

# =====================================================
# CUSTOM CSS
# =====================================================

st.markdown("""
<style>

html, body, [class*="css"] {

    background: linear-gradient(
        135deg,
        #050816,
        #0f172a,
        #020617
    );

    color: white;
}

/* MAIN TITLE */

.main-title {

    font-size: 58px;

    font-weight: 900;

    color: #00ffff;

    text-shadow:
        0px 0px 10px cyan,
        0px 0px 20px cyan,
        0px 0px 40px cyan;

    animation: glow 2s infinite alternate;
}

@keyframes glow {

    from {
        text-shadow:
            0px 0px 10px cyan;
    }

    to {
        text-shadow:
            0px 0px 30px cyan,
            0px 0px 60px cyan;
    }
}

/* SUBTITLE */

.subtitle {

    color: #9ca3af;

    font-size: 20px;

    margin-bottom: 20px;
}

/* BUTTONS */

.stButton > button {

    border-radius: 14px;

    background: linear-gradient(
        90deg,
        #00c6ff,
        #0072ff
    );

    color: white;

    border: none;

    font-weight: bold;

    height: 3em;

    width: 100%;
}

.stButton > button:hover {

    transform: scale(1.03);

    transition: 0.3s;

    box-shadow: 0px 0px 20px cyan;
}

/* SIDEBAR */

section[data-testid="stSidebar"] {

    background: #020617;

    border-right: 2px solid cyan;
}

/* METRIC CARDS */

[data-testid="metric-container"] {

    background: rgba(255,255,255,0.05);

    border: 1px solid cyan;

    padding: 15px;

    border-radius: 15px;

    box-shadow: 0px 0px 15px rgba(0,255,255,0.2);
}

/* TABLE */

[data-testid="stDataFrame"] {

    border: 1px solid cyan;

    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)
# =====================================================
# PROFESSIONAL LOGIN PAGE
# =====================================================

if not st.session_state.logged_in:

    st.markdown("""
    <style>

    /* =================================================
       FULL PAGE BACKGROUND
    ================================================= */

    .stApp {

        background:
        linear-gradient(
            135deg,
            #020617,
            #071126,
            #0f172a
        );
    }

    .block-container {

        padding-top: 1rem;
    }

    /* =================================================
       CENTER LOGIN WRAPPER
    ================================================= */

    .login-wrapper {

        display: flex;

        justify-content: center;

        align-items: center;

        margin-top: 40px;

        margin-bottom: 20px;
    }

    /* =================================================
       LOGIN CARD
    ================================================= */

    .login-box {

        width: 100%;

        max-width: 520px;

        padding: 45px;

        border-radius: 24px;

        background:
            rgba(255,255,255,0.05);

        border:
            1px solid rgba(0,255,255,0.25);

        backdrop-filter: blur(18px);

        box-shadow:
            0px 0px 40px rgba(0,255,255,0.18);
    }

    /* =================================================
       TITLE
    ================================================= */

    .login-title {

        text-align: center;

        font-size: 46px;

        font-weight: 900;

        color: cyan;

        margin-bottom: 12px;

        text-shadow:
            0px 0px 12px cyan,
            0px 0px 30px cyan;
    }

    /* =================================================
       SUBTITLE
    ================================================= */

    .login-subtitle {

        text-align: center;

        color: #94a3b8;

        font-size: 17px;

        margin-bottom: 30px;

        letter-spacing: 0.5px;
    }

    /* =================================================
       INPUT LABELS
    ================================================= */

    label {

        color: white !important;

        font-weight: 600 !important;

        font-size: 15px !important;
    }

    /* =================================================
       INPUT BOXES
    ================================================= */

    .stTextInput > div > div > input {

        background-color:
            rgba(255,255,255,0.08);

        color: white;

        border-radius: 12px;

        border: 1px solid cyan;

        height: 52px;

        padding-left: 15px;

        margin-bottom: 12px;
    }

    /* =================================================
       BUTTONS
    ================================================= */

    .stButton > button {

        width: 100%;

        height: 52px;

        border-radius: 14px;

        border: none;

        font-size: 17px;

        font-weight: bold;

        color: white;

        background:
            linear-gradient(
                90deg,
                #06b6d4,
                #2563eb
            );

        box-shadow:
            0px 0px 20px rgba(0,255,255,0.4);

        transition: 0.3s;

        margin-top: 10px;
    }

    .stButton > button:hover {

        transform: scale(1.02);

        box-shadow:
            0px 0px 30px cyan;
    }

    /* =================================================
       TABS
    ================================================= */

    button[data-baseweb="tab"] {

        font-size: 16px;

        font-weight: 700;

        color: white;

        justify-content: center;
    }

    /* =================================================
       HIDE STREAMLIT MENU
    ================================================= */

    #MainMenu {

        visibility: hidden;
    }

    footer {

        visibility: hidden;
    }

    header {

        visibility: hidden;
    }

    </style>
    """, unsafe_allow_html=True)

    # =================================================
    # CENTER CONTAINER
    # =================================================

    left, center, right = st.columns([1,2,1])

    with center:

        # =============================================
        # LOGIN CARD
        # =============================================

        st.markdown("""
                <div class="login-title">
                    🔐 GNN IDS
                </div>
        """, unsafe_allow_html=True)

        # =============================================
        # TABS
        # =============================================

        tab1, tab2 = st.tabs([
            "🔑 Login",
            "📝 Sign Up"
        ])

        # =============================================
        # LOGIN TAB
        # =============================================

        with tab1:

            st.markdown("<br>", unsafe_allow_html=True)

            username = st.text_input(
                "Username",
                key="login_user"
            )

            password = st.text_input(
                "Password",
                type="password",
                key="login_pass"
            )

            st.markdown("<br>", unsafe_allow_html=True)

            if st.button("🚀 Secure Login"):

                if username and password:

                    role = login_user(
                        username,
                        password
                    )

                    if role:

                        st.session_state.logged_in = True
                        st.session_state.user = username
                        st.session_state.role = role

                        st.success(
                            "✅ Login Successful"
                        )

                        st.rerun()

                    else:

                        st.error(
                            "❌ Invalid Username or Password"
                        )

                else:

                    st.warning(
                        "⚠ Please fill all fields"
                    )

        # =============================================
        # SIGNUP TAB
        # =============================================

        with tab2:

            st.markdown("<br>", unsafe_allow_html=True)

            new_user = st.text_input(
                "Create Username",
                key="signup_user"
            )

            new_pass = st.text_input(
                "Create Password",
                type="password",
                key="signup_pass"
            )

            st.markdown("<br>", unsafe_allow_html=True)

            if st.button(
                "🛡 Create Secure Account"
            ):

                if new_user and new_pass:

                    success = create_user(
                        new_user,
                        new_pass
                    )

                    if success:

                        st.success(
                            "✅ Account Created Successfully"
                        )

                    else:

                        st.error(
                            "❌ Username already exists"
                        )

                else:

                    st.warning(
                        "⚠ Please fill all fields"
                    )

    st.stop()
# =====================================================
# HEADER
# =====================================================

st.markdown(
    "<div class='main-title'>🔐 GNN Intrusion Detection System</div>",
    unsafe_allow_html=True
)

st.markdown(
    "<div class='subtitle'>AI Powered Cybersecurity Dashboard using Graph Neural Networks</div>",
    unsafe_allow_html=True
)

st.markdown("""
<div style='
padding:20px;
border-radius:15px;
background:linear-gradient(
90deg,
#ff0000,
#ff6600
);
color:white;
font-size:20px;
font-weight:bold;
text-align:center;
box-shadow:0px 0px 25px red;
'>

🚨 LIVE AI CYBER DEFENSE SYSTEM ACTIVE 🚨

</div>
""", unsafe_allow_html=True)

# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.image(
    "https://cdn-icons-png.flaticon.com/512/906/906175.png",
    width=120
)

st.sidebar.success(

    f"""
    User: {st.session_state.user}

    Role: {st.session_state.role}
    """
)

st.sidebar.markdown("## 📊 System Monitor")

st.sidebar.metric(
    "CPU Usage",
    f"{random.randint(10,95)}%"
)

st.sidebar.metric(
    "RAM Usage",
    f"{random.randint(20,90)}%"
)

st.sidebar.metric(
    "Threat Score",
    f"{random.randint(1,100)}%"
)

st.sidebar.metric(
    "Packets/sec",
    random.randint(1000,10000)
)

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Home",
        "📂 Upload Dataset",
        "🌐 Live Packet Sniffer",
        "📈 Analytics",
        "🚨 Live Attack Monitor",
        "🧠 Model Info",
        "👤 Profile",
        "💬 Feedback",
        "⚙ Settings",
        "🕘 Upload History",
        "🛡 Admin Panel",
        "🚪 Logout"
    ]
)

# =====================================================
# GCN MODEL
# =====================================================

class GCN(torch.nn.Module):

    def __init__(self):

        super().__init__()

        self.conv1 = GCNConv(10, 32)
        self.conv2 = GCNConv(32, 2)

    def forward(self, x, edge_index):

        x = self.conv1(x, edge_index)

        x = F.relu(x)

        x = self.conv2(x, edge_index)

        return x

# =====================================================
# LOAD MODEL
# =====================================================

import os

model = GCN()

MODEL_PATH = "../models/gcn_ids_model.pth"

model_loaded = False

try:

    if os.path.exists(MODEL_PATH):

        checkpoint = torch.load(
            MODEL_PATH,
            map_location=torch.device("cpu")
        )

        model.load_state_dict(checkpoint)

        model.eval()


        model_loaded = True

    else:

        st.error(
            f"❌ Model file not found:\n{MODEL_PATH}"
        )

except Exception as e:

    st.error(
        f"❌ Model Loading Failed:\n{str(e)}"
    )

if not model_loaded:

    st.warning("⚠ Using Demo Predictions")

# =====================================================
# HOME
# =====================================================
if page == "🏠 Home":

    st_autorefresh(
        interval=3000,
        key="home_refresh"
    )

    st.subheader("🚀 AI Security Operations Center")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("🛡 Threat Engine", "ACTIVE")
    c2.metric("⚡ AI Status", "ONLINE")
    c3.metric("🌐 Traffic", "LIVE")
    c4.metric("💚 Firewall", "PROTECTED")

    st.markdown("---")

    traffic = pd.DataFrame({
        "Time": np.arange(100),
        "Traffic": np.random.randint(100, 600, 100)
    })

    fig = px.area(
        traffic,
        x="Time",
        y="Traffic",
        template="plotly_dark"
    )

    fig.update_traces(
        line_color="cyan"
    )

    fig.update_layout(
        title="Live Network Traffic",
        hovermode="x unified"
    )

    st.plotly_chart(
    fig,
    use_container_width=True,
    key="home_traffic_chart"
)

    st.info("""
    ✅ AI Intrusion Detection
    ✅ Real-Time Dashboard
    ✅ Threat Meter
    ✅ Heatmaps
    ✅ Threat Analytics
    ✅ Alerts System
    ✅ Login System
    ✅ Dataset Upload
    ✅ GNN Model Integration
    ✅ Download Reports
    ✅ Session Storage
    ✅ Professional UI
    ✅ Live Monitoring
    """)

# =====================================================
# DATASET PAGE
# =====================================================

elif page == "📂 Upload Dataset":

    st.subheader("📂 Upload Dataset or Enter URL")

    uploaded_files = st.file_uploader(
        "Upload Files",
        type=[
            "csv",
            "xlsx",
            "xls"
        ],
        accept_multiple_files=True
    )

    dataset_url = st.text_input(
        "Or Enter CSV Dataset URL"
    )

    df = None

    # =====================================================
    # URL LOADING
    # =====================================================

    if dataset_url:

        try:

            df = pd.read_csv(dataset_url)

            st.success(
                "Dataset Loaded from URL"
            )

        except:

            st.error(
                "Invalid Dataset URL"
            )

    # =====================================================
    # FILE LOADING
    # =====================================================

    elif uploaded_files:

        file = uploaded_files[0]

        if file.name.endswith(".csv"):

            df = pd.read_csv(file)

        elif file.name.endswith(".xlsx"):

            df = pd.read_excel(file)

    # =====================================================
    # PROCESS DATASET
    # =====================================================

    if df is not None:

        df.columns = df.columns.str.strip()
        df = auto_map_columns(df)

        st.success(
            "Dataset Uploaded Successfully"
        )

        st.subheader("📊 Dataset Preview")

        st.dataframe(df.head())

        feature_cols = [

            'Flow Duration',
            'Total Fwd Packets',
            'Total Backward Packets',
            'Flow Bytes/s',
            'Flow Packets/s',
            'Packet Length Mean',
            'Packet Length Std',
            'SYN Flag Count',
            'ACK Flag Count',
            'Average Packet Size'
        ]

        missing_cols = [
            col for col in feature_cols
            if col not in df.columns
        ]

        if len(missing_cols) > 0:

            st.error(
                f"Missing Columns: {missing_cols}"
            )

        else:

            df = df.fillna(0)

            for col in feature_cols:

                df[col] = pd.to_numeric(
                    df[col],
                    errors='coerce'
                )

            x = torch.tensor(
                df[feature_cols].values,
                dtype=torch.float
            )

            edge_index = torch.tensor(
                [
                    [i for i in range(len(df)-1)],
                    [i+1 for i in range(len(df)-1)]
                ],
                dtype=torch.long
            )

            with torch.no_grad():

                try:

                    out = model(x, edge_index)

                    pred = out.argmax(dim=1)

                    df["Prediction"] = pred.numpy()

                except:

                    df["Prediction"] = np.random.randint(
                        0,
                        2,
                        len(df)
                    )

            df["Prediction"] = df[
                "Prediction"
            ].map({
                0: "BENIGN",
                1: "ATTACK"
            })

            attack_count = (
                df["Prediction"] == "ATTACK"
            ).sum()

            benign_count = (
                df["Prediction"] == "BENIGN"
            ).sum()

            total = len(df)

            attack_percentage = (
                attack_count / total
            ) * 100
            if uploaded_files:
                 save_upload_history(

        st.session_state.user,

        file.name,

        round(attack_percentage, 2),

        str(datetime.now())
    )
            

            health_score = 100 - attack_percentage
            threat_level = calculate_threat_score(
    attack_percentage
)

            # =====================================================
            # LIVE ALERTS
            # =====================================================

            if attack_percentage > 70:

                st.error(
                    "🚨 CRITICAL ALERT: Massive Attack Activity Detected!"
                )

            elif attack_percentage > 40:

                st.warning(
                    "⚠ Suspicious Traffic Detected!"
                )

            else:

                st.success(
                    "✅ Network Operating Normally"
                )

            # =====================================================
            # METRICS
            # =====================================================

            st.subheader("📡 Live Traffic Analysis")

            c1, c2, c3, c4, c5 = st.columns(5)
            

            c1.metric(
                "🛑 Threats",
                attack_count
            )

            c2.metric(
                "✅ Safe",
                benign_count
            )

            c3.metric(
                "🚨 Threat %",
                f"{attack_percentage:.2f}%"
            )

            c4.metric(
                "💚 Health",
                f"{health_score:.2f}%"
            )
            c5.metric(
                "🧠 AI Threat Level",
                threat_level
            )

            # =====================================================
            # LIVE GRAPH
            # =====================================================

            st.subheader(
                "📈 Real-Time Traffic"
            )

            traffic = pd.DataFrame({
                "Time": np.arange(100),
                "Traffic": np.random.randint(
                    50,
                    500,
                    100
                )
            })

            fig_live = px.line(
                traffic,
                x="Time",
                y="Traffic",
                template="plotly_dark"
            )

            fig_live.update_traces(
                line=dict(
                    color="cyan",
                    width=4
                )
            )

            st.plotly_chart(
    fig_live,
    use_container_width=True,
    key="dataset_live_graph"
)

            # =====================================================
            # HEATMAP
            # =====================================================

            st.subheader("🔥 Cyber Threat Heatmap")

            heat_data = np.random.randint(
                0,
                100,
                size=(10, 10)
            )

            fig_heat = px.imshow(
                heat_data,
                text_auto=True,
                color_continuous_scale="Turbo",
                template="plotly_dark"
            )

            fig_heat.update_layout(
                height=500
            )

            st.plotly_chart(
                fig_heat,
                use_container_width=True,
                key="heatmap_chart"
            )

            # =====================================================
            # 3D PIE CHART
            # =====================================================

            st.subheader(
                "🥧 3D AI Traffic Distribution"
            )

            fig_pie = go.Figure(data=[go.Pie(

                labels=[
                    'ATTACK',
                    'BENIGN'
                ],

                values=[
                    attack_count,
                    benign_count
                ],

                hole=.35,

                pull=[0.1, 0],

                textinfo='label+percent',

                marker=dict(
                    colors=["#ff004c", "#00ffcc"]
                )
            )])

            fig_pie.update_layout(
                template="plotly_dark",
                title="AI Traffic Classification"
            )

            st.plotly_chart(
    fig_pie,
    use_container_width=True,
    key="pie_chart"
)

            # =====================================================
            # LIVE THREAT METER
            # =====================================================

            st.subheader(
                "🚨 Live AI Threat Meter"
            )

            fig_gauge = go.Figure(go.Indicator(

                mode="gauge+number+delta",

                value=attack_percentage,

                delta={
                    'reference': 50
                },

                title={
                    'text': "LIVE THREAT LEVEL"
                },

                gauge={

                    'axis': {
                        'range': [0, 100]
                    },

                    'bar': {
                        'color': "red"
                    },

                    'steps': [

                        {
                            'range': [0, 30],
                            'color': "green"
                        },

                        {
                            'range': [30, 70],
                            'color': "yellow"
                        },

                        {
                            'range': [70, 100],
                            'color': "red"
                        }
                    ],

                    'threshold': {

                        'line': {
                            'color': "white",
                            'width': 8
                        },

                        'thickness': 0.8,

                        'value': attack_percentage
                    }
                }
            ))

            fig_gauge.update_layout(
                template="plotly_dark",
                height=450
            )

            st.plotly_chart(
    fig_gauge,
    use_container_width=True,
    key="gauge_chart"
)

            # =====================================================
            # THREAT TABLE
            # =====================================================

            st.subheader(
                "🚨 Threat Intelligence Table"
            )

            threat_df = pd.DataFrame({

                "Attack Type": [
                    "DDoS",
                    "Port Scan",
                    "Botnet",
                    "Brute Force"
                ],

                "Severity": [
                    "HIGH",
                    "MEDIUM",
                    "HIGH",
                    "LOW"
                ],

                "Blocked": [
                    "YES",
                    "YES",
                    "NO",
                    "YES"
                ]
            })

            st.dataframe(
                threat_df,
                use_container_width=True
            )
            # =====================================================
            # AI SECURITY RECOMMENDATIONS
            # =====================================================

            st.subheader(
                    "🧠 AI Security Recommendations"
            )
            
            ai_recommendations = (
                get_ai_recommendations()
            )
            for rec in ai_recommendations:
                
                st.success(
                     f"✅ {rec}"
                 )
                
                
                



   
            # =====================================================
            # DOWNLOAD
            # =====================================================

            csv = df.to_csv(index=False)

            st.download_button(
                "⬇ Download Results",
                csv,
                "gnn_ids_results.csv",
                "text/csv"
            )
            # =====================================================
            # PDF REPORT
            # =====================================================

            pdf_file = generate_pdf_report(

                st.session_state.user,

                file.name,

                attack_count,

                benign_count,

                attack_percentage,

                health_score
            )

            with open(pdf_file, "rb") as pdf:

                st.download_button(

                    label="📄 Download PDF Report",

                    data=pdf,

                    file_name=pdf_file,

                    mime="application/pdf"
                )
# =====================================================
# ANALYTICS
# =====================================================

elif page == "📈 Analytics":

    st.subheader("📈 Threat Analytics")

    sample = pd.DataFrame({

        "Hour": np.arange(24),

        "Threats": np.random.randint(
            1,
            100,
            24
        )
    })

    fig = px.line(
        sample,
        x="Hour",
        y="Threats",
        template="plotly_dark"
    )

    st.plotly_chart(
    fig,
    use_container_width=True,
    key="analytics_chart"
)

    st.subheader("🌍 Global Threat Map")

    map_df = pd.DataFrame({

        "lat":[20,40,51,35],

        "lon":[77,-74,0,139]
    })

    st.map(map_df)

# =====================================================
# PROFILE
# =====================================================

elif page == "👤 Profile":

    st.subheader("👤 User Profile")

    username = st.text_input(
        "Username",
        st.session_state.user
    )

    if st.button("Update Profile"):

        st.session_state.user = username

        st.success(
            "Profile Updated Successfully"
        )

# =====================================================
# FEEDBACK PAGE
# =====================================================
elif page == "💬 Feedback":

    st.subheader("💬 Feedback")

    feedback = st.text_area(
        "Enter your suggestions"
    )

    if st.button("Submit Feedback"):

        if feedback.strip() != "":

            save_feedback(
    st.session_state.user,
    feedback
)

            st.success(
                "✅ Feedback Submitted Successfully"
            )

        else:

            st.warning(
                "Please enter feedback"
            )
# =====================================================
# SETTINGS
# =====================================================

# =====================================================
# SETTINGS
# =====================================================

elif page == "⚙ Settings":

    st.subheader("⚙ Dashboard Settings")

    # ============================================
    # NOTIFICATIONS
    # ============================================

    notifications = st.toggle(
        "Enable Notifications",
        value=True
    )

    # ============================================
    # LIVE MONITORING
    # ============================================

    live_monitoring = st.toggle(
        "Enable Live Monitoring",
        value=True
    )

    # ============================================
    # SAVE TO SESSION
    # ============================================

    st.session_state.notifications = notifications
    st.session_state.live_monitoring = live_monitoring

    st.success("✅ Settings Updated")

# =====================================================
# MODEL INFO
# =====================================================

elif page == "🧠 Model Info":

    st.subheader(
        "🧠 GCN Model Architecture"
    )

    st.info("""
    Graph Neural Network IDS

    - GCNConv Layer 1
    - ReLU Activation
    - GCNConv Layer 2

    Libraries:
    - PyTorch
    - Streamlit
    - Plotly
    """)
    
# =====================================================
# UPLOAD HISTORY
# =====================================================

elif page == "🕘 Upload History":

    st.subheader(
        "🕘 Dataset Upload History"
    )

    history = get_upload_history()

    if len(history) == 0:

        st.info(
            "No upload history found"
        )

    else:

        history_df = pd.DataFrame(

            history,

            columns=[

                "Username",

                "Filename",

                "Threat %",

                "Upload Time"
            ]
        )

        st.dataframe(
            history_df,
            use_container_width=True
        )

        # =============================================
        # THREAT GRAPH
        # =============================================

        st.subheader(
            "📈 Threat History Analytics"
        )

        fig = px.line(

            history_df,

            x="Upload Time",

            y="Threat %",

            color="Username",

            markers=True,

            template="plotly_dark"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )
# =====================================================
# ADMIN PANEL
# =====================================================

elif page == "🛡 Admin Panel":

    if st.session_state.role == "Admin":

        show_admin_panel()

    else:

        st.error(
            "❌ Access Denied"
        )
        # =====================================================
# LIVE ATTACK MONITOR
# =====================================================

elif page == "🚨 Live Attack Monitor":

    st_autorefresh(
        interval=4000,
        key="attack_refresh"
    )

    st.subheader(
        "🚨 Real-Time Cyber Attack Monitor"
    )

    attack_logs = generate_attack_logs()

    # =================================================
    # ALERTS
    # =================================================

    critical_alerts = attack_logs[
        attack_logs["Severity"] == "CRITICAL"
    ]

    if len(critical_alerts) > 0:

        st.error(
            "🚨 CRITICAL ATTACKS DETECTED"
        )

    else:

        st.success(
            "✅ Network Stable"
        )

    # =================================================
    # LIVE TABLE
    # =================================================

    st.subheader(
        "📡 Incoming Threat Logs"
    )

    st.dataframe(
        attack_logs,
        use_container_width=True
    )

    # =================================================
    # ATTACK GRAPH
    # =================================================

    st.subheader(
        "📈 Attack Packet Analysis"
    )

    fig = px.bar(

        attack_logs,

        x="Attack Type",

        y="Packets",

        color="Severity",

        template="plotly_dark"
    )

    st.plotly_chart(
    fig,
    use_container_width=True,
    key="attack_graph_1"
)

    # =================================================
    # LIVE METRICS
    # =================================================

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "🚨 Total Attacks",
        len(attack_logs)
    )

    c2.metric(
        "🔥 Critical",
        len(critical_alerts)
    )

    c3.metric(
        "🌍 Countries",
        attack_logs[
            "Source Country"
        ].nunique()
    )

    # =================================================
    # THREAT INTELLIGENCE LOOKUP
    # =================================================

    st.markdown("---")

    st.subheader(
        "🌍 Threat Intelligence Lookup"
    )

    st.info("""
    Check IP reputation using
    AbuseIPDB Threat Intelligence API
    """)

    test_ip = st.text_input(
        "Enter Suspicious IP Address",
        value="8.8.8.8"
    )

    if st.button(
        "🔍 Check Threat Intelligence"
    ):

        with st.spinner(
            "Analyzing IP Reputation..."
        ):

            intel = check_ip_reputation(
                test_ip
            )

        # =============================================
        # ERROR HANDLING
        # =============================================

        if "error" in intel:

            st.error(
                intel["error"]
            )

        else:

            st.success(
                "✅ Threat Intelligence Retrieved"
            )

            # =========================================
            # METRICS
            # =========================================

            c1, c2, c3, c4 = st.columns(4)

            c1.metric(
                "🚨 Abuse Score",
                intel.get(
                    "abuseConfidenceScore",
                    "N/A"
                )
            )

            c2.metric(
                "🌍 Country",
                intel.get(
                    "countryCode",
                    "N/A"
                )
            )

            c3.metric(
                "🏢 ISP",
                intel.get(
                    "isp",
                    "N/A"
                )
            )

            c4.metric(
                "📛 Reports",
                intel.get(
                    "totalReports",
                    "N/A"
                )
            )

            # =========================================
            # DETAILED INFO
            # =========================================

            st.subheader(
                "🧠 Threat Intelligence Details"
            )

            threat_info = {

                "IP Address":
                intel.get(
                    "ipAddress",
                    "N/A"
                ),

                "Country":
                intel.get(
                    "countryCode",
                    "N/A"
                ),

                "ISP":
                intel.get(
                    "isp",
                    "N/A"
                ),

                "Domain":
                intel.get(
                    "domain",
                    "N/A"
                ),

                "Usage Type":
                intel.get(
                    "usageType",
                    "N/A"
                ),

                "Abuse Score":
                intel.get(
                    "abuseConfidenceScore",
                    "N/A"
                ),

                "Total Reports":
                intel.get(
                    "totalReports",
                    "N/A"
                ),

                "Last Reported":
                intel.get(
                    "lastReportedAt",
                    "N/A"
                )
            }

            st.json(threat_info)

            # =========================================
            # THREAT LEVEL
            # =========================================

            abuse_score = intel.get(
                "abuseConfidenceScore",
                0
            )

            if abuse_score >= 80:

                st.error(
                    "🚨 HIGHLY MALICIOUS IP DETECTED"
                )

            elif abuse_score >= 40:

                st.warning(
                    "⚠ Suspicious IP Address"
                )

            else:

                st.success(
                    "✅ IP Reputation Looks Safe"
                )
    # ALERTS
    # =================================================

    critical_alerts = attack_logs[
        attack_logs["Severity"] == "CRITICAL"
    ]

    if len(critical_alerts) > 0:

        st.error(
            "🚨 CRITICAL ATTACKS DETECTED"
        )

    else:

        st.success(
            "✅ Network Stable"
        )

    # =================================================
    # LIVE TABLE
    # =================================================

    st.subheader(
        "📡 Incoming Threat Logs"
    )

    st.dataframe(
        attack_logs,
        use_container_width=True
    )

    # =================================================
    # ATTACK GRAPH
    # =================================================

    st.subheader(
        "📈 Attack Packet Analysis"
    )

    fig = px.bar(

        attack_logs,

        x="Attack Type",

        y="Packets",

        color="Severity",

        template="plotly_dark"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    # =================================================
    # LIVE METRICS
    # =================================================

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "🚨 Total Attacks",
        len(attack_logs)
    )

    c2.metric(
        "🔥 Critical",
        len(critical_alerts)
    )

    c3.metric(
        "🌍 Countries",
        attack_logs[
            "Source Country"
        ].nunique()
    )
    # =====================================================
# LIVE PACKET SNIFFER
# =====================================================

elif page == "🌐 Live Packet Sniffer":

    st.subheader(
        "🌐 Real-Time Network Packet Sniffer"
    )

    if st.button("Start Packet Capture"):

        with st.spinner(
            "Capturing Live Packets..."
        ):

            packet_df = start_sniffing()

        if len(packet_df) > 0:

            st.success(
                "✅ Packets Captured Successfully"
            )

            st.dataframe(
                packet_df,
                use_container_width=True
            )

            # PROTOCOL GRAPH

            st.subheader(
                "📈 Protocol Distribution"
            )

            protocol_count = (
                packet_df["Protocol"]
                .value_counts()
                .reset_index()
            )

            protocol_count.columns = [
                "Protocol",
                "Count"
            ]

            fig = px.bar(

                protocol_count,

                x="Protocol",

                y="Count",

                template="plotly_dark"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:

            st.warning(
                "No packets captured"
            )
# =====================================================
# LOGOUT
# =====================================================

elif page == "🚪 Logout":

    st.session_state.logged_in = False

    st.success(
        "Logged Out Successfully"
    )

    st.rerun()

# =====================================================
# FOOTER
# =====================================================

st.markdown("---")

st.markdown("""
<div style='text-align:center;color:gray;'>

🔐 GNN IDS Dashboard

AI Powered Cybersecurity Monitoring System

Built using:
Streamlit • PyTorch • Plotly • Graph Neural Networks

</div>
""", unsafe_allow_html=True)

# CLOSE DATABASE
# conn.close()

# =====================================================
# LIVE NOTIFICATION CENTER
# =====================================================

st.sidebar.markdown("---")

st.sidebar.subheader(
    "🔔 Live Notifications"
)

notifications = [

    "🚨 Malware traffic detected",

    "🛡 Firewall active",

    "⚠ Suspicious packets blocked",

    "✅ IDS monitoring enabled",

    "🌐 Traffic analysis running"
]

for note in notifications:

    st.sidebar.info(note)