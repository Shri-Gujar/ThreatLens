import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import rdpcap

from analyzer import analyze_pcap
from detector import detect_threats
from database import create_database, save_incidents, get_incidents


# -------------------- PAGE SETUP --------------------

st.set_page_config(
    page_title="ThreatLens | Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

create_database()


# -------------------- THEME --------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');

:root {
    --bg: #0b1120;
    --panel: #111b2e;
    --border: #26364d;
    --text: #e8f0fc;
    --muted: #91a4bf;
    --cyan: #35d9f2;
    --teal: #2dd4a8;
}

.stApp {
    background: var(--bg);
    color: var(--text);
    font-family: 'DM Sans', sans-serif;
}

[data-testid="stHeader"] {
    background: rgba(11, 17, 32, 0.95);
}

[data-testid="stSidebar"] {
    background: #0e1728;
    border-right: 1px solid var(--border);
}

[data-testid="stSidebar"] > div {
    padding-top: 1.4rem;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1500px;
}

h1, h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
    color: var(--text) !important;
}

h1 {
    font-size: 2.15rem !important;
    font-weight: 700 !important;
}

h2 {
    font-size: 1.4rem !important;
}

h3 {
    font-size: 1.08rem !important;
}

p, label, li {
    color: #c5d2e5;
}

hr {
    border-color: var(--border);
}

/* Sidebar branding */
.brand-box {
    background: linear-gradient(135deg, #14253b, #102f42);
    border: 1px solid #245168;
    padding: 18px 15px;
    border-radius: 15px;
    margin-bottom: 20px;
}

.brand-name {
    color: #f3f8ff;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 25px;
    font-weight: 700;
}

.brand-name span {
    color: var(--cyan);
}

.brand-subtitle {
    color: #9cb4cb;
    font-size: 10px;
    letter-spacing: 1.4px;
    margin-top: 5px;
}

/* Page heading */
.page-kicker {
    color: var(--cyan);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    margin-bottom: 7px;
}

.page-description {
    color: var(--muted);
    margin-top: -5px;
    margin-bottom: 22px;
}

/* Statistics */
[data-testid="stMetric"] {
    background: linear-gradient(145deg, #15243a, #101b2d);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px;
    min-height: 112px;
}

[data-testid="stMetricLabel"] {
    color: #a7bad1 !important;
    font-size: 13px !important;
}

[data-testid="stMetricValue"] {
    color: #f0f7ff !important;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 29px !important;
    font-weight: 700;
}

/* Upload area */
[data-testid="stFileUploader"] {
    background: #111b2e;
    border: 1px dashed #36516e;
    padding: 12px;
    border-radius: 12px;
}

[data-testid="stFileUploader"] section {
    background: transparent;
}

/* Buttons */
.stButton > button,
.stDownloadButton > button {
    background: linear-gradient(100deg, #087e9a, #087f79);
    color: white !important;
    border: 1px solid #21a9b2;
    border-radius: 9px;
    font-weight: 600;
    padding: 9px 16px;
    transition: all 0.2s ease;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    border-color: var(--cyan);
    background: linear-gradient(100deg, #0b94b4, #0a998b);
}

/* Input fields */
[data-baseweb="select"] > div,
[data-baseweb="input"] > div {
    background: #111b2e;
    border-color: #344760;
    border-radius: 9px;
}

[data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
}

[data-testid="stAlert"] {
    border-radius: 10px;
}

.footer {
    border-top: 1px solid var(--border);
    padding-top: 15px;
    margin-top: 35px;
    color: #7187a2;
    font-size: 11px;
    letter-spacing: 1px;
}

@media (max-width: 768px) {
    .block-container {
        padding-top: 1rem;
    }
    h1 {
        font-size: 1.7rem !important;
    }
}
/* Improved readability and contrast */
.page-description,
.stCaption,
[data-testid="stCaptionContainer"],
[data-testid="stFileUploader"] small,
[data-testid="stFileUploader"] p,
[data-testid="stFileUploader"] span {
    color: #d1deee !important;
}

/* Threat alert tables and their smaller text */
[data-testid="stDataFrame"] *,
[data-testid="stTable"] * {
    color: #e8f0fc !important;
}

/* Upload instructions and file-size limit */
[data-testid="stFileUploader"] section,
[data-testid="stFileUploader"] section small,
[data-testid="stFileUploader"] section span {
    color: #e0eaf8 !important;
}

/* Sidebar descriptions */
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] small,
[data-testid="stSidebar"] label {
    color: #d1deee !important;
}

/* Better contrast for informational messages */
[data-testid="stAlert"] p {
    color: #f1f6ff !important;
}

/* Form labels and helper text */
.stMarkdown p,
[data-testid="stWidgetLabel"] p {
    color: #d1deee;
}
</style>
""", unsafe_allow_html=True)


# -------------------- HELPERS --------------------

def page_header(kicker, title, description):
    st.markdown(
        f'<div class="page-kicker">{kicker}</div>',
        unsafe_allow_html=True
    )
    st.title(title)
    st.markdown(
        f'<div class="page-description">{description}</div>',
        unsafe_allow_html=True
    )


def style_chart(fig):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="DM Sans, sans-serif",
            color="#c5d2e5"
        ),
        title_font=dict(
            family="Space Grotesk, sans-serif",
            size=16,
            color="#e8f0fc"
        ),
        margin=dict(l=15, r=15, t=35, b=15),
        legend=dict(bgcolor="rgba(0,0,0,0)")
    )
    return fig


def render_footer():
    st.markdown(
        '<div class="footer">THREATLENS · NETWORK SECURITY ANALYTICS'
        ' · RULE-BASED DETECTION</div>',
        unsafe_allow_html=True
    )


# -------------------- SIDEBAR --------------------

with st.sidebar:
    st.markdown("""
    <div class="brand-box">
        <div class="brand-name">🛡️ Threat<span>Lens</span></div>
        <div class="brand-subtitle">NETWORK SECURITY PLATFORM</div>
    </div>
    """, unsafe_allow_html=True)

    st.caption("WORKSPACE")

    page = st.radio(
        "Navigation",
        [
            "Security Overview",
            "Traffic Analyzer",
            "Incident History"
        ],
        label_visibility="collapsed"
    )

    st.divider()

    st.markdown("**Detection Engine**")
    st.markdown(
        '<span style="color:#2dd4a8;">●</span> '
        '<span style="color:#91a4bf;">Rule-based analysis</span>',
        unsafe_allow_html=True
    )

    st.caption(
        "Analyze PCAP files and investigate potential network threats."
    )


# -------------------- SECURITY OVERVIEW --------------------

if page == "Security Overview":
    page_header(
        "SECURITY CENTER / OVERVIEW",
        "Security Overview",
        "Monitor saved incidents and review network threat indicators."
    )

    incidents = get_incidents()

    if incidents:
        data = pd.DataFrame(incidents)

        total_incidents = len(data)
        alert_type_count = data["alert_type"].nunique()
        unique_sources = data["source_ip"].nunique()

        col1, col2, col3 = st.columns(3)
        col1.metric("Saved Incidents", total_incidents)
        col2.metric("Alert Categories", alert_type_count)
        col3.metric("Unique Source IPs", unique_sources)

        st.divider()

        left, right = st.columns(2)

        with left:
            st.subheader("Alert Distribution")

            chart_data = (
                data["alert_type"]
                .value_counts()
                .rename_axis("Alert Type")
                .reset_index(name="Count")
            )

            fig = px.pie(
                chart_data,
                names="Alert Type",
                values="Count",
                hole=0.58
            )

            fig.update_traces(
                textposition="inside",
                textinfo="percent+label"
            )

            st.plotly_chart(
                style_chart(fig),
                width="stretch"
            )

        with right:
            st.subheader("Top Source IPs")

            source_data = (
                data["source_ip"]
                .value_counts()
                .head(10)
                .rename_axis("Source IP")
                .reset_index(name="Incident Count")
            )

            fig = px.bar(
                source_data,
                x="Source IP",
                y="Incident Count",
                color="Incident Count",
                color_continuous_scale=["#126782", "#35d9f2"]
            )

            fig.update_layout(coloraxis_showscale=False)

            st.plotly_chart(
                style_chart(fig),
                width="stretch"
            )

        st.info(
            f"Most frequently recorded alert: "
            f"{data['alert_type'].value_counts().index[0]}"
        )

        st.subheader("Recent Incidents")

        st.dataframe(
            data.head(10),
            width="stretch",
            hide_index=True
        )

    else:
        st.info(
            "No saved incidents yet. Open Traffic Analyzer, upload a PCAP "
            "file, and save detected alerts to populate this dashboard."
        )

    render_footer()


# -------------------- TRAFFIC ANALYZER --------------------

elif page == "Traffic Analyzer":
    page_header(
        "SECURITY CENTER / ANALYSIS",
        "Network Traffic Analyzer",
        "Upload a packet capture to analyze IP addresses, protocols "
        "and potential threats."
    )

    uploaded_file = st.file_uploader(
        "Upload network traffic",
        type=["pcap", "pcapng"],
        help="Choose a PCAP or PCAPNG file to analyze."
    )

    if uploaded_file is not None:
        file_path = "uploaded_traffic.pcap"

        with open(file_path, "wb") as file:
            file.write(uploaded_file.getbuffer())

        try:
            results = analyze_pcap(file_path)
            packets = rdpcap(file_path)
            alerts = detect_threats(packets)

            unique_ips = {ip for ip, count in results["top_ips"]}

            st.subheader("Traffic Summary")

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Packets", results["total_packets"])
            col2.metric("Unique IPs in Top 10", len(unique_ips))
            col3.metric("Potential Alerts", len(alerts))

            st.divider()

            left, right = st.columns(2)

            with left:
                st.subheader("Top IP Addresses")

                ip_data = pd.DataFrame(
                    results["top_ips"],
                    columns=["IP Address", "Packet Count"]
                )

                if not ip_data.empty:
                    fig = px.bar(
                        ip_data,
                        x="IP Address",
                        y="Packet Count",
                        color="Packet Count",
                        color_continuous_scale=["#126782", "#35d9f2"]
                    )

                    fig.update_layout(coloraxis_showscale=False)

                    st.plotly_chart(
                        style_chart(fig),
                        width="stretch"
                    )

                    st.dataframe(
                        ip_data,
                        width="stretch",
                        hide_index=True
                    )
                else:
                    st.info("No IP packets found in this file.")

            with right:
                st.subheader("Protocol Distribution")

                protocol_data = pd.DataFrame(
                    list(results["protocols"].items()),
                    columns=["Protocol", "Packets"]
                )

                if not protocol_data.empty:
                    fig = px.pie(
                        protocol_data,
                        names="Protocol",
                        values="Packets",
                        hole=0.52
                    )

                    fig.update_traces(
                        textposition="inside",
                        textinfo="percent+label"
                    )

                    st.plotly_chart(
                        style_chart(fig),
                        width="stretch"
                    )
                else:
                    st.info("No supported IP protocols found.")

            st.divider()
            st.subheader("Threat Detection Alerts")

            if alerts:
                st.warning(
                    f"{len(alerts)} potential alert(s) detected. "
                    "Review the evidence before drawing conclusions."
                )

                st.dataframe(
                    pd.DataFrame(alerts),
                    width="stretch",
                    hide_index=True
                )

                if st.button(
                    "Save Alerts to Incident History",
                    type="primary"
                ):
                    save_incidents(alerts)
                    st.success("Alerts saved to Incident History.")
                    st.rerun()

            else:
                st.success(
                    "No alerts detected by the current detection rules."
                )

            st.caption(
                "Rule-based alerts are indicators, not confirmation of an attack."
            )

        except Exception as error:
            st.error(f"Could not analyze this file: {error}")

    render_footer()


# -------------------- INCIDENT HISTORY --------------------

else:
    page_header(
        "SECURITY CENTER / INVESTIGATION",
        "Incident History",
        "Review saved alerts, filter incidents and export investigation records."
    )

    incidents = get_incidents()

    if incidents:
        data = pd.DataFrame(incidents)

        col1, col2 = st.columns(2)
        col1.metric("Total Saved Incidents", len(data))
        col2.metric("Alert Categories", data["alert_type"].nunique())

        st.divider()
        st.subheader("Filter Incidents")

        alert_types = sorted(
            data["alert_type"].dropna().unique().tolist()
        )

        selected_type = st.selectbox(
            "Alert type",
            ["All Types"] + alert_types
        )

        filtered_data = data.copy()

        if selected_type != "All Types":
            filtered_data = filtered_data[
                filtered_data["alert_type"] == selected_type
            ]

        st.caption(
            f"{len(filtered_data)} incident(s) match your filter."
        )

        st.dataframe(
            filtered_data,
            width="stretch",
            hide_index=True
        )

        csv_data = filtered_data.to_csv(index=False).encode("utf-8")

        st.download_button(
            "Download Incident Report (CSV)",
            data=csv_data,
            file_name="threatlens_incident_report.csv",
            mime="text/csv",
            width="stretch"
        )

    else:
        st.info(
            "No incidents have been saved. Analyze a PCAP file and save "
            "its alerts to see them here."
        )

    render_footer()