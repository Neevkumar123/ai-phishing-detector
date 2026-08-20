import sys
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from predictor import predict_url

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Phishing Website Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ============================================================
# CSS
# ============================================================

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(135deg, #fff8f4 0%, #ffffff 45%, #fffaf8 100%);
        color: #111111;
    }

    .block-container {
        max-width: 1180px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    .top-card {
        background: rgba(255,255,255,0.96);
        border: 1px solid #f0d9d0;
        border-radius: 14px;
        padding: 20px 28px 16px 28px;
        box-shadow: 0 5px 18px rgba(55, 30, 20, 0.05);
        margin-bottom: 14px;
    }

    .title {
        font-size: 31px;
        font-weight: 750;
        margin: 0;
        color: #111111;
    }

    .subtitle {
        margin: 4px 0 0 0;
        color: #6b625e;
        font-size: 15px;
    }

    .section-card {
        background: rgba(255,255,255,0.96);
        border: 1px solid #eadfd9;
        border-radius: 14px;
        padding: 18px;
        box-shadow: 0 4px 15px rgba(55, 30, 20, 0.04);
        height: 100%;
    }

    .section-title {
        font-size: 18px;
        font-weight: 700;
        margin-bottom: 10px;
    }

    .metric-card {
        background: #ffffff;
        border: 1px solid #eadfd9;
        border-radius: 14px;
        padding: 18px;
        min-height: 145px;
        box-shadow: 0 4px 15px rgba(55, 30, 20, 0.04);
    }

    .metric-title {
        font-size: 16px;
        color: #222222;
        font-weight: 600;
    }

    .metric-value {
        font-size: 30px;
        line-height: 1.05;
        font-weight: 750;
        margin-top: 25px;
        color: #111111;
    }

    .metric-sub {
        font-size: 12px;
        color: #7b726d;
        margin-top: 7px;
    }

    .result-safe {
        background: #effaf2;
        border: 1px solid #b9e6c5;
        border-radius: 14px;
        padding: 18px 20px;
        margin-top: 10px;
    }

    .result-warning {
        background: #fff8e7;
        border: 1px solid #efd38a;
        border-radius: 14px;
        padding: 18px 20px;
        margin-top: 10px;
    }

    .result-danger {
        background: #fff0ef;
        border: 1px solid #efb7b2;
        border-radius: 14px;
        padding: 18px 20px;
        margin-top: 10px;
    }

    .result-title {
        font-size: 25px;
        font-weight: 750;
        margin-bottom: 5px;
    }

    .prob-phishing {
        color: #c62828;
        font-size: 28px;
        font-weight: 750;
    }

    .prob-legitimate {
        color: #16803c;
        font-size: 28px;
        font-weight: 750;
    }

    .risk-number {
        font-size: 42px;
        font-weight: 800;
        color: #111111;
        text-align: center;
    }

    .risk-ring {
        width: 118px;
        height: 118px;
        border-radius: 50%;
        margin: 12px auto;
        display: flex;
        align-items: center;
        justify-content: center;
        background: conic-gradient(#9a4f2f var(--risk), #f4ddd2 0);
        position: relative;
    }

    .risk-ring::after {
        content: "";
        position: absolute;
        width: 82px;
        height: 82px;
        border-radius: 50%;
        background: white;
    }

    .risk-ring span {
        position: relative;
        z-index: 2;
        font-size: 25px;
        font-weight: 750;
        color: #111111;
    }

    .small-note {
        color: #766d68;
        font-size: 13px;
    }

    div[data-testid="stTextInput"] input {
        border-radius: 9px;
        border: 1px solid #b9aaa3;
        min-height: 50px;
        font-size: 17px;
    }

    div[data-testid="stButton"] button {
        border-radius: 9px;
        min-height: 50px;
        font-weight: 650;
    }

    .footer-note {
        background: #fff7f3;
        border: 1px solid #efd9cf;
        border-radius: 12px;
        padding: 13px 16px;
        color: #665b55;
        font-size: 13px;
        margin-top: 18px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <div class="top-card">
        <div class="title">🛡️ Welcome to AI Phishing Website Detector</div>
        <div class="subtitle">
            Analyze a website URL and estimate its phishing risk using machine learning.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# URL INPUT
# ============================================================

left, right = st.columns([1.8, 0.55], gap="large")

with left:
    st.markdown("### Analyzed URL")
    url = st.text_input(
        "Website URL",
        placeholder="https://example.com",
        label_visibility="collapsed",
    )

with right:
    st.write("")
    st.write("")
    analyze = st.button("🔍  Analyze URL", type="primary", use_container_width=True)

# ============================================================
# ANALYSIS STATE
# ============================================================

if "last_result" not in st.session_state:
    st.session_state.last_result = None

if analyze:
    clean_url = url.strip()

    if not clean_url:
        st.error("Please enter a website URL.")
    else:
        if not clean_url.lower().startswith(("http://", "https://")):
            clean_url = "https://" + clean_url

        parsed = urlparse(clean_url)

        if not parsed.netloc:
            st.error("Please enter a valid website URL.")
        else:
            try:
                st.session_state.last_result = predict_url(clean_url)
                st.session_state.last_url = clean_url
            except Exception as error:
                st.error("An error occurred while analyzing the URL.")
                st.exception(error)

result = st.session_state.last_result

# ============================================================
# DASHBOARD CONTENT
# ============================================================

if result is None:
    chart_left, chart_right = st.columns(2, gap="large")

    with chart_left:
        st.markdown(
            '<div class="section-card"><div class="section-title">📈 URL Structure Statistics</div>',
            unsafe_allow_html=True,
        )
        st.info("Enter a URL above to generate URL feature statistics.")
        st.markdown("</div>", unsafe_allow_html=True)

    with chart_right:
        st.markdown(
            '<div class="section-card"><div class="section-title">📊 Risk Assessment</div>',
            unsafe_allow_html=True,
        )
        st.info("Risk statistics will appear after URL analysis.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("")
    c1, c2, c3 = st.columns(3, gap="large")

    with c1:
        st.markdown(
            '<div class="metric-card"><div class="metric-title">🎯 Phishing Probability</div>'
            '<div class="metric-value">—</div>'
            '<div class="metric-sub">Run an analysis to calculate</div></div>',
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            '<div class="metric-card"><div class="metric-title">✅ Legitimate Probability</div>'
            '<div class="metric-value">—</div>'
            '<div class="metric-sub">Run an analysis to calculate</div></div>',
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            '<div class="metric-card"><div class="metric-title">📊 Risk Score</div>'
            '<div class="metric-value">—</div>'
            '<div class="metric-sub">Risk score from 0 to 100</div></div>',
            unsafe_allow_html=True,
        )

else:
    phishing = float(result["phishing_probability"])
    legitimate = float(result["legitimate_probability"])
    risk = int(result["risk_score"])
    prediction = result["prediction"]
    trusted = bool(result.get("trusted_domain", False))
    features = result.get("features", {})

    st.markdown("")
    result_col, risk_col = st.columns([1.4, 0.75], gap="large")

    with result_col:
        if prediction == "PHISHING":
            box_class = "result-danger"
            icon = "🚨"
            title = "PHISHING WEBSITE DETECTED"
            message = "The model detected URL characteristics associated with phishing."
        elif prediction == "SUSPICIOUS":
            box_class = "result-warning"
            icon = "⚠️"
            title = "SUSPICIOUS WEBSITE"
            message = "The URL contains characteristics that require caution."
        else:
            box_class = "result-safe"
            icon = "✅"
            title = "LIKELY LEGITIMATE"
            message = (
                "The URL did not show strong phishing characteristics."
                if not trusted
                else "This domain is included in the trusted-domain protection list."
            )

        st.markdown(
            f"""
            <div class="{box_class}">
                <div class="result-title">{icon} {title}</div>
                <div>{message}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("### Probability Assessment")
        p1, p2 = st.columns(2)

        with p1:
            st.markdown(
                f'<div class="metric-card"><div class="metric-title">Phishing Probability</div>'
                f'<div class="prob-phishing">{phishing * 100:.2f}%</div>'
                f'<div class="metric-sub">Estimated phishing likelihood</div></div>',
                unsafe_allow_html=True,
            )

        with p2:
            st.markdown(
                f'<div class="metric-card"><div class="metric-title">Legitimate Probability</div>'
                f'<div class="prob-legitimate">{legitimate * 100:.2f}%</div>'
                f'<div class="metric-sub">Estimated legitimate likelihood</div></div>',
                unsafe_allow_html=True,
            )

    with risk_col:
        st.markdown(
            f"""
            <div class="section-card">
                <div class="section-title">📊 Risk Score</div>
                <div class="risk-ring" style="--risk:{risk * 3.6}deg">
                    <span>{risk}</span>
                </div>
                <div class="risk-number">{risk}/100</div>
                <div style="text-align:center" class="small-note">
                    Risk calculated from phishing probability
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("")
    feature_col, risk_chart_col = st.columns(2, gap="large")

    with feature_col:
        st.markdown(
            '<div class="section-card"><div class="section-title">📈 URL Feature Statistics</div>',
            unsafe_allow_html=True,
        )

        feature_names = [
            "url_length",
            "hostname_length",
            "dot_count",
            "slash_count",
            "hyphen_count",
            "digit_count",
            "query_parameter_count",
            "subdomain_count",
        ]

        values = {
            name: float(features.get(name, 0))
            for name in feature_names
            if name in features
        }

        if values:
            chart_df = pd.DataFrame(
                {"Feature": list(values.keys()), "Value": list(values.values())}
            ).set_index("Feature")
            st.bar_chart(chart_df, height=250)
        else:
            st.info("Feature values are not available for this URL.")

        st.markdown("</div>", unsafe_allow_html=True)

    with risk_chart_col:
        st.markdown(
            '<div class="section-card"><div class="section-title">📊 Risk Assessment</div>',
            unsafe_allow_html=True,
        )

        risk_df = pd.DataFrame(
            {
                "Category": ["Legitimate", "Phishing"],
                "Probability": [legitimate * 100, phishing * 100],
            }
        ).set_index("Category")

        st.bar_chart(risk_df, height=250)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("")
    st.markdown("### 🔬 Extracted URL Features")

    if features:
        feature_display = pd.DataFrame(
            {
                "Feature": list(features.keys()),
                "Value": list(features.values()),
            }
        )
        st.dataframe(
            feature_display,
            use_container_width=True,
            hide_index=True,
        )

    st.markdown(
        """
        <div class="footer-note">
            <b>🤖 Model:</b> Random Forest Classifier &nbsp; | &nbsp;
            <b>Test accuracy:</b> 91.21% &nbsp; | &nbsp;
            Prediction is based on static URL features and is not a guarantee of website safety.
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown(
    """
    <div class="footer-note">
        🛡️ <b>Safety notice:</b> This academic project analyzes URL characteristics.
        Do not enter passwords, payment information, or other sensitive data into suspicious websites.
    </div>
    """,
    unsafe_allow_html=True,
)
