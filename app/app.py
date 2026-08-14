import sys
from pathlib import Path

import streamlit as st
import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


# ============================================================
# IMPORT PREDICTOR
# ============================================================

from predictor import predict_url


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI Phishing Website Detector",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: 700;
        text-align: center;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        font-size: 18px;
        margin-bottom: 30px;
    }

    .safe-box {
        padding: 20px;
        border-radius: 10px;
        background-color: #123d2a;
        border: 1px solid #2ecc71;
        margin-top: 20px;
    }

    .warning-box {
        padding: 20px;
        border-radius: 10px;
        background-color: #4a3a12;
        border: 1px solid #f1c40f;
        margin-top: 20px;
    }

    .danger-box {
        padding: 20px;
        border-radius: 10px;
        background-color: #4a1515;
        border: 1px solid #e74c3c;
        margin-top: 20px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ AI Phishing Website Detector</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Enter a website URL below to analyze its potential phishing risk.'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# URL INPUT
# ============================================================

url = st.text_input(
    "Website URL",
    placeholder="https://example.com",
    help="Enter the complete website URL you want to analyze."
)


# ============================================================
# URL PREPARATION
# ============================================================

def prepare_url(url):

    url = url.strip()

    if not url:
        return None

    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    return url


# ============================================================
# ANALYZE BUTTON
# ============================================================

analyze_button = st.button(
    "🔍 Analyze URL",
    type="primary"
)


# ============================================================
# ANALYSIS
# ============================================================

if analyze_button:

    if not url.strip():

        st.error("Please enter a website URL.")

    else:

        analyzed_url = prepare_url(url)

        try:

            # ==================================================
            # USE CENTRAL PREDICTOR
            # ==================================================

            result = predict_url(analyzed_url)

            prediction = result["prediction"]

            risk_score = result["risk_score"]

            phishing_probability = result["phishing_probability"]

            legitimate_probability = result["legitimate_probability"]

            trusted_domain = result["trusted_domain"]

            features = result["features"]


            # ==================================================
            # RESULT
            # ==================================================

            st.markdown("---")

            st.subheader("🔎 Analysis Result")

            st.write("**Analyzed URL:**")

            st.code(analyzed_url)


            # ==================================================
            # TRUSTED DOMAIN
            # ==================================================

            if trusted_domain:

                st.markdown(
                    """
                    <div class="safe-box">
                        <h2>✅ TRUSTED / LIKELY LEGITIMATE</h2>
                        <p>
                            This domain is included in the trusted-domain
                            protection list.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )


            # ==================================================
            # PHISHING
            # ==================================================

            elif prediction == "PHISHING":

                st.markdown(
                    """
                    <div class="danger-box">
                        <h2>🚨 PHISHING WEBSITE DETECTED</h2>
                        <p>
                            The machine-learning model detected strong
                            characteristics associated with phishing websites.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )


            # ==================================================
            # SUSPICIOUS
            # ==================================================

            elif prediction == "SUSPICIOUS":

                st.markdown(
                    """
                    <div class="warning-box">
                        <h2>⚠️ SUSPICIOUS WEBSITE</h2>
                        <p>
                            The URL contains characteristics that may be
                            associated with phishing.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )


            # ==================================================
            # LEGITIMATE
            # ==================================================

            else:

                st.markdown(
                    """
                    <div class="safe-box">
                        <h2>✅ LIKELY LEGITIMATE WEBSITE</h2>
                        <p>
                            The machine-learning model did not detect strong
                            phishing characteristics.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )


            # ==================================================
            # PROBABILITIES
            # ==================================================

            st.markdown("### 📊 Risk Assessment")

            col1, col2, col3 = st.columns(3)

            with col1:

                st.metric(
                    "Risk Score",
                    f"{risk_score}/100"
                )

            with col2:

                st.metric(
                    "Phishing Probability",
                    f"{phishing_probability * 100:.2f}%"
                )

            with col3:

                st.metric(
                    "Legitimate Probability",
                    f"{legitimate_probability * 100:.2f}%"
                )


            # ==================================================
            # PROBABILITY BAR
            # ==================================================

            st.write("**Phishing Risk Probability**")

            st.progress(
                phishing_probability
            )


            st.write(
                f"**Risk Level:** {prediction}"
            )


            if trusted_domain:

                st.info(
                    "Trusted-domain protection was applied before "
                    "machine-learning classification."
                )


            # ==================================================
            # FEATURES
            # ==================================================

            st.markdown("---")

            st.subheader("🔬 Extracted URL Features")

            feature_display = pd.DataFrame(
                {
                    "Feature": list(features.keys()),
                    "Value": list(features.values())
                }
            )

            st.dataframe(
                feature_display,
                use_container_width=True,
                hide_index=True
            )


            # ==================================================
            # MODEL INFORMATION
            # ==================================================

            st.markdown("---")

            st.subheader("🤖 Machine Learning Model")

            st.write(
                "Random Forest Classifier using 27 URL-based features."
            )

            st.write(
                "**Test accuracy:** 91.21%"
            )


            # ==================================================
            # WARNING
            # ==================================================

            st.warning(
                "This tool provides an AI-based risk assessment and "
                "does not guarantee that a website is safe or malicious."
            )


        except Exception as error:

            st.error(
                "An error occurred while analyzing the URL."
            )

            st.exception(error)


# ============================================================
# ABOUT
# ============================================================

st.markdown("---")

st.header("About this system")

st.write(
    """
    This application uses machine learning and URL-based security
    features to estimate whether a website URL may be associated
    with phishing.
    """
)

st.markdown(
    """
    **Features analyzed include:**

    - URL length
    - Hostname length
    - Dot count
    - Slash count
    - Hyphen count
    - Digit count
    - Query parameters
    - Subdomain count
    - HTTPS usage
    - IP address usage
    - @ symbol usage
    - Suspicious characters
    - Suspicious keywords
    - Domain length
    - Path length
    - Query length
    - Fragment length
    - WWW usage
    - Port usage
    - Hostname digits
    - Path digits
    - Path hyphens
    - Query special characters
    - Double slash count
    - URL shortening
    - Hostname entropy
    - URL entropy
    """
)

st.caption(
    "AI Phishing Website Detector | Academic Project"
)