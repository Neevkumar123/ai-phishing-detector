import sys
from pathlib import Path

import pandas as pd
import joblib


# ============================================================
# PATH SETUP
# ============================================================

SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent

sys.path.insert(0, str(SRC_DIR))

from feature_extractor import extract_features
from trusted_domains import is_trusted_domain


MODEL_FILE = PROJECT_ROOT / "models" / "random_forest.joblib"
PREPROCESSOR_FILE = PROJECT_ROOT / "models" / "preprocessor.joblib"


# ============================================================
# LOAD MODEL
# ============================================================

model = joblib.load(MODEL_FILE)
preprocessor = joblib.load(PREPROCESSOR_FILE)


# ============================================================
# PREDICT URL
# ============================================================

def predict_url(url):

    # --------------------------------------------------------
    # Trusted domain check
    # --------------------------------------------------------

    if is_trusted_domain(url):

        return {
            "prediction": "LEGITIMATE",
            "risk_score": 0,
            "phishing_probability": 0.0,
            "legitimate_probability": 1.0,
            "trusted_domain": True,
            "features": extract_features(url)
        }

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    features = extract_features(url)

    feature_df = pd.DataFrame([features])

    # --------------------------------------------------------
    # Preprocess
    # --------------------------------------------------------

    processed = preprocessor.transform(feature_df)

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = model.predict(processed)[0]

    probabilities = model.predict_proba(processed)[0]

    legitimate_probability = float(probabilities[0])
    phishing_probability = float(probabilities[1])

    # --------------------------------------------------------
    # Risk score
    # --------------------------------------------------------

    risk_score = round(phishing_probability * 100)

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if risk_score >= 70:
        result = "PHISHING"

    elif risk_score >= 40:
        result = "SUSPICIOUS"

    else:
        result = "LEGITIMATE"

    return {
        "prediction": result,
        "risk_score": risk_score,
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
        "trusted_domain": False,
        "features": features
    }