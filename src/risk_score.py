def calculate_risk_score(phishing_probability):
    """
    Convert phishing probability into a risk score,
    risk level, and description.

    Parameters:
        phishing_probability (float):
            Probability of the URL being phishing.
            Expected value between 0 and 1.

    Returns:
        tuple:
            risk_score
            risk_level
            description
    """

    # Convert probability to percentage
    risk_score = phishing_probability * 100

    # Determine risk level
    if risk_score < 30:
        risk_level = "Low Risk"

        description = (
            "The URL appears relatively safe based on "
            "the model analysis."
        )

    elif risk_score < 70:
        risk_level = "Suspicious"

        description = (
            "The URL contains characteristics that may "
            "indicate phishing."
        )

    else:
        risk_level = "High Risk"

        description = (
            "The URL shows strong characteristics "
            "associated with phishing."
        )

    return risk_score, risk_level, description


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("AI PHISHING WEBSITE DETECTOR")
    print("RISK SCORE TEST")
    print("=" * 60)

    test_probabilities = [
        0.10,
        0.35,
        0.65,
        0.85,
        0.97
    ]

    for probability in test_probabilities:

        score, level, description = calculate_risk_score(
            probability
        )

        print()
        print(f"Phishing Probability: {probability}")
        print(f"Risk Score: {score:.1f}")
        print(f"Risk Level: {level}")
        print(f"Description: {description}")

    print()
    print("=" * 60)
    print("RISK SCORE TEST COMPLETED")
    print("=" * 60)