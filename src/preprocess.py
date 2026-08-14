import pandas as pd
import joblib
from pathlib import Path
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TRAIN_INPUT = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "train_features.csv"
)

TEST_INPUT = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "test_features.csv"
)

PREPROCESSOR_OUTPUT = (
    PROJECT_ROOT
    / "models"
    / "preprocessor.joblib"
)


# ============================================================
# ALL FEATURE COLUMNS
# ============================================================

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "dot_count",
    "slash_count",
    "hyphen_count",
    "digit_count",
    "query_parameter_count",
    "subdomain_count",
    "has_https",
    "has_ip_address",
    "has_at_symbol",
    "suspicious_character_count",
    "suspicious_keyword_count",

    # Additional URL features
    "domain_length",
    "path_length",
    "query_length",
    "fragment_length",
    "has_www",
    "has_port",
    "hostname_digit_count",
    "path_digit_count",
    "path_hyphen_count",
    "query_special_character_count",
    "double_slash_count",
    "is_shortened_url",
    "hostname_entropy",
    "url_entropy",
]


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("AI PHISHING WEBSITE DETECTOR")
    print("DATA PREPROCESSING")
    print("=" * 60)

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    print("Loading training dataset...")
    train_df = pd.read_csv(TRAIN_INPUT)

    print("Loading testing dataset...")
    test_df = pd.read_csv(TEST_INPUT)

    print()
    print(f"Training rows: {len(train_df)}")
    print(f"Testing rows:  {len(test_df)}")

    # --------------------------------------------------------
    # Check feature columns
    # --------------------------------------------------------

    missing_train = [
        col for col in FEATURE_COLUMNS
        if col not in train_df.columns
    ]

    missing_test = [
        col for col in FEATURE_COLUMNS
        if col not in test_df.columns
    ]

    if missing_train:
        raise ValueError(
            f"Missing training features: {missing_train}"
        )

    if missing_test:
        raise ValueError(
            f"Missing testing features: {missing_test}"
        )

    # --------------------------------------------------------
    # Select features
    # --------------------------------------------------------

    X_train = train_df[FEATURE_COLUMNS]
    X_test = test_df[FEATURE_COLUMNS]

    print()
    print(f"Number of features: {len(FEATURE_COLUMNS)}")

    print()
    print("Feature columns:")

    for column in FEATURE_COLUMNS:
        print(f"- {column}")

    print()
    print("Feature data types:")
    print(X_train.dtypes)

    # --------------------------------------------------------
    # Preprocessing pipeline
    # --------------------------------------------------------

    preprocessor = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(strategy="median")
            ),
            (
                "scaler",
                StandardScaler()
            )
        ]
    )

    # --------------------------------------------------------
    # Fit ONLY on training data
    # --------------------------------------------------------

    print()
    print("Fitting preprocessor on training data...")

    X_train_processed = preprocessor.fit_transform(X_train)

    print("Transforming testing data...")

    X_test_processed = preprocessor.transform(X_test)

    # --------------------------------------------------------
    # Display shapes
    # --------------------------------------------------------

    print()
    print("Processed training shape:")
    print(X_train_processed.shape)

    print()
    print("Processed testing shape:")
    print(X_test_processed.shape)

    # --------------------------------------------------------
    # Save preprocessor
    # --------------------------------------------------------

    joblib.dump(
        preprocessor,
        PREPROCESSOR_OUTPUT
    )

    print()
    print("Preprocessor saved to:")
    print(PREPROCESSOR_OUTPUT)

    print()
    print("=" * 60)
    print("DATA PREPROCESSING COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()