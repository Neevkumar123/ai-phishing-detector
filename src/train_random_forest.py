import os
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

TRAIN_FILE = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "train_features.csv"
)

TEST_FILE = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "test_features.csv"
)

PREPROCESSOR_FILE = os.path.join(
    BASE_DIR,
    "models",
    "preprocessor.joblib"
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "models",
    "random_forest.joblib"
)


# ============================================================
# FEATURE COLUMNS
# ============================================================

FEATURE_COLUMNS = [
    # Original URL features
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
    "url_entropy"
]


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("AI PHISHING WEBSITE DETECTOR")
    print("RANDOM FOREST TRAINING")
    print("=" * 60)

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    print("Loading training dataset...")
    train_df = pd.read_csv(TRAIN_FILE)

    print("Loading testing dataset...")
    test_df = pd.read_csv(TEST_FILE)

    print()
    print("Training rows:", len(train_df))
    print("Testing rows: ", len(test_df))

    # --------------------------------------------------------
    # Verify features
    # --------------------------------------------------------

    missing_train = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in train_df.columns
    ]

    missing_test = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in test_df.columns
    ]

    if missing_train:
        raise ValueError(
            f"Missing training features: {missing_train}"
        )

    if missing_test:
        raise ValueError(
            f"Missing testing features: {missing_test}"
        )

    print()
    print("Number of features:", len(FEATURE_COLUMNS))

    # --------------------------------------------------------
    # Separate features and labels
    # --------------------------------------------------------

    X_train = train_df[FEATURE_COLUMNS]
    y_train = train_df["Label"]

    X_test = test_df[FEATURE_COLUMNS]
    y_test = test_df["Label"]

    # --------------------------------------------------------
    # Load preprocessing pipeline
    # --------------------------------------------------------

    print()
    print("Loading preprocessor...")

    preprocessor = joblib.load(
        PREPROCESSOR_FILE
    )

    # --------------------------------------------------------
    # Verify preprocessor feature count
    # --------------------------------------------------------

    print("Checking preprocessor...")

    if hasattr(preprocessor, "feature_names_in_"):

        preprocessor_features = list(
            preprocessor.feature_names_in_
        )

        if preprocessor_features != FEATURE_COLUMNS:

            raise ValueError(
                "Feature mismatch between train_random_forest.py "
                "and preprocessor.joblib.\n\n"
                f"Expected:\n{FEATURE_COLUMNS}\n\n"
                f"Preprocessor has:\n{preprocessor_features}"
            )

    # --------------------------------------------------------
    # Transform data
    # --------------------------------------------------------

    print("Transforming training data...")

    X_train_processed = preprocessor.transform(
        X_train
    )

    print("Transforming testing data...")

    X_test_processed = preprocessor.transform(
        X_test
    )

    print()
    print("Training matrix shape:")
    print(X_train_processed.shape)

    print()
    print("Testing matrix shape:")
    print(X_test_processed.shape)

    # --------------------------------------------------------
    # Create Random Forest
    # --------------------------------------------------------

    print()
    print("Creating Random Forest model...")

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    # --------------------------------------------------------
    # Train model
    # --------------------------------------------------------

    print("Training model...")

    model.fit(
        X_train_processed,
        y_train
    )

    print("Model training completed.")

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    print()
    print("Making predictions on test data...")

    y_pred = model.predict(
        X_test_processed
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("RANDOM FOREST RESULTS")
    print("=" * 60)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1-score : {f1:.4f}")

    print()
    print("Confusion Matrix:")
    print(cm)

    print()
    print("Classification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "Legitimate",
                "Phishing"
            ],
            zero_division=0
        )
    )

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    print()
    print("Feature Importance:")

    importance_data = list(
        zip(
            FEATURE_COLUMNS,
            model.feature_importances_
        )
    )

    importance_data.sort(
        key=lambda item: item[1],
        reverse=True
    )

    for feature, importance in importance_data:
        print(
            f"{feature}: {importance:.4f}"
        )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    os.makedirs(
        os.path.dirname(MODEL_FILE),
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_FILE
    )

    print()
    print("Model saved to:")
    print(MODEL_FILE)

    print()
    print("=" * 60)
    print("RANDOM FOREST TRAINING COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()