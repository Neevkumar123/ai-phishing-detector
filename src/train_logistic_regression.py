import os
import pandas as pd
import joblib

from sklearn.linear_model import LogisticRegression
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
    "logistic_regression.joblib"
)


# ============================================================
# FEATURE COLUMNS
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
    "suspicious_keyword_count"
]


# ============================================================
# LOAD DATA
# ============================================================

def load_data():

    print("Loading training dataset...")
    train_df = pd.read_csv(TRAIN_FILE)

    print("Loading testing dataset...")
    test_df = pd.read_csv(TEST_FILE)

    return train_df, test_df


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("AI PHISHING WEBSITE DETECTOR")
    print("LOGISTIC REGRESSION TRAINING")
    print("=" * 60)

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    train_df, test_df = load_data()

    print()
    print("Training rows:", len(train_df))
    print("Testing rows: ", len(test_df))

    # --------------------------------------------------------
    # Separate features and labels
    # --------------------------------------------------------

    X_train = train_df[FEATURE_COLUMNS]
    y_train = train_df["Label"]

    X_test = test_df[FEATURE_COLUMNS]
    y_test = test_df["Label"]

    print()
    print("Preparing features...")

    # --------------------------------------------------------
    # Load preprocessing pipeline
    # --------------------------------------------------------

    print("Loading preprocessor...")

    preprocessor = joblib.load(
        PREPROCESSOR_FILE
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

    # --------------------------------------------------------
    # Create Logistic Regression model
    # --------------------------------------------------------

    print()
    print("Creating Logistic Regression model...")

    model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42
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
    # Make predictions
    # --------------------------------------------------------

    print()
    print("Making predictions on test data...")

    y_pred = model.predict(
        X_test_processed
    )

    # --------------------------------------------------------
    # Calculate metrics
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
    print("LOGISTIC REGRESSION RESULTS")
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

    print("Model saved to:")
    print(MODEL_FILE)

    print()
    print("=" * 60)
    print("LOGISTIC REGRESSION TRAINING COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()