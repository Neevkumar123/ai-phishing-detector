import pandas as pd
from pathlib import Path

from feature_extractor import extract_features


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent

TRAIN_INPUT = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "train.csv"
)

TEST_INPUT = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "test.csv"
)

TRAIN_OUTPUT = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "train_features.csv"
)

TEST_OUTPUT = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "test_features.csv"
)


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
]


def process_dataset(input_path, output_path, dataset_name):
    """
    Extract URL features from a dataset and save the result.
    """

    print(f"\nLoading {dataset_name} dataset...")

    df = pd.read_csv(input_path)

    print(f"Rows loaded: {len(df)}")

    # Extract features from every URL
    print(f"Extracting features from {dataset_name} URLs...")

    feature_data = df["URL"].apply(extract_features)

    features_df = pd.DataFrame(feature_data.tolist())

    # Keep the label
    features_df["Label"] = df["Label"].values

    # Save the feature dataset
    features_df.to_csv(output_path, index=False)

    print(f"{dataset_name} feature extraction completed.")
    print(f"Rows: {len(features_df)}")
    print(f"Columns: {len(features_df.columns)}")
    print(f"Saved to: {output_path}")

    return features_df


def main():
    print("=" * 60)
    print("AI PHISHING WEBSITE DETECTOR")
    print("DATASET FEATURE EXTRACTION")
    print("=" * 60)

    train_df = process_dataset(
        TRAIN_INPUT,
        TRAIN_OUTPUT,
        "training"
    )

    test_df = process_dataset(
        TEST_INPUT,
        TEST_OUTPUT,
        "testing"
    )

    print("\n" + "=" * 60)
    print("FEATURE EXTRACTION SUMMARY")
    print("=" * 60)

    print("\nFeature columns:")

    for column in FEATURE_COLUMNS:
        print(f"- {column}")

    print("\nTraining dataset shape:")
    print(train_df.shape)

    print("\nTesting dataset shape:")
    print(test_df.shape)

    print("\nDataset feature extraction completed successfully.")


if __name__ == "__main__":
    main()