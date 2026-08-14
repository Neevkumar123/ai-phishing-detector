import pandas as pd
from pathlib import Path


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent

RAW_DATASET = PROJECT_ROOT / "data" / "raw" / "phishing_site_urls.csv"
PROCESSED_DATASET = PROJECT_ROOT / "data" / "processed" / "phishing_urls_processed.csv"


def load_dataset():
    """Load the original dataset."""
    print("Loading dataset...")

    df = pd.read_csv(RAW_DATASET)

    print(f"Loaded {len(df)} rows.")

    return df


def clean_dataset(df):
    """Clean and prepare the dataset."""

    # Keep only the required columns
    df = df[["URL", "Label"]].copy()

    # Remove rows with missing URL or label
    df = df.dropna(subset=["URL", "Label"])

    # Remove duplicate URL/label combinations
    df = df.drop_duplicates(subset=["URL", "Label"])

    # Convert labels to numerical values
    label_mapping = {
        "good": 0,
        "bad": 1
    }

    df["Label"] = df["Label"].map(label_mapping)

    # Remove rows with unexpected labels
    df = df.dropna(subset=["Label"])

    # Make sure labels are integers
    df["Label"] = df["Label"].astype(int)

    # Reset row numbering
    df = df.reset_index(drop=True)

    return df


def save_dataset(df):
    """Save the processed dataset."""

    PROCESSED_DATASET.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(PROCESSED_DATASET, index=False)

    print(f"\nProcessed dataset saved to:")
    print(PROCESSED_DATASET)


def main():
    print("=" * 60)
    print("AI PHISHING WEBSITE DETECTOR")
    print("DATASET PREPARATION")
    print("=" * 60)

    df = load_dataset()

    print("\nCleaning dataset...")

    df = clean_dataset(df)

    print("\n--- Processed Dataset Information ---")
    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")

    print("\n--- Label Distribution ---")
    print(df["Label"].value_counts().sort_index())

    save_dataset(df)

    print("\nDataset preparation completed successfully.")


if __name__ == "__main__":
    main()