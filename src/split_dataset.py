import pandas as pd
from pathlib import Path

from sklearn.model_selection import train_test_split


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phishing_urls_processed.csv"
)

TRAIN_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "train.csv"
)

TEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "test.csv"
)


def main():
    print("=" * 60)
    print("AI PHISHING WEBSITE DETECTOR")
    print("TRAIN / TEST SPLIT")
    print("=" * 60)

    print("\nLoading processed dataset...")

    df = pd.read_csv(DATASET_PATH)

    print(f"Total rows: {len(df)}")

    # Separate input URLs and target labels
    X = df["URL"]
    y = df["Label"]

    # 80% training, 20% testing
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    # Reconstruct training and testing DataFrames
    train_df = pd.DataFrame({
        "URL": X_train,
        "Label": y_train
    })

    test_df = pd.DataFrame({
        "URL": X_test,
        "Label": y_test
    })

    # Save the datasets
    train_df.to_csv(TRAIN_PATH, index=False)
    test_df.to_csv(TEST_PATH, index=False)

    print("\n--- Split Results ---")
    print(f"Training rows: {len(train_df)}")
    print(f"Testing rows:  {len(test_df)}")

    print("\n--- Training Label Distribution ---")
    print(train_df["Label"].value_counts().sort_index())

    print("\n--- Testing Label Distribution ---")
    print(test_df["Label"].value_counts().sort_index())

    print("\nTraining dataset saved to:")
    print(TRAIN_PATH)

    print("\nTesting dataset saved to:")
    print(TEST_PATH)

    print("\nTrain/test split completed successfully.")


if __name__ == "__main__":
    main()