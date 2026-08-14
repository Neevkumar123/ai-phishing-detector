import pandas as pd
from pathlib import Path


# Find the project folder automatically
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Dataset location
DATASET_PATH = PROJECT_ROOT / "data" / "raw" / "phishing_site_urls.csv"


print("=" * 60)
print("AI PHISHING WEBSITE DETECTOR")
print("DATASET INSPECTION")
print("=" * 60)

print(f"\nDataset: {DATASET_PATH}")

# Load the dataset
df = pd.read_csv(DATASET_PATH)

print("\nDataset loaded successfully!")

print("\n--- Dataset Shape ---")
print(f"Rows: {df.shape[0]}")
print(f"Columns: {df.shape[1]}")

print("\n--- Column Names ---")
print(df.columns.tolist())

print("\n--- First 5 Rows ---")
print(df.head())

print("\n--- Missing Values ---")
print(df.isnull().sum())

print("\n--- Duplicate Rows ---")
print(df.duplicated().sum())

print("\n--- Data Types ---")
print(df.dtypes)

print("\n--- Label Distribution ---")
print(df["Label"].value_counts(dropna=False))

print("\n--- Unique Labels ---")
print(df["Label"].unique())

print("\n" + "=" * 60)
print("Inspection completed.")
print("=" * 60)