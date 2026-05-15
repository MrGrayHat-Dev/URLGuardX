# =========================
# FILE: features.py
# =========================

import pandas as pd
import numpy as np

from sklearn.preprocessing import LabelEncoder


def preprocess_dataset(df):

    df = df.copy()

    # =====================================================
    # REMOVE UNUSED / URL COLUMNS
    # =====================================================

    remove_cols = [
        "url",
        "URL",
        "domain"
    ]

    for col in remove_cols:
        if col in df.columns:
            df.drop(columns=[col], inplace=True)

    # =====================================================
    # AUTO DETECT LABEL COLUMN
    # =====================================================

    possible_labels = [
        "label",
        "Label",
        "status",
        "result",
        "Class"
    ]

    label_col = None

    for col in possible_labels:
        if col in df.columns:
            label_col = col
            break

    if label_col is None:
        raise Exception(
            "❌ Label column not found."
        )

    # =====================================================
    # LABEL NORMALIZATION
    # =====================================================

    y = df[label_col]

    if y.dtype == object:

        y = y.astype(str).str.lower()

        y = y.map(
            lambda x:
                1 if x in [
                    "1",
                    "phishing",
                    "bad",
                    "malicious"
                ] else 0
        )

    df.drop(columns=[label_col], inplace=True)

    # =====================================================
    # HANDLE CATEGORICAL FEATURES
    # =====================================================

    categorical_cols = df.select_dtypes(
        include=["object"]
    ).columns

    for col in categorical_cols:

        le = LabelEncoder()

        df[col] = le.fit_transform(
            df[col].astype(str)
        )

    # =====================================================
    # CLEAN NUMERICS
    # =====================================================

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    df.fillna(0, inplace=True)

    X = df.astype(float)

    return X, y