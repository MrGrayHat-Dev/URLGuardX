# =========================================================
# FILE: features.py
# =========================================================

import re
import math
import numpy as np
import pandas as pd
import tldextract

from urllib.parse import urlparse

from sklearn.preprocessing import LabelEncoder


# =========================================================
# URL FEATURE EXTRACTION
# =========================================================

def entropy(text):

    prob = [
        float(text.count(c)) / len(text)
        for c in dict.fromkeys(list(text))
    ]

    return -sum([p * math.log2(p) for p in prob])


def extract_features(url):

    url = str(url)

    parsed = urlparse(url)

    ext = tldextract.extract(url)

    domain = ext.domain
    suffix = ext.suffix

    host = parsed.netloc
    path = parsed.path
    query = parsed.query

    # =====================================================
    # BASIC COUNTS
    # =====================================================

    url_len = len(url)

    dom_len = len(host)

    tld_len = len(suffix)

    subdom_cnt = (
        len(ext.subdomain.split("."))
        if ext.subdomain else 0
    )

    letter_cnt = sum(c.isalpha() for c in url)

    digit_cnt = sum(c.isdigit() for c in url)

    special_cnt = len(
        re.findall(r"[^A-Za-z0-9]", url)
    )

    eq_cnt = url.count("=")

    qm_cnt = url.count("?")

    amp_cnt = url.count("&")

    dot_cnt = url.count(".")

    dash_cnt = url.count("-")

    under_cnt = url.count("_")

    slash_cnt = url.count("/")

    # =====================================================
    # RATIOS
    # =====================================================

    letter_ratio = (
        letter_cnt / url_len
        if url_len else 0
    )

    digit_ratio = (
        digit_cnt / url_len
        if url_len else 0
    )

    spec_ratio = (
        special_cnt / url_len
        if url_len else 0
    )

    # =====================================================
    # HTTPS
    # =====================================================

    is_https = (
        1 if parsed.scheme == "https"
        else 0
    )

    # =====================================================
    # IP CHECK
    # =====================================================

    is_ip = 1 if re.match(
        r"^\d{1,3}(\.\d{1,3}){3}$",
        host
    ) else 0

    # =====================================================
    # PATH + QUERY
    # =====================================================

    path_len = len(path)

    query_len = len(query)

    # =====================================================
    # ENTROPY
    # =====================================================

    ent = entropy(url)

    # =====================================================
    # RETURN ORDER
    # =====================================================

    return [

        url_len,
        dom_len,
        is_ip,
        tld_len,
        subdom_cnt,
        letter_cnt,
        digit_cnt,
        special_cnt,
        eq_cnt,
        qm_cnt,
        amp_cnt,
        dot_cnt,
        dash_cnt,
        under_cnt,
        letter_ratio,
        digit_ratio,
        spec_ratio,
        is_https,
        slash_cnt,
        ent,
        path_len,
        query_len
    ]


# =========================================================
# DATASET PREPROCESSING
# =========================================================

def preprocess_dataset(df):

    df = df.copy()

    # =====================================================
    # REMOVE UNUSED URL COLUMNS
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
    # LABEL DETECTION
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
    # ENCODE CATEGORICALS
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

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    df.fillna(0, inplace=True)

    X = df.astype(float)

    return X, y