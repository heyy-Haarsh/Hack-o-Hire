"""
data_ingestion.py – Loads and preprocesses local phishing/legitimate URL datasets.

Supported formats: CSV, JSON

Auto-detected schemas:
  1. Standard schema  – columns: url, label
  2. PhishTank schema – columns: phish_id, url, phish_detail_url, submission_time,
                                  verified, verification_time, online, target
     → all rows treated as label="phishing" (it's a phishing-only feed)
  3. Any schema where a url-like column + label-like column exist

No data is sent anywhere.  Raw URL strings are discarded after feature
extraction; only the numerical feature matrix is retained.
"""
from __future__ import annotations

import hashlib
import json
import dataclasses
from pathlib import Path
from typing import Literal

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from app.config import settings
from app.feature_extractor import URLFeatures, extractor
from app.logger import logger


# ── Known dataset schema patterns ─────────────────────────────────────────────

# PhishTank-style: contains these columns → all rows are phishing
_PHISHTANK_COLS = {"phish_id", "url", "phish_detail_url", "submission_time"}

LABEL_MAP = {
    # Numeric labels
    0: "legitimate",
    1: "phishing",
    2: "suspicious",
    # String variants from common datasets
    "legitimate": "legitimate",
    "phishing": "phishing",
    "benign": "legitimate",
    "malicious": "phishing",
    "suspicious": "suspicious",
    "0": "legitimate",
    "1": "phishing",
    "-1": "legitimate",
}

# URL column name aliases
_URL_COLS = {"url", "urls", "link", "address"}
# Label column name aliases
_LABEL_COLS = {"label", "type", "status", "class", "phishing", "result"}


class DataIngestion:
    """
    Loads local CSV / JSON datasets, cleans them, extracts features,
    and splits into train / test sets.
    """

    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or settings.data_dir

    # ── Public API ─────────────────────────────────────────────────────────────

    def load_all(self) -> tuple[np.ndarray, np.ndarray, LabelEncoder]:
        """
        Scan data_dir for CSV / JSON files, extract features from every URL,
        and return (X, y, label_encoder).
        """
        records = self._load_records()
        if not records:
            raise RuntimeError(
                f"No records found in {self.data_dir}. "
                "Place CSV/JSON datasets there first."
            )

        logger.info(f"Loaded {len(records):,} raw records.")

        # Class balance report
        from collections import Counter
        dist = Counter(r["label"] for r in records)
        logger.info(f"Class distribution before dedup: {dict(dist)}")

        # Deduplicate by URL hash
        records = self._deduplicate(records)
        logger.info(f"After deduplication: {len(records):,} records.")

        dist2 = Counter(r["label"] for r in records)
        logger.info(f"Class distribution after dedup: {dict(dist2)}")

        X, y_raw = self._extract_features(records)

        le = LabelEncoder()
        y = le.fit_transform(y_raw)

        logger.info(
            f"Feature matrix shape: {X.shape} | Classes: {le.classes_.tolist()}"
        )
        return X, y, le

    def train_test(
        self,
    ) -> tuple[
        np.ndarray, np.ndarray, np.ndarray, np.ndarray,
        StandardScaler, LabelEncoder,
    ]:
        """
        Full pipeline: load → clean → extract → scale → split.

        Returns
        -------
        X_train, X_test, y_train, y_test, scaler, label_encoder
        """
        X, y, le = self.load_all()

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled,
            y,
            test_size=settings.test_size,
            random_state=settings.random_seed,
            stratify=y,
        )

        logger.info(
            f"Train: {len(X_train):,} | Test: {len(X_test):,}"
        )
        return X_train, X_test, y_train, y_test, scaler, le

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _load_records(self) -> list[dict]:
        records: list[dict] = []
        self.data_dir.mkdir(parents=True, exist_ok=True)

        for fp in sorted(self.data_dir.rglob("*")):
            if fp.suffix.lower() == ".csv":
                batch = self._load_csv(fp)
                logger.info(f"  {fp.name}: {len(batch):,} records")
                records.extend(batch)
            elif fp.suffix.lower() == ".json":
                batch = self._load_json(fp)
                logger.info(f"  {fp.name}: {len(batch):,} records")
                records.extend(batch)

        return records

    def _load_csv(self, path: Path) -> list[dict]:
        try:
            # First try reading with header
            df = pd.read_csv(path, dtype=str, low_memory=False, nrows=5)
            # If it looks like 'top-1m' (no header, just digits in first col), re-read without header
            if path.name.lower().startswith("top-1m"):
                df = pd.read_csv(path, header=None, dtype=str, low_memory=False, names=["rank", "url"])
            else:
                df = pd.read_csv(path, dtype=str, low_memory=False)
            
            return self._normalise_df(df, path)
        except Exception as exc:
            logger.warning(f"Could not read CSV {path}: {exc}")
            return []

    def _load_json(self, path: Path) -> list[dict]:
        try:
            with path.open() as fh:
                data = json.load(fh)
            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = pd.DataFrame([data])
            return self._normalise_df(df, path)
        except Exception as exc:
            logger.warning(f"Could not read JSON {path}: {exc}")
            return []

    def _normalise_df(self, df: pd.DataFrame, source: Path) -> list[dict]:
        """Detect schema type and normalise to {url, label} records."""
        df.columns = [str(c).strip().lower() for c in df.columns]
        col_set = set(df.columns)

        # ── PhishTank schema detection ─────────────────────────────────────
        if _PHISHTANK_COLS.issubset(col_set):
            logger.info(
                f"  Detected PhishTank schema in {source.name} "
                f"({len(df):,} rows → all labelled 'phishing')"
            )
            return self._load_phishtank(df, source)

        # ── Top 1M schema detection (rank, domain) ─────────────────────────
        if source.name.lower().startswith("top-1m"):
            logger.info(
                f"  Detected Top-1M schema in {source.name} "
                f"({len(df):,} rows → all labelled 'legitimate')"
            )
            # Take a subset to avoid 1M rows for now
            limit = 50_000
            if len(df) > limit:
                df = df.head(limit)
                logger.info(f"  Limited to first {limit:,} records from Top-1M.")
            return self._load_top1m(df)

        # ── Standard schema detection ──────────────────────────────────────
        url_col = next((c for c in df.columns if c in _URL_COLS), None)
        label_col = next((c for c in df.columns if c in _LABEL_COLS), None)

        if url_col is None or label_col is None:
            logger.warning(
                f"Skipping {source.name}: cannot identify url/label columns. "
                f"Columns found: {df.columns.tolist()}"
            )
            return []

        df = df[[url_col, label_col]].dropna()
        df[label_col] = df[label_col].apply(self._map_label)
        df = df[df[label_col].notna()]

        return [
            {"url": row[url_col], "label": row[label_col]}
            for _, row in df.iterrows()
        ]

    def _load_phishtank(self, df: pd.DataFrame, source: Path) -> list[dict]:
        """
        PhishTank-specific loader.

        Filters:
          - verified == 'yes'   (confirmed phishing)
          - online   == 'yes'   (still active — optional, can remove)
          - url must not be empty
        """
        # Optional: filter only verified entries
        if "verified" in df.columns:
            df = df[df["verified"].str.strip().str.lower() == "yes"]

        df = df[df["url"].notna() & (df["url"].str.strip() != "")]

        records = [
            {"url": row["url"].strip(), "label": "phishing"}
            for _, row in df.iterrows()
        ]
        logger.info(
            f"  PhishTank: {len(records):,} verified phishing URLs loaded."
        )
        return records

    def _load_top1m(self, df: pd.DataFrame) -> list[dict]:
        """
        Top 1M specific loader. Everything is legitimate.
        Ensures domains are prepended with http:// if missing.
        Adds both direct and 'www.' versions to the dataset.
        """
        import random
        random.seed(settings.random_seed)  # For reproducible dataset generation

        records = []
        for _, row in df.iterrows():
            domain = str(row["url"]).strip()
            if not domain:
                continue

            # Flip scheme (70% https)
            scheme = "https://" if random.random() < 0.7 else "http://"
            url_direct = f"{scheme}{domain}" if "://" not in domain else domain
            records.append({"url": url_direct, "label": "legitimate"})

            # Occasionally add a path to legitimate URLs so the model learns that
            # having a path (like /index.html) isn't inherently phishing.
            if random.random() < 0.3:
                common_paths = ["index.html", "about", "contact", "faq", "services"]
                path = random.choice(common_paths)
                records.append({"url": f"{url_direct}/{path}", "label": "legitimate"})

            # Add www. version
            if not domain.startswith("www."):
                scheme_www = "https://" if random.random() < 0.7 else "http://"
                url_www = f"{scheme_www}www.{domain}"
                records.append({"url": url_www, "label": "legitimate"})
                
                # Also add path to some www versions
                if random.random() < 0.3:
                    path = random.choice(["index.html", "login", "home"])
                    records.append({"url": f"{url_www}/{path}", "label": "legitimate"})

        return records

    @staticmethod
    def _map_label(raw: object) -> str | None:
        try:
            # Handle potential string/int variations safely
            s_raw = str(raw).strip().lower()
            if s_raw.isdigit():
                key: int | str = int(s_raw)
            else:
                key = s_raw
        except (TypeError, ValueError):
            key = str(raw).strip().lower()
        
        # Explicitly casting for a specific linter that struggles with dict keys
        from typing import Any
        return LABEL_MAP.get(key)  # type: ignore[arg-type]

    @staticmethod
    def _deduplicate(records: list[dict]) -> list[dict]:
        seen: set[str] = set()
        unique: list[dict] = []
        for r in records:
            h = hashlib.sha256(r["url"].encode()).hexdigest()
            if h not in seen:
                seen.add(h)
                unique.append(r)
        return unique

    def _extract_features(
        self, records: list[dict]
    ) -> tuple[np.ndarray, list[str]]:
        rows: list[list[float]] = []
        labels: list[str] = []
        failed = 0

        for i, r in enumerate(records):
            if i % 10_000 == 0 and i > 0:
                logger.info(f"  Feature extraction progress: {i:,}/{len(records):,}")
            try:
                feat = extractor.extract(r["url"])
                rows.append(feat.to_list())
                labels.append(r["label"])
            except Exception:
                failed += 1

        if failed > 0:
            logger.warning(f"Feature extraction failed for {failed} records.")

        return np.array(rows, dtype=np.float32), labels
