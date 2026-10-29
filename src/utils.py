"""
Shared utilities for Autonomous Network Shield.
"""

import pandas as pd


def to_ist(series: pd.Series) -> pd.Series:
    """Convert UTC ISO timestamp series into Indian Standard Time (IST, UTC+5:30) strings.

    Handles mixed formats, naive/aware timestamps, and missing values gracefully.
    """
    if series is None or series.empty:
        return series
    try:
        dt = pd.to_datetime(series, format="mixed", utc=True)
        return dt.dt.tz_convert("Asia/Kolkata").dt.strftime("%Y-%m-%d %H:%M:%S IST").fillna("-")
    except Exception:
        return series
