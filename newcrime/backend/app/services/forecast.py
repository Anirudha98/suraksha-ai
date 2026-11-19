"""Crime forecasting from local case history (replaces QuickML Prophet).

Fits a linear trend to daily case counts over the recent history window and
projects it forward with a 95% band from the residual spread.

ponytail: linear trend, no weekly/yearly seasonality. Swap in Prophet or
statsmodels if the host has the RAM (Render free has 512 MB) and the data has
enough history for seasonality to matter.
"""
from __future__ import annotations

import statistics
from collections import Counter
from datetime import date, datetime, timedelta

# Last failure, surfaced by /api/health.
last_error: str | None = None

HISTORY_DAYS = 180


def _daily_counts(crime_type, district) -> tuple[list[int], date] | None:
    from ..database import SessionLocal
    from .. import models as m
    db = SessionLocal()
    try:
        q = db.query(m.Case.occurrence_date).filter(m.Case.occurrence_date.isnot(None))
        if crime_type:
            q = q.filter(m.Case.crime_type == crime_type)
        if district:
            q = q.filter(m.Case.district == district)
        days = [d.date() if isinstance(d, datetime) else d for (d,) in q.all()]
        # anchor on the newest case overall, like Prophet's last `ds`
        newest = db.query(m.Case.occurrence_date).order_by(
            m.Case.occurrence_date.desc()).first()
    finally:
        db.close()
    if not newest or not newest[0]:
        return None
    end = newest[0].date() if isinstance(newest[0], datetime) else newest[0]
    start = end - timedelta(days=HISTORY_DAYS - 1)
    hits = Counter(d for d in days if start <= d <= end)
    return [hits.get(start + timedelta(days=i), 0) for i in range(HISTORY_DAYS)], end


def project(counts: list[int], end: date, horizon_days: int) -> list[dict]:
    xs = range(len(counts))
    slope, intercept = statistics.linear_regression(xs, counts)
    resid = [c - (slope * x + intercept) for x, c in zip(xs, counts)]
    band = 1.96 * statistics.pstdev(resid)
    out = []
    for h in range(1, horizon_days + 1):
        y = max(0.0, slope * (len(counts) - 1 + h) + intercept)
        out.append({"date": (end + timedelta(days=h)).isoformat(),
                    "predicted_count": round(y, 3),
                    "lower_bound": round(max(0.0, y - band), 3),
                    "upper_bound": round(y + band, 3)})
    return out


def get_forecast(crime_type: str | None = None, district: str | None = None,
                 horizon_days: int = 30) -> list[dict]:
    global last_error
    try:
        hist = _daily_counts(crime_type, district)
        last_error = None
        return project(*hist, horizon_days) if hist else []
    except Exception as e:
        last_error = f"{type(e).__name__}: {e}"[:300]
        return []


def get_risk_assessment(district: str) -> dict:
    """Forecast the main crime types for one district.

    One network round trip per crime type inside a serverless request, so keep
    the list short.
    """
    from ..services.nlq import CRIME_LEXICON
    risks = []
    for crime_type in sorted(set(CRIME_LEXICON.values()))[:8]:
        forecast = get_forecast(crime_type=crime_type, district=district)
        if not forecast:
            continue
        total = sum(f["predicted_count"] for f in forecast)
        risks.append({
            "crime_type": crime_type,
            "predicted_cases": round(total, 1),
            "risk_level": "High" if total > 10 else "Medium" if total > 3 else "Low",
        })
    risks.sort(key=lambda r: -r["predicted_cases"])
    return {
        "district": district,
        "horizon_days": 30,
        "risks": risks,
        "overall_risk": ("High" if any(r["risk_level"] == "High" for r in risks)
                         else "Medium" if risks else "Unknown"),
        "error": last_error,
    }
