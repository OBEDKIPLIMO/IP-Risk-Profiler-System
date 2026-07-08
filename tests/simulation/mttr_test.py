"""
tests/simulation/mttr_test.py
------------------------------
Day 35 — MTTR Measurement.

Queries all acknowledged alerts in the DB, computes the time-to-acknowledge
(created_at → acknowledged_at) for each, and calculates the mean MTTR.

Run this AFTER you've manually acknowledged at least 10 alerts through the
dashboard (naturally, as if you were the analyst) — this script does not
generate synthetic delays; it measures real recorded timestamps.
"""

import json
import statistics
from datetime import datetime
from db.database import get_session
from db.models import RiskAlert
from datetime import datetime, timezone


def compute_mttr(min_scenarios=10):
    session = get_session()
    try:
        acked = (session.query(RiskAlert)
                 .filter(RiskAlert.acknowledged == True)
                 .filter(RiskAlert.acknowledged_at.isnot(None))
                 .order_by(RiskAlert.acknowledged_at.desc())
                 .limit(min_scenarios)
                 .all())

        if not acked:
            print("[MTTR] No acknowledged alerts found. Acknowledge some alerts via the dashboard first.")
            return None

        results = []
        for a in acked:
            delta_seconds = (a.acknowledged_at - a.created_at).total_seconds()
            results.append({
                "alert_id":       a.alert_id,
                "asset_ip":       a.asset_ip,
                "severity_label": a.severity_label,
                "created_at":     a.created_at.isoformat(),
                "acknowledged_at": a.acknowledged_at.isoformat(),
                "response_time_seconds": round(delta_seconds, 2),
            })

        response_times = [r["response_time_seconds"] for r in results]
        mean_mttr   = round(statistics.mean(response_times), 2)
        median_mttr = round(statistics.median(response_times), 2)

        summary = {
            "scenario_count":     len(results),
            "mean_mttr_seconds":  mean_mttr,
            "median_mttr_seconds": median_mttr,
            "mean_mttr_minutes":  round(mean_mttr / 60, 2),
            "scenarios":          results,
            "generated_at":      datetime.now(timezone.utc).isoformat(),
        }

        # Save for Chapter 4
        with open("db/mttr_results.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"\n[MTTR] Scenarios measured: {len(results)}")
        print(f"[MTTR] Mean response time:   {mean_mttr}s  ({summary['mean_mttr_minutes']} min)")
        print(f"[MTTR] Median response time: {median_mttr}s")
        print(f"[MTTR] Results saved to db/mttr_results.json")

        return summary

    finally:
        session.close()


if __name__ == "__main__":
    compute_mttr(min_scenarios=10)