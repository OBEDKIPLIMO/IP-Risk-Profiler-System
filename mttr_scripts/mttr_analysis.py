#!/usr/bin/env python3
"""
MTTR Measurement Analysis
Extracts acknowledged alerts from the project's SQLite database
and computes Mean Time To Respond (MTTR).
"""

from datetime import datetime
import sqlite3
import json
from pathlib import Path

# ------------------------------------------------------------------
# Project root
# ------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "dev.db"


def extract_mttr_data():
    """Query database for all acknowledged alerts."""

    if not DB_PATH.exists():
        raise FileNotFoundError(f"Database not found: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            alert_id,
            asset_ip,
            risk_score,
            severity_label,
            created_at,
            acknowledged_at
        FROM risk_alerts
        WHERE acknowledged = 1
          AND acknowledged_at IS NOT NULL
        ORDER BY created_at ASC
    """)

    alerts = cursor.fetchall()
    conn.close()

    return alerts


def calculate_mttr_seconds(created_str, acknowledged_str):
    """Calculate MTTR in seconds."""

    created = datetime.fromisoformat(created_str)
    acknowledged = datetime.fromisoformat(acknowledged_str)

    return (acknowledged - created).total_seconds()


def generate_report():

    print("\n" + "=" * 70)
    print("MTTR MEASUREMENT REPORT")
    print("=" * 70)
    print(f"\nDatabase: {DB_PATH}\n")

    alerts = extract_mttr_data()

    if not alerts:
        print("No acknowledged alerts found.")
        print("Please acknowledge one or more alerts from the dashboard first.")
        return

    print(f"Found {len(alerts)} acknowledged alerts.\n")

    mttr_data = []

    print("-" * 70)
    print(f"{'Alert':<8}{'Severity':<10}{'Score':<10}{'MTTR(s)':<12}")
    print("-" * 70)

    for alert in alerts:

        mttr = calculate_mttr_seconds(
            alert["created_at"],
            alert["acknowledged_at"]
        )

        mttr_data.append({
            "alert_id": alert["alert_id"],
            "asset_ip": alert["asset_ip"],
            "severity": alert["severity_label"],
            "risk_score": alert["risk_score"],
            "created_at": alert["created_at"],
            "acknowledged_at": alert["acknowledged_at"],
            "mttr_seconds": mttr
        })

        print(
            f"{alert['alert_id']:<8}"
            f"{alert['severity_label']:<10}"
            f"{alert['risk_score']:<10.2f}"
            f"{mttr:<12.2f}"
        )

    print("-" * 70)

    mttr_values = [x["mttr_seconds"] for x in mttr_data]

    mean_mttr = sum(mttr_values) / len(mttr_values)

    sorted_values = sorted(mttr_values)
    n = len(sorted_values)

    if n % 2 == 0:
        median_mttr = (
            sorted_values[n // 2 - 1] + sorted_values[n // 2]
        ) / 2
    else:
        median_mttr = sorted_values[n // 2]

    minimum = min(mttr_values)
    maximum = max(mttr_values)

    variance = sum((x - mean_mttr) ** 2 for x in mttr_values) / len(mttr_values)
    std_dev = variance ** 0.5

    manual_baseline = 196.0
    improvement = ((manual_baseline - mean_mttr) / manual_baseline) * 100

    print("\nSTATISTICAL SUMMARY")
    print("-" * 70)
    print(f"Sample Size           : {len(mttr_values)}")
    print(f"Mean MTTR             : {mean_mttr:.2f} seconds")
    print(f"Median MTTR           : {median_mttr:.2f} seconds")
    print(f"Standard Deviation    : {std_dev:.2f} seconds")
    print(f"Minimum               : {minimum:.2f} seconds")
    print(f"Maximum               : {maximum:.2f} seconds")
    print(f"Manual Baseline       : {manual_baseline:.2f} seconds")
    print(f"Improvement           : {improvement:.2f}%")

    print("\nMTTR BY SEVERITY")
    print("-" * 70)

    for severity in ("High", "Medium", "Low"):

        values = [
            x["mttr_seconds"]
            for x in mttr_data
            if x["severity"] == severity
        ]

        if values:
            print(
                f"{severity:<10}"
                f"Count={len(values):<3}"
                f"Average={sum(values)/len(values):.2f}s"
            )
        else:
            print(f"{severity:<10}No acknowledged alerts")

    report = {
        "generated_at": datetime.now().isoformat(),
        "database": str(DB_PATH),
        "sample_size": len(mttr_values),
        "mean_mttr": mean_mttr,
        "median_mttr": median_mttr,
        "std_dev": std_dev,
        "minimum": minimum,
        "maximum": maximum,
        "manual_baseline": manual_baseline,
        "improvement_percent": improvement,
        "alerts": mttr_data
    }

    output_file = PROJECT_ROOT / "mttr_results.json"

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\nResults saved to {output_file}")
    print("=" * 70)

    return report


if __name__ == "__main__":
    generate_report()