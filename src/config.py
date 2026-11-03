from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
FIGURES = ROOT / "results" / "figures"
METRICS = ROOT / "results" / "metrics"
for p in [RAW, PROCESSED, FIGURES, METRICS]:
    p.mkdir(parents=True, exist_ok=True)
COLUMN_ALIASES = {
    "url": ["url", "phish_url", "urlhaus_reference", "uri", "link", "domain"],
    "date": ["date", "submission_time", "verified_at", "verification_time", "date_added", "first_seen", "report_time", "timestamp", "time"],
    "label": ["label", "class", "is_phishing", "verified", "threat"]
}
SEED = 42
