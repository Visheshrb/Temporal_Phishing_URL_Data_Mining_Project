# Temporal Mining of Phishing URLs: Detecting Evolving Attack Patterns and Model Drift

This is a reproducible implementation package: ingestion, URL cleaning, feature engineering, EDA, clustering, classification, chronological evaluation, drift analysis, report template, and presentation outline.

**Important:** This ZIP does not contain third-party datasets or fabricated results. Download permitted data, place it in `data/raw/`, run the pipeline, inspect the outputs, and write conclusions from measured results before submission.

## Research question
Which URL signals remain predictive when a model trained on earlier phishing observations is evaluated on later observations, and can periodic retraining mitigate performance degradation?

## Data sources
- Piracema: https://github.com/cmrevoredo/piracema.raw
- Piracema paper: https://doi.org/10.1038/s41598-022-19442-8
- PhishTank: https://phishtank.org/developer_info.php
- URLhaus: https://urlhaus.abuse.ch/api/
- Tranco: https://tranco-list.eu/

Follow current terms and access instructions. Piracema compressed data may require requesting credentials from maintainers; do not bypass access controls. PhishTank and URLhaus schemas can change. Tranco is a lower-risk reference list, not guaranteed benign ground truth. URLhaus is broader malware URL data, not automatically phishing-only.

## Setup (Windows PowerShell)
```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```
Python 3.10 or 3.11 recommended.

## Data placement
Put CSV/TXT files in `data/raw/`, e.g. `phishtank.csv`, `urlhaus.csv`, `piracema.csv`, `tranco.csv`. The loader detects common URL/date/label column names. If your column names differ, edit `COLUMN_ALIASES` in `src/config.py`. Minimum useful schema: URL, date, label. For Tranco, a domain column is enough; the code marks it as a weak reference negative.

## Run
```bash
python -m src.run_pipeline
```
Optional:
```bash
python -m src.run_pipeline --min-year-count 20 --cluster-sample 10000
```

Outputs are written to `data/processed/` and `results/`. The pipeline skips experiments when data is insufficient instead of inventing results.

## Methodology
1. Integrate feeds, normalize URL strings, parse dates, deduplicate.
2. Extract URL length, hostname length, path depth, subdomains, digit/special-character ratios, query length, HTTPS/IP-host flags, TLD, and registered domain.
3. Plot temporal/source trends.
4. Run K-means on numeric structural features (exploratory clusters, not confirmed campaigns).
5. Compare logistic regression, random forest, and character 3–5-gram TF-IDF logistic regression.
6. Train on earlier years and test on later years; compare expanding and recent rolling windows.
7. Measure adjacent-year feature distribution change with KS statistics.

## Validity safeguards
- Chronological testing is primary; random splits can hide temporal drift.
- Report source composition by year. Source/feed changes can mimic temporal drift.
- Check duplicate URLs and domain/campaign overlap across periods.
- Do not treat Tranco as verified benign labels.
- Do not label all URLhaus records as phishing.
- Report precision, recall, F1, PR-AUC, and false-positive rate, not accuracy alone.
- Do not visit or execute malicious URLs. Analyze strings and source metadata only.
- Do not redistribute data if source terms restrict it.

## Structure
- `src/`: pipeline code
- `data/raw/`: downloaded source files (not included)
- `data/processed/`: generated datasets and source manifest
- `results/figures/`: generated plots
- `results/metrics/`: generated tables
- `report/`: final report template and checklist
- `presentation/`: slide outline

Final submission must include real measured findings, source documentation, readable code, dependencies, and a clean end-to-end run.
