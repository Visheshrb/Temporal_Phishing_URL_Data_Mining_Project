# PhishShift: Claude Code Instructions

This file is loaded automatically in every session. Read it fully before doing anything.
The step-by-step build plan is `docs/2026-11-05-phishshift-implementation-plan.md`. Work only from that plan.

## What this project is

CSCI 6443 (Data Mining, GWU) final project. Thesis: a phishing URL detector goes stale before anyone
notices; using only **unlabeled** traffic, data mining can tell us **when** it is going stale, **what**
changed, and **which few URLs to label** to fix it.

- RQ1 Decay: how fast does a classifier trained once lose Recall at 1% FPR, week by week?
- RQ2 Detect: do label-free signals (S1 JS divergence, S2 orphan rate, S3 novelty) predict recall loss
  1 to 4 weeks ahead, better than baselines (B1 uncertainty share, B2 score shift, B3 PSI)? Validated
  with controlled drift injection.
- RQ3 Explain: emerging-pattern mining names what attackers changed.
- RQ4 Act: a small radar-chosen labeling budget recovers recall better than random or uncertainty labels.

Data: OpenPhish public feed git history (Oct 12, 2024 to Nov 2026, weekly windows), Phishing.Database
for replication, time-matched benign URLs from the Common Crawl index on same-date Tranco domains,
HuggingFace/UCI benign sets for sensitivity only. Storage: DuckDB star schema + parquet.

Deadlines: results freeze Wed Nov 25, presentation Thu Dec 3, submission Fri Dec 11, 2026.

## How to work (mandatory)

1. Open the plan and find the first phase in the **Progress tracker** that is not checked.
2. Implement only that phase. Do not start the next phase.
3. Run `make test` (and the phase's acceptance checks). Fix failures before moving on.
4. Tick the finished tasks in the Progress tracker and add a dated one-line note under **Build log**.
5. At the phase's **STOP checkpoint**, stop and report: what you built, files changed, test results,
   the numbers the checkpoint asks for, and anything that deviated from the plan. Wait for a human.
6. If the plan is ambiguous or a spec looks wrong, ask. Do not invent a new design silently.

## Hard rules

### Safety
- **Never send any request to a phishing URL** or any host taken from a phishing feed. No `requests.get`,
  no DNS lookups, no screenshots, no WHOIS. We only read git history, archive files, and index metadata.
- Any URL shown in a notebook, figure, log, or the demo must pass through `url_parser.defang()`.
- `data/` is git-ignored. Never commit raw URL lists.

### Files
- `data/raw/` is immutable. Never modify or delete anything in it. Every downloaded file is logged in
  `data/raw/data_log.csv` (source_url, utc, sha256, rows) via `src/datalog.py`.
- Ask before deleting or overwriting any existing file outside `data/interim/`, `data/processed/`, and
  `reports/`.

### Leakage (the project is graded on rigor; these are non-negotiable)
- Chronological splits only for headline results. Never `train_test_split` with shuffle on test data.
- Phishing URLs are grouped into MinHash campaigns and every member is locked to the campaign's earliest
  week. A campaign must never appear in both a training window and an evaluation week.
- Evaluation always drops any URL (phishing or benign) that appears in that model's training data.
- **Never use as features:** source, `tranco_rank_bucket`, crawl id, or anything describing where a URL
  came from rather than what it looks like.
- Every fitted object (scalers, vectorizers, IDF, SVD, bins, TLD frequencies, rules, centroids, PSI bins)
  is fit on the training/reference window only, then applied forward. Use fit/transform APIs.
- Thresholds: FPR thresholds come from validation data; the radar threshold tau comes from config and
  the reference-window null distribution. Never tune on test labels.
- Radar signals S1 to S3 and baselines B1 to B3 must not read the `label` column. Enforce this in code
  (drop `label` before calling `radar.signals`).

### Reproducibility
- Every tunable number lives in `config.yaml`. No magic numbers in `src/`, `scripts/`, or notebooks.
- Every function that uses randomness takes an explicit `seed`. Global default seed is 42.
- Pipeline logic lives in `src/` (importable, tested). `scripts/` run pipeline steps and write outputs.
  `notebooks/primary/` only read outputs and plot. Never copy pipeline code into notebooks.

## Repository layout

```
PhishShift/
  CLAUDE.md                 this file
  config.yaml               every parameter
  Makefile                  make setup|data|timeline|benign|warehouse|rq1|patterns|radar|inject|explain|policy|freeze|demo|test|notebooks
  requirements.txt          pinned after first install (pip freeze)
  docs/                     implementation plan, design notes
  src/                      config, datalog, url_parser, timeline, campaigns, benign, warehouse,
                            features, models, metrics, patterns, families, radar, inject, policy
  scripts/                  run_*.py entry points called by make
  notebooks/primary/        01 to 10, thin, plot from results
  notebooks/secondary/      exploratory and failed work, each with a markdown note on what failed
  tests/                    pytest
  app/streamlit_app.py      demo, reads reports/demo/*.parquet only
  data/raw | interim | processed     (git-ignored)
  reports/figures | demo | paper
```

## Commands

- `make setup`: create venv, install requirements.
- `make test`: `pytest -q`.
- `make <stage>`: run one pipeline stage (see plan). Each stage reads only earlier outputs.
- `make notebooks`: execute primary notebooks in order with `jupyter nbconvert --execute --inplace`.

## Code conventions

- Python 3.11, type hints on public functions, short docstrings stating inputs, outputs, and side effects.
- pandas DataFrames, NumPy arrays, SciPy CSR matrices at module boundaries. Function signatures in the
  plan are contracts; other modules depend on them. If you must change one, update the plan too.
- `logging` (not print) with module loggers; log counts at every filtering step (rows in, rows dropped, why).
- Network code: cache every response on disk, resumable, retry with exponential backoff on 429/5xx,
  polite rate from config. Never hammer an API.
- Format with `ruff format`; keep functions small and pure where possible.
- Tests use tiny synthetic data and run in seconds. No network in tests.

## Known facts (verified Nov 5, 2026)

- `github.com/openphish/public_feed`: file `feed.txt`, 12,123 commits from 2024-10-12 to 2026-11-05,
  roughly every 2 hours. Snapshots held 500 URLs early on and 300 in the latest commit (the cap changed;
  find the date). About 2,000 unique URLs appear per week. A full clone is small; use it.
- Everything else (Phishing.Database history depth, Common Crawl index rate limits, Tranco date API,
  HuggingFace/UCI files) is unverified until Phase 1 checks it.
