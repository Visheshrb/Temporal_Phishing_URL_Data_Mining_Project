# Temporal Mining of Phishing URLs: Detecting Evolving Attack Patterns and Model Drift

## Abstract
Summarize the problem, data sources/date coverage, methods, chronological evaluation, measured findings, and limitations. Complete after running experiments.

## 1. Introduction and Research Questions
Explain phishing evolution, operational importance, and the project's research questions.

## 2. Data Sources
For each source document access date, snapshot/version, row count, date range, fields, labels, terms, and limitations.

## 3. Data Preparation and EDA
Explain URL normalization, deduplication, timestamp handling, source overlap, label assumptions, class balance, and temporal plots.

## 4. Feature Engineering
Describe engineered lexical/structural features and character n-gram TF-IDF.

## 5. Methods
Describe clustering, classification baselines, chronological splits, rolling/expanding windows, drift statistics, and leakage controls.

## 6. Results
Report actual precision, recall, F1, PR-AUC, false-positive rate, confusion counts, plots, and failed experiments. Never invent results.

## 7. Discussion
Answer the research questions. Distinguish source/label shift from genuine attacker behavior changes.

## 8. Limitations and Ethics
Discuss feed bias, Tranco weak negatives, source coverage, missing metadata, leakage, and safe handling.

## 9. Conclusion and References
Summarize measured findings and cite datasets, APIs, papers, and software.
