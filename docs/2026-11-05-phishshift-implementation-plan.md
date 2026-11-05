# PhishShift Implementation Plan (for Claude Code)

Companion to `CLAUDE.md` (rules, always loaded). This file is the build plan: phases, file contracts,
acceptance checks, and STOP checkpoints. Implement one phase at a time and stop at each checkpoint.

**Kickoff prompt for a new session:**
> Read CLAUDE.md and docs/2026-11-05-phishshift-implementation-plan.md. Find the first unchecked phase
> in the Progress tracker, implement it, run the tests and acceptance checks, update the tracker and
> build log, then stop at the checkpoint and report.

---

## Progress tracker

Tick items as they are completed. Dates are targets from the project guide.

- [ ] **Phase 0** Scaffold (Nov 5)
- [ ] **Phase 1** Data acquisition and verification (Nov 5 to 6)
- [ ] **Phase 2** Phishing timeline, URL parsing, campaigns (Nov 6 to 10)
- [ ] **Phase 3** Benign stream, warehouse, shortcut audit (Nov 6 to 11)
- [ ] **Phase 4** Features, models, metrics, EDA, RQ1 decay (Nov 9 to 13, project gate Fri Nov 13)
- [ ] **Phase 5** Rules and attack families (Nov 9 to 18)
- [ ] **Phase 6** Radar signals and lead-time test, RQ2 (Nov 14 to 20)
- [ ] **Phase 7** Drift injection and replication, RQ2 (Nov 17 to 23)
- [ ] **Phase 8** Emerging patterns, RQ3 (Nov 18 to 24)
- [ ] **Phase 9** Labeling budget, retraining policies, sensitivity, RQ4 (Nov 20 to 25)
- [ ] **Phase 10** Results freeze and Streamlit demo (Nov 24 to Dec 1)
- [ ] **Phase 11** Reproducibility pass and cleanup (Dec 4 to 8)

## Build log

Add one dated line per work session: `YYYY-MM-DD Phase N: what was done; open issues.`

---

## Shared specifications

### config.yaml (create exactly this in Phase 0)

```yaml
seed: 42
paths:
  raw: data/raw
  interim: data/interim
  processed: data/processed
  results: data/processed/results
  duckdb: data/processed/phishshift.duckdb
  figures: reports/figures
  demo: reports/demo
sources:
  openphish_repo: https://github.com/openphish/public_feed.git
  openphish_file: feed.txt
  phishdb_repo: https://github.com/Phishing-Database/Phishing.Database.git
  cc_collinfo: https://index.commoncrawl.org/collinfo.json
  tranco_date_api: https://tranco-list.eu/api/lists/date/{yyyymmdd}
  hf_benign_csv: https://huggingface.co/datasets/Mitake/PhishingURLsANDBenignURLs/resolve/main/PhishBenignDataset.csv
  uci_zip: https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip
study:
  start: 2024-10-14          # first Monday after the feed starts
  end: 2026-11-01
  label_delay_weeks: 4
sampling:
  phish_per_week: 1500
  benign_ratio: 5
  benign_domains_per_crawl: 2000
  urls_per_domain: 5
  rank_buckets: [1000, 10000, 100000, 1000000]
  shared_hosts: [github.io, sites.google.com, weebly.com, blogspot.com, web.app, firebaseapp.com,
                 docs.google.com, dropbox.com, wixsite.com, netlify.app, vercel.app, pages.dev]
network:
  cc_requests_per_sec: 1.0
  max_retries: 5
  backoff_base_sec: 2.0
  timeout_sec: 60
campaigns: {shingle: 4, jaccard: 0.85, num_perm: 128}
features:
  char_ngrams: [3, 5]
  char_min_df: 5
  char_max_features: 300000
  token_min_df: 20
  hash_features: 1048576
  svd_components: 100        # HGB only, refit on each training window
  url_stopwords: [http, https, www, html, htm, php, index, com]
  sensitive_keywords: [login, verify, update, secure, account, banking, confirm]
model:
  anchor_train_weeks: 8
  val_fraction: 0.2
  fpr: 0.01
  logreg: {C: 1.0, max_iter: 2000, class_weight: balanced}
  hgb: {max_iter: 300, learning_rate: 0.1}
  prevalence: ["1:10", "1:100", "1:1000"]
  bootstrap_n: 500
patterns: {block_weeks: 4, min_support: 0.005, max_len: 4, strong_conf: 0.80, strong_g2: 50}
families: {k_grid: [5, 8, 10, 12, 15], link_threshold: 0.80, ari_bootstrap: 50, silhouette_sample: 5000}
radar:
  ngram_n: 4
  ref_centroids_k: 20
  uncertainty_band: [0.3, 0.7]
  psi_bins: 10
  psi_top_features: 10
  tau: 2.0
  tau_grid: [1.5, 2.0, 2.5, 3.0]
  lead_max_lag: 4
  perm_block: 4
  n_perm: 1000
explain: {window_weeks: 4, min_support: 0.005, min_growth: 5, top_k: 10}
inject:
  global_k: 15
  n_families: 10
  min_family_size: 500
  rates: [0.05, 0.10, 0.20, 0.40]
  duration_weeks: 8
  horizon_weeks: 4
policy:
  budgets: [50, 100, 200, 500]
  candidate_weeks: 2
  eval_weeks: 4
  seeds: [0, 1, 2, 3, 4]
  strategies: [random, uncertainty, novelty, pattern, mixed]
  radar_policy_strategy: novelty
  radar_policy_budget: 200
sensitivity:
  label_delay_weeks: [2, 8]
```

### Star schema DDL (DuckDB, created in Phase 3)

```sql
CREATE TABLE dim_source (source_key SMALLINT PRIMARY KEY, source_name VARCHAR,
  class_kind VARCHAR, collection_method VARCHAR);
CREATE TABLE dim_week (week_key INTEGER PRIMARY KEY,      -- ISO yyyyww, Monday start
  week_start DATE, study_week INTEGER, quarter VARCHAR, cc_crawl_id VARCHAR, period_role VARCHAR);
CREATE TABLE dim_domain (domain_key BIGINT PRIMARY KEY, registered_domain VARCHAR, tld VARCHAR,
  domain_identity VARCHAR,   -- registered_domain, or full host when is_shared_host
  tranco_rank_bucket VARCHAR, is_shared_host BOOLEAN);
CREATE TABLE dim_url (url_key BIGINT PRIMARY KEY, url_canonical VARCHAR UNIQUE, scheme VARCHAR,
  subdomain VARCHAR, path VARCHAR, query VARCHAR, fragment VARCHAR, port INTEGER, url_length INTEGER);
CREATE TABLE dim_campaign (campaign_key BIGINT PRIMARY KEY, n_urls INTEGER,
  earliest_week_key INTEGER, family_id INTEGER);
CREATE TABLE fact_url_observation (obs_id BIGINT PRIMARY KEY,
  url_key BIGINT REFERENCES dim_url, domain_key BIGINT REFERENCES dim_domain,
  week_key INTEGER REFERENCES dim_week, source_key SMALLINT REFERENCES dim_source,
  campaign_key BIGINT,       -- null for benign
  label TINYINT, first_seen TIMESTAMP, last_seen TIMESTAMP, n_snapshots INTEGER,
  in_weekly_sample BOOLEAN, crawl_id VARCHAR);
```

`study_week` runs 1 to about 107. `period_role` is `train` for study weeks 1 to 8, else `test`.

### Result tables (parquet in `data/processed/results/`, registered as DuckDB views)

| Table | Columns |
|---|---|
| weekly_metrics | model_id, policy, run_id, week_key, study_week, recall_at_1fpr, pr_auc, roc_auc, tpr_fixed, fpr_fixed, ci_lo, ci_hi, n_phish, n_benign |
| radar_signals | run_id, ref_id, week_key, study_week, s1_js, s2_orphan, s3_novelty, b1_uncert, b2_shift, b3_psi, z_s1, z_s2, z_s3, z_b1, z_b2, z_b3, composite, alarm |
| rules | block_id, antecedent (list[str]), label, support, confidence, pmi, g2, precision, recall, f1, is_strong |
| rule_half_life | rule_id, antecedent, label, f1_start, half_life_weeks, category |
| families / family_links | block_id, family_id, size, top_tokens, silhouette / block_t, fam_t, block_t1, fam_t1, cosine |
| lead_time | signal, lag, spearman_rho, p_perm |
| emerging_patterns | run_id, alarm_week_key, itemset (list[str]), supp_ref, supp_now, growth, is_new, g2, rank |
| injection_results | family_id, rate, kind (phish or benign_control), signal, onset_week, detected, delay_weeks, false_alarm_rate |
| budget_results | alarm_week_key, strategy, budget, seed, recall_next4, recall_no_retrain, recall_oracle, recall_recovered |
| policy_summary | policy, mean_recall_at_1fpr, n_retrains, n_labels |

Per-week model scores are cached at `data/processed/scores/{model_id}/{week_key}.parquet`
(url_key, label, score) so later phases never re-score.

---

## Phase 0: Scaffold

**Goal:** an empty but runnable project skeleton.

Create:
- Folder tree from CLAUDE.md, with `.gitkeep` where needed, `.gitignore` (data/, .venv/, __pycache__/,
  .ipynb_checkpoints/, reports/demo/*.parquet).
- `config.yaml` exactly as above.
- `requirements.txt` (unpinned first): duckdb, pandas, pyarrow, numpy, scipy, scikit-learn, mlxtend,
  datasketch, tldextract, requests, pyyaml, tqdm, openpyxl, matplotlib, seaborn, streamlit, jupyter,
  nbconvert, pytest, ruff. After a successful install, pin with `pip freeze > requirements.txt`.
- `Makefile` with targets: setup, test, data, timeline, benign, warehouse, rq1, patterns, radar, inject,
  explain, policy, freeze, demo, notebooks, all. Targets for later phases may echo "not implemented".
- `src/__init__.py`, `src/config.py`, `src/datalog.py`, `src/log.py`.
- `tests/conftest.py` with a fixture that loads config.yaml and a `tmp_path`-based fake data root.

Contracts:
```python
# src/config.py
def load_config(path: str = "config.yaml") -> dict: ...      # also resolves paths to pathlib.Path
# src/datalog.py
def log_file(path: Path, source_url: str, rows: int | None, log_csv: Path) -> str: ...
    # appends (file_name, source_url, utc_iso, sha256, bytes, rows); returns sha256; idempotent per sha
# src/log.py
def get_logger(name: str) -> logging.Logger: ...              # consistent format, INFO default
```

Tests: `test_config.py` (loads, required keys present), `test_datalog.py` (hash correct, no duplicate rows).

Acceptance: `make setup && make test` passes.

**STOP checkpoint 0:** show the tree, the Makefile targets, and the test output.

---

## Phase 1: Data acquisition and verification

**Goal:** all sources downloaded or cloned, logged, and their real properties measured.

Create `scripts/run_data.py` (make data) doing:
1. `git clone` (full) OpenPhish into `data/raw/openphish_public_feed`. Record commit count, first and last
   commit dates.
2. Phishing.Database: first a blobless clone (`--filter=blob:none --no-checkout`). Measure commit count,
   date range of the links files, and estimated history size (`git count-objects -vH` after fetching a
   sample of blobs). List the files that change over time; prefer a file listing newly added links if one
   exists, since its history is cheaper to walk. Do not fetch the full history yet; report first.
3. Tranco: call the date API for 2024-10-14 and 2026-11-01; download one list; log it.
4. Common Crawl: fetch `collinfo.json`; list crawl ids whose dates fall in the study window. Run 50 index
   queries for random Tranco domains against one crawl, measuring latency, error codes, and URLs returned.
5. HuggingFace CSV and UCI zip: download, log, print row counts and column names.

All downloads go through `datalog.log_file`. No request ever goes to a URL taken from a phishing feed.

Write `data/raw/verification_report.md` with a table: source, status, coverage, size, notes.

Acceptance: report exists; data_log.csv has one row per file.

**STOP checkpoint 1:** paste the verification report. Humans decide: Phishing.Database history approach
(full walk, sampled daily, or fallback to replicating on a held-out half of OpenPhish weeks), and the safe
Common Crawl request rate (update `network.cc_requests_per_sec`).

---

## Phase 2: Phishing timeline, URL parsing, campaigns

**Goal:** a clean weekly phishing table with first-seen dates, components, and campaign locks.

Create `src/url_parser.py`, `src/timeline.py`, `src/campaigns.py`, `scripts/run_timeline.py` (make timeline).

```python
# src/url_parser.py
def canonicalize(url: str) -> str | None
    # strip; reject non-UTF-8/unparsable/no host -> None; lowercase scheme+host; drop "www.";
    # drop :80 for http and :443 for https; percent-decode unreserved chars only; keep path/query/fragment
def componentize(url: str) -> dict
    # keys: scheme, subdomain, registered_domain, tld, host, port, path, query, fragment, url_length
    # use tldextract with the bundled suffix snapshot (no network): TLDExtract(suffix_list_urls=())
def domain_identity(components: dict, shared_hosts: list[str]) -> tuple[str, bool]
    # (identity, is_shared_host): full host if registered_domain or host suffix is in shared_hosts
def defang(url: str) -> str     # "hxxp(s)://", "." -> "[.]" in host; display only

# src/timeline.py
def build_timeline(repo: Path, path: str = "feed.txt") -> pd.DataFrame
    # walk `git log --reverse --format=%H %cI -- <path>`; for each commit read the file
    # (use one `git cat-file --batch` process for speed); columns: url_raw, first_seen, last_seen, n_snapshots
def snapshot_sizes(repo: Path, path: str = "feed.txt") -> pd.DataFrame     # commit_time, n_urls
def detect_cap_change(sizes: pd.DataFrame) -> pd.Timestamp | None          # first time the rolling max drops
def assign_week(ts: pd.Series) -> pd.Series                                 # ISO yyyyww (UTC, Monday start)
def weekly_subsample(df: pd.DataFrame, n_per_week: int, seed: int) -> pd.DataFrame
    # per week_key sample n without replacement (seed + week_key); weeks with fewer keep all and log it;
    # sets in_weekly_sample

# src/campaigns.py
def campaign_groups(urls: pd.Series, shingle: int, threshold: float, num_perm: int, seed: int) -> pd.Series
    # datasketch MinHash on char shingles of the canonical URL + MinHashLSH; connected components -> campaign_key
def lock_to_earliest(df: pd.DataFrame) -> pd.DataFrame
    # every member gets the group's earliest first_seen week_key
```

Pipeline order in `run_timeline.py`: build_timeline, canonicalize (log drops), exact dedupe on canonical
(keep earliest first_seen, max last_seen, sum n_snapshots), componentize, campaign_groups, lock_to_earliest,
assign_week, filter to study window, weekly_subsample. Write `data/interim/openphish_timeline.parquet`,
`data/interim/snapshot_sizes.csv`. Repeat for Phishing.Database with the approach chosen at checkpoint 1
(write `phishdb_timeline.parquet`).

Tests:
- `test_url_parser.py`: default ports, "www.", percent-decoding, punycode host, malformed -> None, defang.
- `test_timeline.py`: build a tiny git repo in `tmp_path` with 3 commits of feed.txt and assert
  first_seen, last_seen, n_snapshots exactly; weekly_subsample is deterministic for a seed.
- `test_campaigns.py`: URLs differing only by a random session token share a campaign; unrelated URLs do not;
  lock_to_earliest moves all members to the earliest week.

Acceptance: weekly counts for about 107 weeks; cap-change date found; no campaign_key spans two week_keys.

**STOP checkpoint 2:** report rows in/out at each step, the cap-change date, weekly count summary
(min/median/max), campaign size distribution, and a snapshot-size plot saved to `reports/figures/`.

---

## Phase 3: Benign stream, warehouse, shortcut audit

**Goal:** time-matched benign URLs, the DuckDB star schema, weekly mixed streams, and a passing audit.

Create `src/benign.py`, `src/warehouse.py`, `scripts/run_benign.py` (make benign),
`scripts/run_warehouse.py` (make warehouse), `notebooks/primary/02_benign_stream_and_shortcut_audit.ipynb`.

```python
# src/benign.py
def crawls_in_window(collinfo: list[dict], start: date, end: date) -> pd.DataFrame   # crawl_id, crawl_date
def tranco_for_date(d: date, cache_dir: Path) -> pd.DataFrame                       # rank, domain (cached)
def sample_domains(tranco: pd.DataFrame, n: int, buckets: list[int], seed: int) -> pd.DataFrame
    # equal share per rank bucket; columns domain, rank, rank_bucket
def cc_urls(crawl_id: str, domain: str, limit: int, cache_dir: Path, rate: float) -> list[str]
    # GET https://index.commoncrawl.org/{crawl_id}-index?url={domain}/*&output=json&filter=status:200
    #     &filter=mime:text/html&fl=url,timestamp&limit=<limit*4>
    # cache raw response as JSONL per (crawl, domain); prefer URLs with a non-root path or a query;
    # return up to `limit`; retries with backoff; fully resumable (skip cached pairs)
def build_benign(crawls: pd.DataFrame, cfg: dict) -> pd.DataFrame
    # url_raw, crawl_id, crawl_date, domain, rank_bucket
```

Warehouse (`src/warehouse.py`):
```python
def create_schema(con) -> None                                  # DDL above
def load_star_schema(con, phish: pd.DataFrame, benign: pd.DataFrame, cfg: dict) -> None
    # canonicalize + componentize benign; assign each benign URL to its earliest crawl only;
    # drop benign rows whose domain_identity ever appears as a non-shared phishing identity;
    # fill dims; dim_week.cc_crawl_id = crawl with the nearest date to week_start
def mixed_stream(con, week_key: int, ratio: int, seed: int,
                 phish_source: str = "OpenPhish", benign_source: str = "CommonCrawl") -> pd.DataFrame
    # phishing: in_weekly_sample rows of that week; benign: sample ratio * n_phish from the pool of the
    # week's cc_crawl_id without replacement within the week (seed + week_key); if the pool is short,
    # take all and log a warning. Benign URLs may repeat across weeks of the same crawl; evaluation
    # removes training URLs (see Phase 4), so this does not leak.
    # columns: url_key, url_canonical, components..., domain_identity, is_shared_host, label,
    #          campaign_key, source_name, week_key
def stream_without_labels(df: pd.DataFrame) -> pd.DataFrame    # drops label; used by the radar
```

Notebook 02: shortcut audit. Train LogisticRegression on only url_length, path_depth, has_path, has_query
using study weeks 1 to 8; report ROC-AUC on weeks 9 to 16. If > 0.80, implement histogram matching on
path_depth in benign sampling (`sampling.match_path_depth: true`) and rerun.

Tests: `test_warehouse.py` (schema creates; FK integrity on a toy load; mixed_stream ratio and determinism;
domain-overlap removal), `test_benign.py` (cc_urls parses a mocked JSONL response and resumes from cache;
no network: monkeypatch requests).

Acceptance: every study week has a stream; benign/phishing ratio 5:1 (log exceptions); audit ROC-AUC in
0.50 to 0.70; a join query of fact to dim_week and dim_domain runs in under 1 second.

**STOP checkpoint 3:** report benign counts per crawl and per rank bucket, crawls used, domains removed by
the overlap rule, audit ROC-AUC (and whether matching was needed).

---

## Phase 4: Features, models, metrics, EDA, RQ1 decay

**Goal:** the decay curve with confidence bands. This is the project gate (Fri Nov 13).

Create `src/features.py`, `src/models.py`, `src/metrics.py`, `scripts/run_eda.py`, `scripts/run_rq1.py`
(make rq1), notebooks 03 and 04.

```python
# src/features.py
ENGINEERED_COLUMNS: list[str]   # fixed order, ~30 names
def shannon_entropy(s: str) -> float                              # bits per character
def fit_bins(ref: pd.DataFrame) -> dict                           # tertiles: entropy, url_length; tld_freq
def engineered(df: pd.DataFrame, bins: dict) -> pd.DataFrame
    # url/host/path/query lengths, n_subdomains, path_depth, n_query_params, digit_ratio, letter_ratio,
    # counts of - _ @ = % ~ ., longest_digit_run, n_tokens, mean_token_len, entropy_url, entropy_host,
    # entropy_path, has_ip_host, has_punycode, has_port, is_https, n_sensitive_keywords, tld_freq,
    # is_shared_host. MUST NOT use source, rank bucket, crawl id, or label.
class UrlVectorizer:     # token BoW (TF-IDF, min_df=token_min_df, stopwords) + char 3-5 TF-IDF (vocabulary)
    def fit(self, urls: pd.Series) -> "UrlVectorizer"
    def transform(self, urls: pd.Series) -> csr_matrix
class HashedNgrams:      # char 3-5 HashingVectorizer(alternate_sign=False, norm=None) + TfidfTransformer
    def fit(self, ref_urls: pd.Series) -> "HashedNgrams"           # IDF from reference only
    def transform(self, urls: pd.Series) -> csr_matrix             # L2-normalized rows
def tokenize(url: str, stopwords: list[str]) -> list[str]
def transactions(df: pd.DataFrame, bins: dict, vocab: set[str]) -> list[frozenset[str]]
    # items: TLD=, HOST_TOK=, PATH_TOK= (only tokens in vocab), KW=, ENTROPY=LOW|MID|HIGH,
    # LEN=SHORT|MID|LONG, SUBDOMAINS=0|1|2|3+, SHARED_HOST, HAS_QUERY, HAS_IP

# src/models.py
@dataclass
class TrainedModel: kind: str; model: Any; pipe: dict; threshold: float; r_val: float; train_url_keys: set
def split_validation(train_df, val_fraction, seed) -> tuple[pd.DataFrame, pd.DataFrame]
    # phishing split by campaign_key, benign by url_key
def train(train_df: pd.DataFrame, kind: str, cfg: dict, seed: int) -> TrainedModel
    # logreg: hstack(scaled engineered as sparse, UrlVectorizer) -> LogisticRegression(**cfg logreg)
    # hgb: engineered + TruncatedSVD(svd_components) of char TF-IDF, fit on the training window
    # threshold = calibrate_threshold(val benign scores, fpr); r_val = recall_at_fpr on validation
def score(m: TrainedModel, df: pd.DataFrame) -> np.ndarray
def exclude_seen(df: pd.DataFrame, m: TrainedModel) -> pd.DataFrame     # drop url_keys seen in training

# src/metrics.py
def recall_at_fpr(y, s, fpr=0.01) -> float       # threshold = (1 - fpr) quantile of benign scores, strict >
def calibrate_threshold(benign_scores, fpr=0.01) -> float
def prevalence_precision(tpr, fpr, pi) -> float  # pi = phishing share, "1:100" -> 1/101
def block_bootstrap(fn, y, s, groups, n, seed) -> tuple[float, float]   # 2.5 / 97.5 percentiles
def psi(ref, now, bins=10, eps=1e-4) -> float    # quantile bins from ref
```

`run_rq1.py`: train LR and HGB on study weeks 1 to 8; for every later week: mixed_stream, exclude_seen,
score (cache scores), metrics with block-bootstrap CIs (phishing by campaign_key, benign by url_key),
fixed-threshold TPR/FPR, prevalence-adjusted precision. Write `weekly_metrics` (policy = "static").

`run_eda.py`: weekly medians and IQRs of engineered features by label, top-10 TLD shares per week, and
the data dictionary (column, primitive type, logical type) to `results/`.

Notebooks: 03 (6 trend plots + data dictionary table), 04 (decay curve: Recall at 1% FPR vs weeks since
training, CI band, both models; PR-AUC panel).

Tests: `test_metrics.py` (recall_at_fpr toy case; prevalence formula; PSI = 0 for identical; bootstrap
deterministic), `test_features.py` (column count and order; no forbidden columns; HashedNgrams gives
nonzero weight to an n-gram unseen in the reference), `test_no_leakage.py` (for the anchor split: no
campaign_key or url_key in both train and any evaluated week after exclude_seen).

Acceptance: decay curve exists for both models with CIs.

**STOP checkpoint 4 (project gate):** report R_val, Recall at 1% FPR at weeks +1, +4, +12, +26, +52, last
week, with CIs; the decay curve path; anything surprising (for example, flat decay).

---

## Phase 5: Rules and attack families

**Goal:** strong rules for the orphan-rate signal, rule half-life, and a family catalog.

Create `src/patterns.py`, `src/families.py`, `scripts/run_patterns.py` (make patterns), notebook 05.

```python
# src/patterns.py
def one_hot(tx: list[frozenset[str]]) -> pd.DataFrame                    # sparse bool via TransactionEncoder
def mine_itemsets(tx, min_support: float, max_len: int) -> pd.DataFrame  # mlxtend fpgrowth, use_colnames
def focused_rules(tx, labels: np.ndarray, min_support: float, max_len: int) -> pd.DataFrame
    # append LABEL=1 / LABEL=0 items, mine, keep rules A => LABEL=x with A free of LABEL items;
    # compute from counts: support, confidence, pmi=log2(P(A,B)/(P(A)P(B))),
    # g2 = 2*sum O*ln(O/E) over the 2x2 table (skip zero cells), precision/recall/f1 of A as a classifier
def strong_rules(rules, min_conf: float, min_g2: float) -> pd.DataFrame
def matches_any(tx, antecedents: list[frozenset[str]]) -> np.ndarray     # bool per transaction
def rule_half_life(start_rules: pd.DataFrame, blocks: dict[int, tuple[list, np.ndarray]]) -> pd.DataFrame
    # F1 of each strong phishing rule per later block; half_life = first week offset where F1 < 0.5*F1_start;
    # category persistent (never halves) / decaying / emerging (strong later, not at start)
def emerging_patterns(tx_ref, tx_now, min_support, min_growth, top_k) -> pd.DataFrame   # used in Phase 8
    # growth = supp_now / max(supp_ref, 1/N_ref); is_new = supp_ref == 0; rank by g2 of window x presence

# src/families.py
@dataclass
class FamilyModel: k: int; centroids: np.ndarray; labels: np.ndarray; silhouette: pd.DataFrame
def fit_families(X: csr_matrix, k_grid: list[int], seed: int, sample: int) -> FamilyModel
    # MiniBatchKMeans on L2-normalized rows; k chosen by mean silhouette (cosine) on a sample,
    # but store per-cluster silhouette for the plot; centroids L2-normalized
def link_blocks(C_t, C_t1, threshold) -> pd.DataFrame     # S = C_t @ C_t1.T; pairs with S >= threshold
def bootstrap_ari(X, k, n, seed) -> float
def top_tokens(X, labels, vectorizer, n=10) -> dict[int, list[str]]
```

`run_patterns.py`: transactions for all weeks with bins and token vocab fit on weeks 1 to 8; focused rules
on weeks 1 to 8 (labeled); strong rules saved (needed by Phase 6); half-life over 4-week blocks; families
per 4-week block (phishing only, HashedNgrams fit on weeks 1 to 8); links; ARI.

Tests: `test_patterns.py` (support/confidence/PMI/G2 on a hand-computed 2x2 example; matches_any).

**STOP checkpoint 5:** number of strong rules per label, top 15 persistent / decaying / emerging rules,
chosen k per block, mean silhouette and ARI, number of family births and deaths.

---

## Phase 6: Radar signals and lead-time test (RQ2)

**Goal:** weekly S1 to S3 and B1 to B3, composite alarms, and the lead-time analysis.

Create `src/radar.py`, `scripts/run_radar.py` (make radar), notebook 06.

```python
# src/radar.py
class Reference:
    def fit(self, weeks: list[pd.DataFrame], model: TrainedModel, strong: pd.DataFrame, cfg: dict) -> "Reference"
        # weeks = unlabeled streams of the reference window (labels dropped by caller)
        # stores: char-4gram distribution (S1); bins, token vocab, strong antecedents (S2);
        # HashedNgrams + MiniBatchKMeans(k=ref_centroids_k) normalized centroids (S3);
        # reference model scores (B1, B2); quantile bins of the top-|coef| engineered features (B3);
        # null mean/sd per signal via leave-one-week-out (each week vs a Reference fit on the other weeks)
def signals(ref: Reference, stream: pd.DataFrame) -> dict[str, float]
    # assert "label" not in stream.columns
    # s1_js: summed HashingVectorizer(analyzer="char", ngram_range=(4,4), n_features=hash_features,
    #        alternate_sign=False, norm=None) counts -> distributions; scipy jensenshannon(base=2) ** 2
    # s2_orphan: 1 - mean(matches_any(tx, strong antecedents))
    # s3_novelty: mean(1 - max(X @ C.T)) with HashedNgrams rows
    # b1_uncert: share of scores in uncertainty_band; b2_shift: |mean score - ref mean|; b3_psi: mean PSI
def zscores(ref: Reference, sig: dict) -> dict[str, float]       # sd floored at 1e-6
def composite(z: dict) -> float                                   # mean of z_s1, z_s2, z_s3
def lead_time(sig: pd.Series, drop: pd.Series, max_lag: int, block: int, n_perm: int, seed: int) -> pd.DataFrame
    # Spearman(sig[w], drop[w+lag]) for lag 0..max_lag; p from permuting contiguous blocks of sig
```

`run_radar.py`: Reference on study weeks 1 to 8 with the anchor LR model; signals for every later week;
alarm = composite >= tau; `drop(w) = r_val - recall_at_1fpr(w)` from weekly_metrics; lead_time for each
of S1 to S3, composite, B1 to B3. Write `radar_signals` and `lead_time`.

Tests: `test_signals.py` (JS = 0 for identical streams and in (0, 1] otherwise; novelty = 0 for a URL equal
to a centroid's source; orphan = 1 with no rules; signals raise if `label` present; shuffling a hidden label
column before dropping it does not change outputs).

**STOP checkpoint 6:** lead-time table (rho and p per signal and lag), alarm weeks, and whether any data
mining signal beats all three baselines. Report honestly if not.

---

## Phase 7: Drift injection and replication (RQ2 ground truth)

Create `src/inject.py`, `scripts/run_inject.py` (make inject), notebooks 07 and 10.

```python
# src/inject.py
def global_families(phish: pd.DataFrame, cfg: dict, seed: int) -> pd.Series     # k-means k=global_k; writes dim_campaign.family_id
def pick_families(fam: pd.Series, weeks: pd.Series, n: int, min_size: int, seed: int) -> list[int]
    # families with >= min_size URLs present both in weeks 1 to 8 and later
def quiet_onset(composite: pd.Series, duration: int) -> int     # first test week starting `duration` weeks without alarms
def inject(stream: pd.DataFrame, donors: pd.DataFrame, rate: float, seed: int) -> pd.DataFrame
    # replace `rate` of the phishing rows with donor rows (without replacement across weeks); adds is_injected
def inject_benign(stream, donors_benign, rate, seed) -> pd.DataFrame      # benign-only control (HF benign donors)
def detection(alarms: pd.Series, onset: int, horizon: int) -> dict        # detected, delay_weeks
```

`run_inject.py`, per family F: remove F from training weeks and from the natural stream; retrain the
anchor LR; refit Reference; find the onset; for each rate inject F for duration_weeks; compute signals
and alarms for every signal separately (z >= tau) and for the composite; record detection, delay, and the
false-alarm rate on non-injected weeks. Then the benign-only control at the same rates. Then replication:
rerun Phase 4 RQ1 and Phase 6 lead-time on Phishing.Database (or the fallback chosen at checkpoint 1).

Tests: `test_inject.py` (injected share equals rate within one URL; donors never reused within a run).

**STOP checkpoint 7:** detection power and median delay per signal x rate, false-alarm rates, benign-control
comparison, replication table.

---

## Phase 8: Emerging patterns (RQ3)

Create `scripts/run_explain.py` (make explain), notebook 08 (uses `patterns.emerging_patterns`).

- At each real alarm week: transactions of the reference window vs the trailing `window_weeks` weeks
  (unlabeled); emerging patterns; save top_k.
- Injection validation: signature items of family F = top 10 items by lift in F vs other training-era
  phishing. precision@10 = share of the top 10 emerging patterns containing at least one signature item.
- After labels: false-negative rate inside vs outside each pattern (static model, fixed threshold) -> lift;
  false-negative rate by decile of per-URL S3 novelty.

**STOP checkpoint 8:** the "what changed" table for 2 to 3 real alarms, precision@10 on injections,
FN-lift and novelty-decile results.

---

## Phase 9: Labeling budget, retraining policies, sensitivity (RQ4)

Create `src/policy.py`, `scripts/run_policy.py` (make policy), notebook 09.

```python
# src/policy.py
def select(candidates: pd.DataFrame, strategy: str, budget: int, model: TrainedModel,
           ref: Reference, patterns: pd.DataFrame, seed: int) -> pd.Index
    # random | uncertainty (|score - 0.5| smallest) | novelty (highest per-URL S3) |
    # pattern (matches a top-k emerging pattern, then random among matches) | mixed (half novelty, half pattern)
def labeled_window(con, end_week: int, n_weeks: int, delay: int) -> pd.DataFrame
    # weeks (end_week - delay - n_weeks + 1) .. (end_week - delay), labels available
def budget_experiment(alarm_week: int, cfg: dict, seed: int) -> pd.DataFrame
    # candidates = streams of alarm_week-1 and alarm_week; retrain on labeled_window + selected labels;
    # evaluate weeks alarm+1..alarm+4 (exclude_seen); no_retrain = static model; oracle = retrain with all
    # labels up to alarm_week; recall_recovered = (R_policy - R_no) / (R_oracle - R_no) (nan if denominator <= 0)
def run_policy(name: str, cfg: dict) -> pd.DataFrame
    # static | weekly | every4 | radar (retrain at alarms with radar_policy_strategy/budget);
    # each retrain uses labeled_window (delay-aware); returns weekly_metrics rows + counts
```

Sensitivity runs (same code, config overrides): benign source HuggingFace/UCI instead of Common Crawl
(for RQ1 and the headline budget result), tau_grid, label_delay_weeks in [2, 8].

**STOP checkpoint 9 (humans choose the headline by Wed Nov 25):** budget table (mean and CI of
recall_recovered per strategy x budget), policy_summary, sensitivity table.

---

## Phase 10: Results freeze and demo

Create `scripts/freeze_results.py` (make freeze), `app/streamlit_app.py` (make demo).

- freeze_results: regenerate every final figure into `reports/figures/` with stable names
  (fig01_snapshot_sizes.png ... ), write `reports/figures/MANIFEST.md` (figure, source table, git commit),
  and write demo parquet files to `reports/demo/`: weekly series (recall static vs radar policy, composite,
  tau, alarms), emerging patterns per alarm (tokens only; any example URL defanged), budget curves.
- Streamlit app: reads only `reports/demo/*.parquet`; sidebar week slider and policy selector; panels:
  (1) recall over time, (2) composite with tau line and alarm markers, (3) top emerging patterns at the
  selected alarm, (4) recall recovered vs budget by strategy. No model code runs in the app.

Acceptance: `streamlit run app/streamlit_app.py` works with network disabled.

**STOP checkpoint 10:** list of figures, screenshot of the demo, and the git commit hash of the freeze.
After this checkpoint, analysis changes go only to notebooks/secondary/.

---

## Phase 11: Reproducibility pass and cleanup

- `make all` from `data/raw/` reproduces every result table; record total runtime in the README.
- `make notebooks` executes all primary notebooks without errors.
- Pin requirements; README with setup, data sources and terms, pipeline overview, how to run the demo,
  safety rules.
- notebooks/secondary/: every notebook starts with a markdown cell stating what was tried and why it was
  dropped.
- `ruff check` clean; `make test` green.

**STOP checkpoint 11:** runtime, test count, and anything that could not be reproduced.
