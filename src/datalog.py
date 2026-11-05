"""Record every downloaded file in data/raw/data_log.csv."""

import csv
import hashlib
from datetime import UTC, datetime
from pathlib import Path

from src.log import get_logger

log = get_logger(__name__)

COLUMNS = ["file_name", "source_url", "utc_iso", "sha256", "bytes", "rows"]
CHUNK = 1 << 20


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, read in 1 MiB chunks."""
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def log_file(path: Path, source_url: str, rows: int | None, log_csv: Path) -> str:
    """Append one row for `path` to `log_csv` and return the file's sha256.

    Row: file_name, source_url, utc_iso, sha256, bytes, rows (blank when rows is None).
    Creates the CSV with a header if needed. If a row with the same sha256 already exists,
    nothing is written (idempotent per sha).
    """
    path, log_csv = Path(path), Path(log_csv)
    digest = sha256_file(path)

    if log_csv.exists():
        with log_csv.open(newline="", encoding="utf-8") as fh:
            if any(r["sha256"] == digest for r in csv.DictReader(fh)):
                log.info("already logged %s (sha256 %s)", path.name, digest[:12])
                return digest

    log_csv.parent.mkdir(parents=True, exist_ok=True)
    new = not log_csv.exists()
    with log_csv.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if new:
            writer.writerow(COLUMNS)
        writer.writerow(
            [
                path.name,
                source_url,
                datetime.now(UTC).isoformat(timespec="seconds"),
                digest,
                path.stat().st_size,
                "" if rows is None else rows,
            ]
        )
    log.info(
        "logged %s: %d bytes, rows=%s, sha256 %s", path.name, path.stat().st_size, rows, digest[:12]
    )
    return digest
