import csv
import hashlib

from src.datalog import COLUMNS, log_file


def _rows(log_csv):
    with log_csv.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_hash_and_row(tmp_cfg):
    raw = tmp_cfg["paths"]["raw"]
    f = raw / "a.txt"
    f.write_bytes(b"hello\n")
    log_csv = raw / "data_log.csv"

    digest = log_file(f, "https://example.org/a.txt", 1, log_csv)

    assert digest == hashlib.sha256(b"hello\n").hexdigest()
    rows = _rows(log_csv)
    assert list(rows[0].keys()) == COLUMNS
    assert rows[0]["file_name"] == "a.txt"
    assert rows[0]["sha256"] == digest
    assert rows[0]["bytes"] == "6"
    assert rows[0]["rows"] == "1"


def test_idempotent_per_sha(tmp_cfg):
    raw = tmp_cfg["paths"]["raw"]
    log_csv = raw / "data_log.csv"
    a, b = raw / "a.txt", raw / "b.txt"
    a.write_bytes(b"one")
    b.write_bytes(b"two")

    log_file(a, "src-a", None, log_csv)
    log_file(a, "src-a", None, log_csv)
    log_file(b, "src-b", 3, log_csv)

    rows = _rows(log_csv)
    assert [r["file_name"] for r in rows] == ["a.txt", "b.txt"]
    assert rows[0]["rows"] == ""
