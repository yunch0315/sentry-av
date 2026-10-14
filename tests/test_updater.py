"""Hash feeds: txt / CSV / zip parsing, recent-feed append, full index build + lookup."""
import hashlib
import io
import time
import zipfile
from pathlib import Path

import pytest

from sentry import updater
from sentry.scanner.hashindex import HashIndex
from sentry.scanner.signatures import SignatureDB

H1 = hashlib.sha256(b"one").hexdigest()
H2 = hashlib.sha256(b"two").hexdigest()
H3 = hashlib.sha256(b"three").hexdigest()

TXT = f"# MalwareBazaar\n{H1}\r\n{H2}\r\nnot a hash\n".encode()
CSV = (f'"2026-10-14 01:53:32", "1964812", "{H3}", "sha256_hash", "payload", "elf.mirai", '
       f'"Katana", "Mirai", "", "90", "False", "None", "elf,Mirai", "0", "r"\n').encode()


def _zip(**members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_iter_hashes_txt_csv_zip():
    assert list(updater.iter_hashes(TXT)) == [(H1, ""), (H2, "")]
    assert list(updater.iter_hashes(CSV)) == [(H3, "Mirai")]
    z = _zip(**{"full_sha256.txt": TXT, "x.csv": CSV})
    assert sorted(h for h, _ in updater.iter_hashes(z)) == sorted([H1, H2, H3])


def test_update_signatures_appends_and_dedups(cfg, monkeypatch):
    feeds = {"https://a.example/recent": TXT, "https://b.example/recent.csv": CSV}
    monkeypatch.setattr(updater, "_fetch", lambda url, timeout, dest=None, progress=None: feeds[url])
    res = updater.update_signatures(list(feeds))
    assert res["added"] == 3 and res["total"] == 3
    text = Path(res["file"]).read_text()
    assert f"{H3} Mirai feed:b.example" in text and f"{H1} feed:a.example" in text
    res2 = updater.update_signatures(list(feeds))
    assert res2["added"] == 0 and res2["total"] == 3
    assert not updater.signatures_due(24)
    db = SignatureDB()
    assert db.lookup_hash(H3) == "Mirai feed:b.example"
    assert db.lookup_hash(H1.upper()) == "feed:a.example"


def test_update_signatures_feed_failure_is_reported(cfg, monkeypatch):
    def boom(url, timeout, dest=None, progress=None):
        raise OSError("offline")
    monkeypatch.setattr(updater, "_fetch", boom)
    res = updater.update_signatures(["https://a.example/x"])
    assert res["added"] == 0 and res["feeds"]["https://a.example/x"].startswith("failed")


def test_hashindex_build_and_lookup(tmp_path):
    hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(1000)]
    p = tmp_path / "idx.bin"
    n = HashIndex.build(p, hashes + hashes[:10] + ["zz", "0" * 63])
    assert n == 1000 and p.stat().st_size == 16 + 1000 * 32
    idx = HashIndex(p)
    assert idx.count == 1000
    assert all(idx.contains(h) for h in hashes)
    assert not idx.contains(hashlib.sha256(b"absent").hexdigest())
    assert not idx.contains(None) and not idx.contains("abc")
    idx.close()


def test_hashindex_rejects_corrupt_file(tmp_path):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"garbage")
    idx = HashIndex(p)
    assert idx.count == 0 and not idx.contains(H1)


def test_update_full_builds_index_used_by_signaturedb(cfg, monkeypatch):
    dump = _zip(**{"full_sha256.txt": TXT})

    def fake_fetch(url, timeout, dest=None, progress=None):
        Path(dest).write_bytes(dump)
        if progress:
            progress(len(dump), len(dump))
        return Path(dest)
    monkeypatch.setattr(updater, "_fetch", fake_fetch)
    assert updater.full_due(7)
    res = updater.update_full("https://x/full")
    assert res["count"] == 2 and Path(res["file"]).exists()
    assert not updater.full_due(7) and updater.full_index_age_days() < 1
    assert not list(updater.app_dir().glob("sentry-feed-*"))    # temp dir cleaned
    db = SignatureDB()
    assert db.stats()["hashes_full"] == 2
    assert "full" in db.lookup_hash(H2)
    assert db.lookup_hash(H3) is None


def test_update_full_removes_stale_tempdirs(cfg, monkeypatch):
    stale = updater.app_dir() / "sentry-feed-stale"
    stale.mkdir()
    (stale / "full.bin").write_bytes(b"partial")
    dump = _zip(**{"full_sha256.txt": TXT})

    def fake_fetch(url, timeout, dest=None, progress=None):
        Path(dest).write_bytes(dump)
        return Path(dest)
    monkeypatch.setattr(updater, "_fetch", fake_fetch)
    updater.update_full("https://x/full")
    assert not stale.exists() and not list(updater.app_dir().glob("sentry-feed-*"))
