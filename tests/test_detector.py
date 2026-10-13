import os
import time

from sentry.realtime.detector import BehaviorDetector
from sentry.scanner.signatures import SignatureDB


def make(cfg, canaries=None):
    cfg.set("window_seconds", 10)
    cfg.set("min_events_per_window", 30)
    cfg.set("min_suspicious_renames", 5)
    return BehaviorDetector(cfg, SignatureDB(), canaries)


def test_canary_set_is_shared_not_copied(cfg, tmp_path):
    canaries: set[str] = set()
    det = make(cfg, canaries)
    c = str(tmp_path / "!!_important_backup.docx")
    canaries.add(c)                      # monitor deploys decoys *after* constructing the detector
    det.feed("modified", c)
    a = det.assess()
    assert a.level == "ransomware" and a.canary_hit
    assert "canary" in a.reasons[0]


def test_untouched_canary_is_quiet(cfg, tmp_path):
    det = make(cfg, {str(tmp_path / "decoy.pdf")})
    det.feed("created", str(tmp_path / "decoy.pdf"))   # creation (our own deploy) is not tampering
    assert det.assess().level == "none"


def test_rename_burst_to_ransom_extension(cfg, tmp_path):
    det = make(cfg)
    for i in range(6):
        src = str(tmp_path / f"doc_{i}.pdf")
        det.feed("moved", src, src + ".locked")
    a = det.assess()
    assert a.level in ("suspicious", "ransomware")
    assert any("renamed" in r for r in a.reasons)


def test_rename_burst_plus_note_is_ransomware(cfg, tmp_path):
    det = make(cfg)
    for i in range(6):
        src = str(tmp_path / f"doc_{i}.docx")
        det.feed("moved", src, src + ".locked")
    det.feed("created", str(tmp_path / "HOW_TO_DECRYPT_FILES.txt"))
    assert det.assess().level == "ransomware"


def test_high_entropy_overwrites(cfg, tmp_path):
    cfg.set("min_high_entropy_writes", 3)
    det = make(cfg)
    for i in range(4):
        p = tmp_path / f"report_{i}.pdf"
        p.write_bytes(os.urandom(4096))          # no %PDF header, random content
        det.feed("modified", str(p))
    a = det.assess()
    assert any("high-entropy" in r for r in a.reasons)


def test_normal_editing_is_none(cfg, tmp_path):
    det = make(cfg)
    for i in range(10):
        p = tmp_path / f"notes_{i}.txt"
        p.write_text("hello " * 300)
        det.feed("modified", str(p))
    assert det.assess().level == "none"


def test_reset_and_prune(cfg, tmp_path):
    det = make(cfg)
    det.window = 0.05
    for i in range(6):
        src = str(tmp_path / f"d{i}.pdf")
        det.feed("moved", src, src + ".locked")
    time.sleep(0.1)
    assert det.assess().level == "none"      # everything aged out of the window
