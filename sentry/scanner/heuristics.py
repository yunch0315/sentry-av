"""Content heuristics: file typing, encrypted-file detection, suspicious strings.

False-positive policy
---------------------
Every indicator is either *strong* (specific to malware / ransomware: shadow-copy
deletion, ransom-note wording, bulk encryption loops, ...) or *weak* (things that
also appear in ordinary software: base64 blobs, crypto APIs, "bitcoin" in a word
list, zero-width characters in i18n tables, ...).

A file is only reported when it has at least one strong indicator, or when it
accumulates several different weak indicators (a classic dropper is nothing but
weak indicators stacked together).  A single weak hit never produces a finding.
"""
from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePath

from ..utils import entropy

STRONG_MIN = 4          # evidence with score >= STRONG_MIN counts as strong unless stated otherwise
WEAK_COMBO = 4          # this many *different* weak indicators + score >= high => reported anyway

# ---- file typing -----------------------------------------------------------
SCRIPT_EXTS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
               ".hta", ".sh", ".bash", ".zsh", ".command", ".py", ".pyw", ".rb", ".pl",
               ".scpt", ".applescript", ".lnk", ".reg", ".inf"}
EXEC_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".msi", ".app",
             ".dylib", ".so", ".bin", ".pkg", ".dmg"}
OFFICE_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".docx", ".xlsx", ".pptx",
               ".doc", ".xls", ".ppt"}
ARCHIVE_EXTS = {".jar", ".war", ".ear", ".zip", ".whl", ".egg", ".apk", ".ipa", ".xpi", ".crx", ".asar",
                ".nupkg", ".vsix"}

# magic bytes expected for common document / media extensions
MAGIC: dict[str, tuple[bytes, ...]] = {
    ".pdf": (b"%PDF",), ".jpg": (b"\xff\xd8\xff",), ".jpeg": (b"\xff\xd8\xff",),
    ".png": (b"\x89PNG",), ".gif": (b"GIF8",), ".zip": (b"PK\x03\x04",),
    ".docx": (b"PK\x03\x04",), ".xlsx": (b"PK\x03\x04",), ".pptx": (b"PK\x03\x04",),
    ".doc": (b"\xd0\xcf\x11\xe0",), ".xls": (b"\xd0\xcf\x11\xe0",), ".ppt": (b"\xd0\xcf\x11\xe0",),
    ".mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"), ".mp4": (b"\x00\x00\x00",),
    ".mov": (b"\x00\x00\x00",), ".bmp": (b"BM",), ".rar": (b"Rar!",), ".7z": (b"7z\xbc\xaf",),
    ".gz": (b"\x1f\x8b",), ".sqlite": (b"SQLite",), ".psd": (b"8BPS",), ".tif": (b"II*\x00", b"MM\x00*"),
    ".hwp": (b"\xd0\xcf\x11\xe0", b"HWP Document"), ".hwpx": (b"PK\x03\x04",),
}
DOC_EXTS = set(MAGIC) | {".txt", ".csv", ".json", ".xml", ".html", ".md", ".rtf", ".odt", ".ods",
                         ".key", ".pages", ".numbers", ".heic", ".raw", ".cr2", ".ai", ".svg"}

# Any well-known container/media/executable header.  A file that starts with one of these is
# *not* ransomware output even if its extension says something else (e.g. a JPEG named .png).
_KNOWN_HEADS: tuple[bytes, ...] = tuple({m for ms in MAGIC.values() for m in ms if m != b"\x00\x00\x00"}) + (
    b"RIFF", b"OggS", b"fLaC", b"\x1aE\xdf\xa3", b"FLV", b"wOFF", b"OTTO", b"\x00\x01\x00\x00",
    b"\x00\x00\x01\x00", b"%!PS", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
    b"\x7fELF", b"#!", b"bplist", b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"BZh", b"\xfd7zXZ\x00",
    b"\x28\xb5\x2f\xfd", b"<?xml", b"<!DOCTYPE", b"<html", b"<HTML", b"WEBP", b"\x00asm", b"SQLite",
    b"\x1f\x8b", b"PK", b"ustar", b"!<arch>", b"\xed\xab\xee\xdb", b"xar!", b"\x03\x00\x00\x00",
)


def _looks_like_text(head: bytes) -> bool:
    sample = head[:1024]
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    try:
        s = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
    return printable / max(1, len(s)) > 0.95


def known_format(head: bytes) -> bool:
    """True when the header identifies a well-known file format (or plain text)."""
    if any(head.startswith(m) for m in _KNOWN_HEADS):
        return True
    if head[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free"):   # ISO media (mp4/mov/heic)
        return True
    return _looks_like_text(head)


def detect_type(head: bytes, ext: str) -> str:
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                    b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "macho"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] == b"PK\x03\x04":
        return "office" if ext in OFFICE_EXTS else "zip"
    if ext in ARCHIVE_EXTS:
        return "zip"
    if head[:2] == b"#!":
        return "script"
    if ext in SCRIPT_EXTS:
        return "script"
    if ext in OFFICE_EXTS and head[:4] == b"\xd0\xcf\x11\xe0":
        return "office"
    if ext in EXEC_EXTS:
        return "exec-ext"
    return "other"


# ---- findings ---------------------------------------------------------------
@dataclass
class Evidence:
    score: int
    label: str
    strong: bool = False


@dataclass
class Analysis:
    severity: str = "clean"   # clean | low | medium | high | critical
    category: str = ""
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(e.score for e in self.evidence)

    @property
    def has_strong(self) -> bool:
        return any(e.strong for e in self.evidence)

    def add(self, score: int, label: str, strong: bool | None = None) -> None:
        self.evidence.append(Evidence(score, label, (score >= STRONG_MIN) if strong is None else strong))

    def finalize(self, category: str, high: int = 8, medium: int = 5, low: int = 3) -> "Analysis":
        s = self.score
        weak_kinds = {e.label for e in self.evidence if not e.strong}
        reportable = self.has_strong or (len(weak_kinds) >= WEAK_COMBO and s >= high)
        if not reportable:
            self.severity, self.category = "clean", ""
            return self
        if s >= high:
            self.severity = "high"
        elif s >= medium:
            self.severity = "medium"
        elif s >= low:
            self.severity = "low"
        else:
            self.severity = "clean"
        self.category = category if self.severity != "clean" else ""
        return self


# ---- encrypted-file heuristics ------------------------------------------------
_COMPANION_EXTS = {".bak", ".tmp", ".old", ".orig", ".part", ".crdownload", ".download", ".zip",
                   ".gz", ".7z", ".sql", ".lock", ".log", ".json", ".xml", ".txt", ".md5", ".sha256",
                   ".sig", ".asc", ".gpg", ".pgp", ".torrent", ".url", ".lnk", ".bz2", ".xz", ".zst"}


def analyze_encrypted(path: str, head: bytes, sigdb) -> Analysis:
    """Does this file look like the *output* of ransomware (encrypted victim file or ransom note)?"""
    a = Analysis()
    p = PurePath(path)
    ext = p.suffix.lower()
    inner_ext = PurePath(p.stem).suffix.lower()
    ent = entropy(head) if head else 0.0
    random_body = bool(head) and len(head) >= 1024 and not known_format(head)

    if sigdb.is_ransom_ext(ext):
        if inner_ext in DOC_EXTS and (ent > 7.0 or random_body):
            a.add(8, f"known ransomware extension {ext}")
        elif random_body and ent > 7.5:
            a.add(5, f"ransomware-style extension {ext} with random content (entropy {ent:.2f})")

    # name.pdf.xyz : original type ext followed by an unknown extension, body is random bytes
    if inner_ext in MAGIC and ext and ext not in MAGIC and ext not in DOC_EXTS and ext not in SCRIPT_EXTS \
            and ext not in EXEC_EXTS and ext not in _COMPANION_EXTS and not ext.endswith(("-shm", "-wal", "-journal")) \
            and random_body and ent > 7.6:
        a.add(6, f"double extension {inner_ext}{ext} with high entropy {ent:.2f}")

    # type says PDF/JPG... but header is random bytes (not merely *another* known format)
    if ext in MAGIC and head and not any(head.startswith(m) for m in MAGIC[ext]) and random_body and ent > 7.9:
        a.add(6, f"{ext} header mismatch, entropy {ent:.2f} (possibly encrypted)")

    # ransom notes: file name alone is never enough, the wording has to be there too
    hits = _note_text_hits(head) if head and (ext in (".txt", ".html", ".htm", ".hta", ".rtf", "") or
                                             sigdb.is_ransom_note_name(p.name)) else 0
    if sigdb.is_ransom_note_name(p.name) and hits >= 2:
        a.add(9, "ransom note (file name + wording)")
    elif hits >= 3:
        a.add(8, "ransom-note wording in content")

    return a.finalize("ransomware-artifact")


_NOTE_PHRASES = [
    rb"your files (have been|are|were) encrypted", rb"all your (files|data) (are|have been) (encrypted|locked)",
    rb"to (decrypt|restore|recover) your files", rb"decrypt(ion|or)? (key|tool|software)",
    rb"private key", rb"bitcoin", rb"\bbtc\b", rb"monero", rb"\.onion\b", rb"tor browser",
    rb"do not (try to )?(rename|modify|decrypt)", rb"personal id", rb"unique id", rb"pay(ment)? (the )?ransom",
    rb"contact us (at|via)", rb"within (24|48|72) hours", rb"price will (double|increase)",
]
_NOTE_RE = [re.compile(p, re.IGNORECASE) for p in _NOTE_PHRASES]


def _note_text_hits(data: bytes) -> int:
    sample = data[:65536]
    try:  # handle UTF-16 notes
        if sample[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in sample[:200]:
            sample = sample.decode("utf-16", errors="ignore").encode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        pass
    return sum(1 for r in _NOTE_RE if r.search(sample))


# ---- executable / script content heuristics ------------------------------------
# (regex, score, label).  score >= STRONG_MIN => strong indicator (see module docstring).
_SECURITY_PROCS = rb"(MsMpEng|MpCmdRun|vgc|vgtray|EasyAntiCheat(_EOS)?|BEService|avp|ekrn|bdagent|AhnLab|V3Lite|V3Svc|ASDSvc|ALYac|AYAgent|csfalcon|SentinelAgent|CylanceSvc|SAVService|mbam|McShield)"

_BIN_INDICATORS: list[tuple[bytes, int, str]] = [
    (rb"vssadmin(\.exe)?\s+delete\s+shadows", 8, "shadow copy deletion command"),
    (rb"wmic(\.exe)?\s+shadowcopy\s+delete", 8, "shadow copy deletion (wmic)"),
    (rb"bcdedit(\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no", 8, "disables Windows recovery"),
    (rb"bcdedit(\.exe)?\s+/set\s+\{default\}\s+bootstatuspolicy\s+ignoreallfailures", 6, "boot status policy tamper"),
    (rb"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)", 8, "backup catalog deletion"),
    (rb"tmutil\s+deletelocalsnapshots", 8, "Time Machine snapshot deletion"),
    (rb"cipher(\.exe)?\s+/w:", 4, "free-space wiping"),
    (rb"Set-MpPreference\s+-Disable", 6, "disables Defender"),
    (rb"netsh\s+advfirewall\s+set\s+\w+\s+state\s+off", 4, "disables firewall"),
    (rb"your files (have been|are) encrypted", 8, "ransom note string"),
    (rb"all your files (are|have been) (encrypted|locked)", 8, "ransom note string"),
    (rb"to decrypt your files", 6, "ransom note string"),
    (rb"(taskkill|kill)\b[^\n\x00]{0,100}" + _SECURITY_PROCS + rb"\b", 4, "kills security software"),
    (rb"decrypt(ion)? (key|tool)", 2, "decryption key wording"),
    (rb"\.onion\b", 2, "Tor hidden service reference"),
    (rb"\b(bitcoin|monero)\b", 2, "cryptocurrency reference"),
    (rb"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", 1, "Bitcoin address-like string"),
    (rb"CryptEncrypt|BCryptEncrypt|CryptGenKey|CryptDeriveKey", 2, "crypto API"),
    (rb"RtlEncryptMemory|EVP_EncryptInit|AES_set_encrypt_key|ChaCha20|Salsa20|curve25519", 2, "cipher primitive"),
    (rb"GetLogicalDrives|FindFirstFileW.{0,200}FindNextFileW", 1, "drive/file enumeration"),
    (rb"NetShareEnum|WNetOpenEnum", 2, "network share enumeration"),
    (rb"IsDebuggerPresent|CheckRemoteDebuggerPresent", 1, "anti-debugging"),
    (rb"VirtualAllocEx.{0,400}WriteProcessMemory.{0,400}CreateRemoteThread", 4, "process injection pattern"),
    (rb"SetWindowsHookEx", 1, "keyboard/window hook"),
    (rb"schtasks(\.exe)?\s+/create", 2, "scheduled task persistence"),
    (rb"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 2, "Run-key persistence"),
    (rb"Software\\Policies\\Microsoft\\Windows Defender", 3, "Defender policy tamper"),
    (rb"mshta(\.exe)?\s+(http|vbscript|javascript)|regsvr32\s+/s\s+/u\s+/i:|rundll32\s+javascript:", 3, "LOLBin abuse"),
    (rb"-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/=]{40,}", 4, "encoded PowerShell"),
    (rb"\.locked\b|\.encrypted\b|\.crypted\b", 2, "ransomware-style extension string"),
    (rb"(HOW[_\-]?TO[_\-]?(DECRYPT|RESTORE|RECOVER)|DECRYPT[_\-]?(FILES|INSTRUCTIONS|MY|YOUR)|"
     rb"RESTORE[_\-]?(FILES|MY|YOUR)|READ[_\-]?ME[_\-]?(FOR[_\-]?)?(DECRYPT|RESTORE|RECOVER|UNLOCK))"
     rb"[^\x00\n]{0,30}\.(txt|hta|html?)", 4, "ransom note filename string"),
    (rb"xattr\s+-[dr]\s+com\.apple\.quarantine", 2, "Gatekeeper quarantine attribute removal"),
    (rb"/Library/LaunchAgents/|/Library/LaunchDaemons/", 1, "launchd persistence path"),
]
_BIN_RE = [(re.compile(p, re.IGNORECASE | re.DOTALL), s, l) for p, s, l in _BIN_INDICATORS]


def analyze_executable(data: bytes, kind: str) -> Analysis:
    a = Analysis()
    text = data
    # include UTF-16LE strings (common in PE)
    try:
        wide = data.decode("utf-16-le", errors="ignore").encode("ascii", errors="ignore")
    except Exception:  # noqa: BLE001
        wide = b""
    seen: set[str] = set()
    for rx, score, label in _BIN_RE:
        if label in seen:
            continue
        if rx.search(text) or (wide and rx.search(wide)):
            a.add(score, label)
            seen.add(label)
    ent = entropy(data[:1 << 20])
    if kind == "pe" and ent > 7.3 and len(data) > 65536:
        a.add(2, f"packed/encrypted PE body (entropy {ent:.2f})")
    return a.finalize("suspicious-executable")


_SCRIPT_INDICATORS: list[tuple[bytes, int, str]] = [
    (rb"-[Ee]nc(odedCommand|oded)?\s+[A-Za-z0-9+/=]{40,}", 5, "encoded PowerShell command"),
    (rb"\bIEX\b|Invoke-Expression", 3, "Invoke-Expression"),
    (rb"DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|\biwr\s|curl\s[^\n]*\|\s*(ba)?sh\b|wget\s[^\n]*\|\s*(ba)?sh\b",
     3, "downloads and executes remote content"),
    (rb"FromBase64String\(", 3, "base64 decode"),
    (rb"[A-Za-z0-9+/]{200,}={0,2}", 2, "long base64 blob"),
    (rb"-w(indowstyle)?\s+hidden|-nop\b|-NoProfile|-ExecutionPolicy\s+Bypass", 2, "hidden/bypass PowerShell flags"),
    (rb"vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete", 8, "shadow copy deletion"),
    (rb"bcdedit\s+/set\s+\{default\}", 5, "boot configuration tamper"),
    (rb"tmutil\s+deletelocalsnapshots", 8, "Time Machine snapshot deletion"),
    (rb"Set-MpPreference\s+-Disable|Add-MpPreference\s+-ExclusionPath", 6, "Defender tamper"),
    (rb"certutil(\.exe)?\s+(-urlcache|-decode)|bitsadmin\s+/transfer", 4, "LOLBin download/decode"),
    (rb"openssl\s+enc\s+-(aes|chacha).{0,300}(find|for\s)|(find|for\s).{0,300}openssl\s+enc\s+-(aes|chacha)",
     8, "bulk encryption with openssl"),
    (rb"gpg\s+(--batch\s+)?(-c|--symmetric).{0,200}(find|for\s)", 6, "bulk encryption with gpg"),
    (rb"Get-ChildItem.{0,200}-Recurse.{0,400}(AesManaged|RijndaelManaged|CreateEncryptor)", 8, "recursive encryption loop"),
    (rb"(os\.walk|glob\.glob|Get-ChildItem|find\s).{0,600}(Fernet|AES\.new|Cipher\(|CreateEncryptor|openssl\s+enc).{0,600}(\.locked|\.encrypted|\.crypt|os\.rename|Rename-Item|\bmv\s)",
     8, "recursive encryption loop"),
    (rb"rm\s+-rf\s+(/|~|\$HOME)(\s|$|[\"'])", 5, "deletes root/home"),
    (rb"shred\s+-|del\s+/[fqs]\s+/[fqs]\s+.*\\\*|Remove-Item\s+.*-Recurse\s+-Force", 3, "mass deletion"),
    (rb"xattr\s+-[dr]\s+com\.apple\.quarantine", 3, "removes Gatekeeper quarantine"),
    (rb"osascript.{0,200}administrator privileges", 3, "AppleScript privilege prompt"),
    (rb"launchctl\s+(load|bootstrap).{0,200}(/tmp|/private/tmp|\.hidden|/\.)", 4, "hidden launchd persistence"),
    (rb"chmod\s+\+?x.{0,100}(/tmp|/var/tmp|/dev/shm)", 3, "makes temp file executable"),
    (rb"crontab\s+-|/etc/cron", 1, "cron persistence"),
    (rb"\bnc\s+-e\s|/dev/tcp/|mkfifo.{0,100}\bnc\s", 5, "reverse shell"),
    (rb"schtasks\s+/create|reg\s+add\s+.*\\Run\b|New-ItemProperty.*\\Run\b", 3, "persistence"),
    (rb"(taskkill|kill)\b[^\n\x00]{0,100}" + _SECURITY_PROCS + rb"\b", 4, "kills security software"),
    (rb"your files (have been|are) encrypted|to decrypt your files", 8, "ransom note string"),
    (rb"\.onion\b|bitcoin|monero", 2, "Tor/crypto reference"),
    (rb"\xe2\x80[\x8b-\x8f\xaa-\xae]", 3, "zero-width / RTL override characters"),
    (rb"\b(eval|exec)\s*\(\s*(base64|b64decode|codecs\.decode|bytes\.fromhex|chr\()", 4, "obfuscated eval"),
    (rb"String\.fromCharCode\((\s*\d+\s*,){20,}", 4, "charcode-obfuscated JavaScript"),
    (rb"WScript\.Shell|Shell\.Application|ActiveXObject\(", 2, "WScript shell object"),
]
_SCRIPT_RE = [(re.compile(p, re.IGNORECASE | re.DOTALL), s, l) for p, s, l in _SCRIPT_INDICATORS]


def analyze_script(data: bytes) -> Analysis:
    a = Analysis()
    text = data
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16", errors="ignore").encode("utf-8", errors="ignore")
    seen: set[str] = set()
    for rx, score, label in _SCRIPT_RE:
        if label not in seen and rx.search(text):
            a.add(score, label)
            seen.add(label)
    return a.finalize("suspicious-script")


def analyze_office(path: str) -> Analysis:
    a = Analysis()
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                a.add(2, "document contains VBA macros")
                try:
                    blob = b"".join(z.read(n) for n in names if n.lower().endswith("vbaproject.bin"))
                    if re.search(rb"Auto_?Open|Document_Open|Workbook_Open|AutoExec", blob, re.I):
                        a.add(4, "auto-executing macro")
                    if re.search(rb"Shell|WScript|powershell|CreateObject|URLDownloadToFile|cmd\.exe", blob, re.I):
                        a.add(5, "macro launches external processes")
                except Exception:  # noqa: BLE001
                    pass
            if any(n.lower().endswith((".exe", ".dll", ".ps1", ".vbs", ".js", ".bat")) for n in names):
                a.add(6, "embedded executable/script inside document")
            if any("oleObject" in n for n in names):
                a.add(1, "embedded OLE object")
    except (zipfile.BadZipFile, OSError):
        pass
    return a.finalize("suspicious-document")
