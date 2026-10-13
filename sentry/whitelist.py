"""Trusted-process / excluded-path decisions.

Anti-cheat drivers (Riot Vanguard, EasyAntiCheat, BattlEye), OS security
components (Defender, XProtect), sync clients and backup daemons legitimately
touch huge numbers of files.  They are never treated as ransomware suspects.

Note: the *command-line rules* in realtime/process_watch.py deliberately ignore
this whitelist - `vssadmin delete shadows` is dangerous regardless of who runs it.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from typing import Optional

import psutil

from .utils import IS_MACOS, IS_WINDOWS, run_cmd

_LOG = logging.getLogger("sentry.whitelist")

_WIN_NAMES = {
    # Riot Vanguard & other anti-cheat
    "vgc.exe", "vgtray.exe", "vgk.sys", "riotclientservices.exe", "riotclientux.exe",
    "easyanticheat.exe", "easyanticheat_eos.exe", "easyanticheat_setup.exe",
    "beservice.exe", "battleye.exe", "faceitservice.exe", "faceit.exe",
    "steam.exe", "steamservice.exe", "steamwebhelper.exe", "epicgameslauncher.exe",
    # Windows Defender / security center
    "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "mpdefendercoreservice.exe", "smartscreen.exe",
    # core OS
    "system", "registry", "memory compression", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "smss.exe", "svchost.exe",
    "explorer.exe", "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "tiworker.exe", "trustedinstaller.exe", "wuauclt.exe", "usoclient.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe", "dwm.exe",
    "runtimebroker.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "audiodg.exe", "spoolsv.exe", "conhost.exe", "wmiprvse.exe", "compattelrunner.exe",
    "msiexec.exe", "dism.exe", "cleanmgr.exe",
    # cloud sync / backup
    "onedrive.exe", "filecoauth.exe", "dropbox.exe", "googledrivefs.exe",
    "icloud.exe", "icloudservices.exe", "applephotostreams.exe",
    "backblaze.exe", "bzfilelist.exe", "bztransmit.exe",
}

_MAC_NAMES = {
    # macOS system daemons that churn through files
    "backupd", "backupd-helper", "mds", "mds_stores", "mdworker", "mdworker_shared",
    "mdsync", "fseventsd", "cloudd", "bird", "fileproviderd", "photolibraryd",
    "photoanalysisd", "syspolicyd", "xprotect", "xprotectservice", "xprotectremediator",
    "xprotectpluginservice", "securityd", "trustd", "launchd", "kernel_task",
    "finder", "spotlight", "diskimagesmounthelper", "diskarbitrationd", "revisiond",
    "suhelperd", "softwareupdated", "installd", "system_installd", "nsurlsessiond",
    "coreduetd", "iconservicesagent", "quicklookuiservice", "com.apple.quicklook",
    "mtmd", "mtmfs", "timemachine", "appstoreagent", "storedownloadd",
    # anti-cheat / games
    "vanguard", "riot client", "riotclientservices", "steam", "steam_osx", "steam helper",
    "easyanticheat", "epic games launcher",
    # cloud sync
    "dropbox", "onedrive", "google drive", "googledrivefs", "icloud", "icloud drive",
    "backblaze", "bzfilelist", "bztransmit",
}

_WIN_PREFIXES = [
    "C:\\Windows\\",
    "C:\\Program Files\\Riot Vanguard\\",
    "C:\\Program Files\\Riot Games\\",
    "C:\\Program Files\\Windows Defender\\",
    "C:\\Program Files\\Windows Defender Advanced Threat Protection\\",
    "C:\\ProgramData\\Microsoft\\Windows Defender\\",
    "C:\\Program Files\\EasyAntiCheat\\",
    "C:\\Program Files (x86)\\EasyAntiCheat\\",
    "C:\\Program Files (x86)\\Common Files\\BattlEye\\",
    "C:\\Program Files (x86)\\Steam\\",
    "C:\\Program Files\\Microsoft OneDrive\\",
    "C:\\Program Files\\Dropbox\\",
    "C:\\Program Files\\Google\\Drive File Stream\\",
]
# user-writable sub-folders of C:\Windows that must NOT inherit trust
_WIN_UNTRUSTED_SUB = [
    "C:\\Windows\\Temp\\", "C:\\Windows\\Tasks\\", "C:\\Windows\\tracing\\",
    "C:\\Windows\\System32\\Tasks\\", "C:\\Windows\\System32\\spool\\drivers\\color\\",
    "C:\\Windows\\Registration\\CRMLog\\", "C:\\Windows\\debug\\WIA\\",
]

_MAC_PREFIXES = [
    "/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/sbin/", "/bin/",
    "/Library/Apple/", "/Library/Application Support/com.apple.TCC/",
    "/Applications/Riot Vanguard.app/", "/Library/Application Support/Riot Vanguard/",
    "/Applications/Steam.app/", "/Applications/Dropbox.app/", "/Applications/OneDrive.app/",
    "/Applications/Google Drive.app/",
]

_WIN_SIGNERS = [
    "Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher",
    "Riot Games, Inc.", "Valve", "Valve Corp", "Epic Games", "EasyAntiCheat",
    "BattlEye Innovations", "Google LLC", "Dropbox, Inc", "Apple Inc.", "Backblaze",
]


class Whitelist:
    def __init__(self, cfg=None):
        names = set(_WIN_NAMES if IS_WINDOWS else _MAC_NAMES)
        prefixes = list(_WIN_PREFIXES if IS_WINDOWS else _MAC_PREFIXES)
        signers = list(_WIN_SIGNERS)
        team_ids: list[str] = []
        excluded: list[str] = []
        if cfg is not None:
            names |= {n.lower() for n in cfg.get("whitelist_process_names", [])}
            prefixes += list(cfg.get("whitelist_path_prefixes", []))
            signers += list(cfg.get("trusted_signers", []))
            team_ids += list(cfg.get("trusted_team_ids", []))
            excluded += list(cfg.get("excluded_paths", []))
        self.names = {n.lower() for n in names}
        self.prefixes = [self._norm(p) for p in prefixes]
        self.untrusted_sub = [self._norm(p) for p in _WIN_UNTRUSTED_SUB]
        self.signers = [s.lower() for s in signers]
        self.team_ids = set(team_ids)
        self.excluded = [self._norm(p) for p in excluded]
        self._sig_cache: dict[str, bool] = {}
        self._valid_cache: dict[str, bool] = {}
        self._lock = threading.Lock()
        self.own_pid = os.getpid()
        self.protected_pids = self._own_ancestry()

    @staticmethod
    def _own_ancestry() -> set[int]:
        pids = {os.getpid(), 0, 4}
        try:
            me = psutil.Process()
            pids.update(a.pid for a in me.parents())
        except psutil.Error:
            pass
        return pids

    @staticmethod
    def _norm(p: str) -> str:
        p = os.path.normpath(p)
        return p.lower() if IS_WINDOWS else p

    def is_excluded_path(self, path: str) -> bool:
        p = self._norm(path)
        for ex in self.excluded:
            if p == ex or p.startswith(ex.rstrip("\\/") + os.sep):
                return True
        return False

    def _path_trusted(self, exe: str) -> bool:
        p = self._norm(exe)
        for sub in self.untrusted_sub:
            if p.startswith(sub.rstrip("\\/") + os.sep):
                return False
        for pre in self.prefixes:
            if p.startswith(pre.rstrip("\\/") + os.sep) or p == pre:
                return True
        return False

    def is_trusted_process(self, proc: psutil.Process) -> bool:
        try:
            if proc.pid in self.protected_pids:
                return True
            name = (proc.name() or "").lower()
            if name in self.names:
                return True
            exe = ""
            try:
                exe = proc.exe() or ""
            except (psutil.AccessDenied, psutil.ZombieProcess):
                exe = ""
            if exe and self._path_trusted(exe):
                return True
            if IS_MACOS and exe.startswith("/Applications/") and ".app/" in exe:
                # app bundles: trust Apple-signed / App Store / trusted team IDs
                return self.signature_trusted(exe)
            if IS_WINDOWS and exe:
                return self.signature_trusted(exe)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return False
        return False

    def is_trusted_process_path(self, exe: str) -> bool:
        return self._path_trusted(exe) or self.signature_trusted(exe)

    def signature_trusted(self, exe: str) -> bool:
        with self._lock:
            if exe in self._sig_cache:
                return self._sig_cache[exe]
        ok = False
        try:
            if IS_MACOS:
                ok = self._mac_sig(exe)
            elif IS_WINDOWS:
                ok = self._win_sig(exe)
        except Exception as e:  # noqa: BLE001
            _LOG.debug("signature check failed for %s: %s", exe, e)
        with self._lock:
            self._sig_cache[exe] = ok
        return ok

    def signature_valid(self, exe: str) -> bool:
        """Intact signature from *any* identified developer (weaker than signature_trusted)."""
        with self._lock:
            if exe in self._valid_cache:
                return self._valid_cache[exe]
        ok = False
        try:
            if IS_MACOS:
                rc, out, err = run_cmd(["codesign", "-dv", "--verbose=2", exe], timeout=10)
                text = out + err
                ok = rc == 0 and ("Authority=Developer ID Application" in text or
                                  "Authority=Apple Mac OS Application Signing" in text or
                                  "Authority=Software Signing" in text)
                if ok:   # also make sure the signature actually verifies
                    rc2, _, _ = run_cmd(["codesign", "--verify", exe], timeout=15)
                    ok = rc2 == 0
            elif IS_WINDOWS:
                ps = (f"$s=Get-AuthenticodeSignature -LiteralPath '{exe.replace(chr(39), chr(39)*2)}';"
                      "if($s.Status -eq 'Valid'){'VALID'}")
                rc, out, _ = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=20)
                ok = rc == 0 and "VALID" in out
        except Exception as e:  # noqa: BLE001
            _LOG.debug("signature validity check failed for %s: %s", exe, e)
        with self._lock:
            self._valid_cache[exe] = ok
        return ok

    def _mac_sig(self, exe: str) -> bool:
        rc, out, err = run_cmd(["codesign", "-dv", "--verbose=2", exe], timeout=10)
        if rc != 0:
            return False
        text = out + err
        if "Authority=Software Signing" in text and "Authority=Apple Root CA" in text:
            return True   # Apple platform binary
        if "Authority=Apple Mac OS Application Signing" in text:
            return True   # Mac App Store
        m = re.search(r"TeamIdentifier=([A-Z0-9]+)", text)
        if m and m.group(1) in self.team_ids:
            return True
        return False

    def _win_sig(self, exe: str) -> bool:
        ps = (f"$s=Get-AuthenticodeSignature -LiteralPath '{exe.replace(chr(39), chr(39)*2)}';"
              "if($s.Status -eq 'Valid'){$s.SignerCertificate.Subject}")
        rc, out, _ = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                             timeout=20)
        if rc != 0 or not out.strip():
            return False
        subj = out.lower()
        return any(s in subj for s in self.signers)

    def describe(self) -> dict:
        return {"names": sorted(self.names), "path_prefixes": self.prefixes,
                "signers": self.signers, "team_ids": sorted(self.team_ids),
                "excluded_paths": self.excluded}


def proc_info(proc: psutil.Process) -> dict:
    """Safe snapshot used in logs / incident reports."""
    d: dict = {"pid": proc.pid}
    for attr in ("name", "exe", "cmdline", "username", "create_time", "ppid"):
        try:
            d[attr] = getattr(proc, attr)()
        except (psutil.Error, OSError):
            d[attr] = None
    return d
