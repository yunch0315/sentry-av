"""Config persistence: only overrides are written; legacy full copies are migrated."""
import json

from sentry.config import DEFAULTS, load_config


def test_first_run_writes_only_overrides(isolated_home):
    path = isolated_home / "home" / "config.json"
    cfg = load_config(path)
    assert json.loads(path.read_text()) == {}
    cfg.set("kill_score", 12)
    cfg.set("whitelist_process_names", ["foo.exe"])
    cfg.save()
    saved = json.loads(path.read_text())
    assert saved == {"kill_score": 12, "whitelist_process_names": ["foo.exe"]}
    again = load_config(path)
    assert again.kill_score == 12 and again.signature_urls == DEFAULTS["signature_urls"]


def test_legacy_signature_urls_are_upgraded(isolated_home):
    path = isolated_home / "home" / "config.json"
    old = dict(DEFAULTS)
    old["signature_urls"] = ["https://bazaar.abuse.ch/export/txt/sha256/recent/"]
    path.write_text(json.dumps(old))
    cfg = load_config(path)
    assert cfg.signature_urls == DEFAULTS["signature_urls"]
    assert len(cfg.signature_urls) >= 2


def test_user_custom_feed_list_is_kept(isolated_home):
    path = isolated_home / "home" / "config.json"
    path.write_text(json.dumps({"signature_urls": ["https://my.feed/x"]}))
    assert load_config(path).signature_urls == ["https://my.feed/x"]
