"""Tests for scripts/sync_whatsapp_allowlist.py.

The WhatsApp bridge reads its allowlist ONLY from WHATSAPP_ALLOWED_USERS, so
allow_from in config.yaml is decorative unless the two are kept in sync. These
tests cover the drift detection and the rewrite.
"""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import sync_whatsapp_allowlist as sync  # noqa: E402


CONFIG_YAML = """\
platforms:
  whatsapp:
    enabled: true
    extra:
      dm_policy: allowlist
      allow_admin_from:
        - '15550000001'
      allow_from:
        - '15550000002'
        - '+1 555 0000003'
"""


@pytest.fixture
def home(tmp_path):
    (tmp_path / "config.yaml").write_text(CONFIG_YAML, encoding="utf-8")
    return tmp_path


def _env(home, line):
    (home / ".env").write_text(f"SOMETHING_ELSE=keep-me\n{line}\n", encoding="utf-8")
    return sync.env_lines(home)


def test_normalize_strips_plus_spaces_and_jid_suffix():
    assert sync.normalize("+1 555 0000003") == "15550000003"
    # Uses the '@lid' form rather than the phone-JID one: this repo's gitleaks
    # rule rejects that literal even in synthetic fixtures, and normalize()
    # strips everything after '@' either way.
    assert sync.normalize("15550000002@lid") == "15550000002"


def test_expected_reads_admin_numbers_first(home):
    expected, err = sync.expected_from_config(home)
    assert err is None
    assert expected == ["15550000001", "15550000002", "15550000003"]


def test_in_sync_reports_no_problems(home):
    _, lines = _env(home, "WHATSAPP_ALLOWED_USERS=15550000001,15550000002,15550000003")
    expected, _ = sync.expected_from_config(home)
    current, allow_all, wildcard = sync.current_from_env(lines)
    assert sync.report(expected, current, allow_all, wildcard) == []


def test_missing_number_is_reported(home):
    _, lines = _env(home, "WHATSAPP_ALLOWED_USERS=15550000001,15550000002")
    expected, _ = sync.expected_from_config(home)
    current, allow_all, wildcard = sync.current_from_env(lines)
    problems = sync.report(expected, current, allow_all, wildcard)
    assert len(problems) == 1 and "15550000003" in problems[0]


def test_wildcard_is_reported_even_though_it_covers_everyone(home):
    # '*' technically "allows" every configured number, but it also allows
    # everyone else -- the config allowlist stops meaning anything.
    _, lines = _env(home, "WHATSAPP_ALLOWED_USERS=*")
    expected, _ = sync.expected_from_config(home)
    current, allow_all, wildcard = sync.current_from_env(lines)
    problems = sync.report(expected, current, allow_all, wildcard)
    assert any("*" in p for p in problems)


def test_allow_all_flag_is_reported(home):
    (home / ".env").write_text(
        "WHATSAPP_ALLOWED_USERS=15550000001,15550000002,15550000003\n"
        "WHATSAPP_ALLOW_ALL_USERS=true\n", encoding="utf-8")
    _, lines = sync.env_lines(home)
    expected, _ = sync.expected_from_config(home)
    current, allow_all, wildcard = sync.current_from_env(lines)
    assert allow_all is True
    assert any("ALLOW_ALL" in p for p in sync.report(expected, current, allow_all, wildcard))


def test_fix_rewrites_env_keeps_other_lines_and_backs_up(home):
    env_path, lines = _env(home, "WHATSAPP_ALLOWED_USERS=15550000001")
    expected, _ = sync.expected_from_config(home)
    backup = sync.write_env(env_path, lines, expected)

    written = env_path.read_text(encoding="utf-8")
    assert "WHATSAPP_ALLOWED_USERS=15550000001,15550000002,15550000003" in written
    assert "SOMETHING_ELSE=keep-me" in written        # unrelated lines survive
    assert backup.exists()                            # the old file is recoverable

    _, lines_after = sync.env_lines(home)
    current, allow_all, wildcard = sync.current_from_env(lines_after)
    assert sync.report(expected, current, allow_all, wildcard) == []


def test_fix_comments_out_allow_all(home):
    (home / ".env").write_text(
        "WHATSAPP_ALLOWED_USERS=15550000001\nWHATSAPP_ALLOW_ALL_USERS=true\n",
        encoding="utf-8")
    env_path, lines = sync.env_lines(home)
    expected, _ = sync.expected_from_config(home)
    sync.write_env(env_path, lines, expected)
    written = env_path.read_text(encoding="utf-8")
    assert "#WHATSAPP_ALLOW_ALL_USERS=true" in written
    assert "\nWHATSAPP_ALLOW_ALL_USERS=true" not in written


def test_missing_whatsapp_section_is_an_error(tmp_path):
    (tmp_path / "config.yaml").write_text("platforms: {}\n", encoding="utf-8")
    expected, err = sync.expected_from_config(tmp_path)
    assert expected is None and "platforms.whatsapp" in err
