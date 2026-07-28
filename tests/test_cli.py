from __future__ import annotations

from pathlib import Path

import pytest

from imapbackup3.cli import get_config, string_from_file


def test_plain_string_unchanged() -> None:
    assert string_from_file("hunter2") == "hunter2"


def test_empty_string_unchanged() -> None:
    assert string_from_file("") == ""


def test_escaped_at_is_literal() -> None:
    assert string_from_file("\\@notapath") == "@notapath"


def test_at_reads_file(tmp_path: Path) -> None:
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("s3cr3t\n")
    assert string_from_file(f"@{secret_file}") == "s3cr3t"


class TestGetConfig:
    def _run(self, monkeypatch: pytest.MonkeyPatch, argv: list[str]):
        monkeypatch.setattr(
            "sys.argv", ["imapbackup3", "-s", "host", "-u", "user", "-p", "pw", *argv]
        )
        return get_config()

    def test_default_port_no_ssl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = self._run(monkeypatch, [])
        assert config.port == 143
        assert config.ssl is False

    def test_default_port_with_ssl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = self._run(monkeypatch, ["-e"])
        assert config.port == 993
        assert config.ssl is True

    def test_explicit_port_overrides_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = self._run(monkeypatch, ["-e", "-P", "1993"])
        assert config.port == 1993

    def test_folders_split_on_comma(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = self._run(monkeypatch, ["-f", "INBOX, INBOX.Sent"])
        assert config.folders == ["INBOX", "INBOX.Sent"]

    def test_thunderbird_renames_inbox_folder(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = self._run(monkeypatch, ["-f", "Inbox,Inbox.Archive", "--thunderbird"])
        assert config.folders == ["INBOX", "INBOX.Archive"]

    def test_password_read_from_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        secret_file = tmp_path / "pw.txt"
        secret_file.write_text("s3cr3t\n")
        monkeypatch.setattr(
            "sys.argv",
            ["imapbackup3", "-s", "host", "-u", "user", "-p", f"@{secret_file}"],
        )
        config = get_config()
        assert config.password == "s3cr3t"

    def test_missing_password_prompts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["imapbackup3", "-s", "host", "-u", "user"])
        monkeypatch.setattr("getpass.getpass", lambda: "prompted-pw")
        config = get_config()
        assert config.password == "prompted-pw"
