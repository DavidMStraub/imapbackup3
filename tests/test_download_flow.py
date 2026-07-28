"""Integration-style tests for folder diffing and the full download flow,
using real mailbox.mbox files on disk against a mocked IMAP server."""

from __future__ import annotations

import mailbox
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from imapbackup3.backup import IMAPBackup, email_message_factory
from imapbackup3.exceptions import SkipFolderException


def _make_backup() -> IMAPBackup:
    imb = IMAPBackup(host="localhost", user="user", password="pw")
    imb.mailserver = MagicMock()
    return imb


class TestDownloadFolderMessages:
    def test_skips_messages_already_present(self, tmp_path: Path) -> None:
        imb = _make_backup()
        mbox_path = tmp_path / "INBOX.mbox"
        mbox = mailbox.mbox(str(mbox_path), factory=email_message_factory)
        mbox.lock()
        mbox.add(b"Message-Id: <existing@x.com>\r\nSubject: old\r\n\r\nbody")
        mbox.flush()
        mbox.unlock()

        imb.mailserver.scan_folder.return_value = {
            "<existing@x.com>": 1,
            "<new@x.com>": 2,
        }
        imb.mailserver.fetch_message.return_value = (
            "Message-Id: <new@x.com>\r\nSubject: new\r\n\r\nbody"
        )

        imb.download_folder_messages(mbox, "INBOX")

        mbox.close()
        reopened = mailbox.mbox(str(mbox_path), factory=email_message_factory)
        message_ids = {msg["message-id"] for msg in reopened.values()}
        assert message_ids == {"<existing@x.com>", "<new@x.com>"}
        # fetch_message should only be called for the genuinely new message
        imb.mailserver.fetch_message.assert_called_once_with("INBOX", 2)

    def test_local_message_without_message_id_does_not_crash(
        self, tmp_path: Path
    ) -> None:
        """Regression test: a pre-existing local message with no Message-Id
        header used to raise AttributeError (None.strip()) on every backup
        of that folder."""
        imb = _make_backup()
        mbox_path = tmp_path / "INBOX.mbox"
        mbox = mailbox.mbox(str(mbox_path), factory=email_message_factory)
        mbox.lock()
        mbox.add(b"Subject: no message id here\r\n\r\nbody")
        mbox.flush()
        mbox.unlock()

        imb.mailserver.scan_folder.return_value = {"<new@x.com>": 1}
        imb.mailserver.fetch_message.return_value = (
            "Message-Id: <new@x.com>\r\nSubject: new\r\n\r\nbody"
        )

        imb.download_folder_messages(mbox, "INBOX")

        mbox.close()
        reopened = mailbox.mbox(str(mbox_path), factory=email_message_factory)
        assert len(list(reopened.values())) == 2


class TestDownloadAllMessages:
    def test_downloads_across_multiple_folders(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        imb = _make_backup()
        imb._names = [("INBOX", "INBOX.mbox"), ("INBOX.Sent", "INBOX.Sent.mbox")]

        def scan_folder(folder: str):
            return {f"<{folder}@x.com>": 1}

        imb.mailserver.scan_folder.side_effect = scan_folder
        imb.mailserver.fetch_message.side_effect = lambda folder, num: (
            f"Message-Id: <{folder}@x.com>\r\n\r\nbody"
        )

        imb.download_all_messages()

        assert (tmp_path / "INBOX.mbox").exists()
        assert (tmp_path / "INBOX.Sent.mbox").exists()

    def test_skip_folder_exception_does_not_abort_remaining_folders(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        imb = _make_backup()
        imb._names = [("Broken", "Broken.mbox"), ("OK", "OK.mbox")]

        def scan_folder(folder: str):
            if folder == "Broken":
                raise SkipFolderException("boom")
            return {"<ok@x.com>": 1}

        imb.mailserver.scan_folder.side_effect = scan_folder
        imb.mailserver.fetch_message.return_value = "Message-Id: <ok@x.com>\r\n\r\nbody"

        imb.download_all_messages()

        assert (tmp_path / "OK.mbox").exists()

    def test_thunderbird_nested_folder_parent_dir_is_created(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Regression test: thunderbird-format filenames can contain a `/`
        (e.g. "Inbox.sbd/Sent"); mailbox.mbox() does not create missing
        parent directories itself, so this used to raise FileNotFoundError."""
        monkeypatch.chdir(tmp_path)
        imb = _make_backup()
        imb.thunderbird = True
        imb.fmt = "mbox"
        imb._names = [("INBOX.Sent", "Inbox.sbd/Sent")]

        imb.mailserver.scan_folder.return_value = {"<sent@x.com>": 1}
        imb.mailserver.fetch_message.return_value = (
            "Message-Id: <sent@x.com>\r\n\r\nbody"
        )

        imb.download_all_messages()

        assert (tmp_path / "Inbox.sbd" / "Sent").exists()


class TestDownloadMessages:
    def test_keyboard_interrupt_propagates_and_unlocks_exactly_once(
        self, tmp_path: Path
    ) -> None:
        """Regression test: Ctrl-C used to be swallowed inside the download
        loop (no break/raise), which kept downloading and then called
        mbox.unlock() a second time on an already-unlocked mailbox."""
        imb = _make_backup()
        mbox_path = tmp_path / "INBOX.mbox"
        mbox = mailbox.mbox(str(mbox_path), factory=email_message_factory)

        def fetch_message(folder: str, num: int):
            raise KeyboardInterrupt

        imb.mailserver.fetch_message.side_effect = fetch_message

        with pytest.raises(KeyboardInterrupt):
            imb.download_messages(mbox, "INBOX", {"<a@x.com>": 1})

        # unlock() raises if called while not locked; if this returns
        # cleanly, download_messages left the mailbox unlocked exactly once.
        mbox.lock()
        mbox.unlock()

    def test_download_message_size_matches_actual_bytes_written(
        self, tmp_path: Path
    ) -> None:
        """Regression test: size used to come from sys.getsizeof(str), which
        reflects interpreter object overhead, not the bytes actually
        written to the mailbox."""
        imb = _make_backup()
        mbox_path = tmp_path / "INBOX.mbox"
        mbox = mailbox.mbox(str(mbox_path), factory=email_message_factory)
        mbox.lock()

        text = "Message-Id: <a@x.com>\r\nSubject: hi\r\n\r\nbody"
        imb.mailserver.fetch_message.return_value = text

        size = imb.download_message(mbox, "INBOX", 1, msg_id="<a@x.com>")

        mbox.flush()
        mbox.unlock()
        assert size == len(text.encode())
