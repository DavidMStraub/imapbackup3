"""Integration-style tests for folder diffing and the full download flow,
using real mailbox.mbox files on disk against a mocked IMAP server."""

from __future__ import annotations

import mailbox
from pathlib import Path
from unittest.mock import MagicMock

from imapbackup3.imapbackup import (
    IMAPBackup,
    SkipFolderException,
    email_message_factory,
)


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
