"""Tests for the pure parsing/formatting helpers and IMAPBackup logic."""

from __future__ import annotations

import mailbox
from unittest.mock import MagicMock

import pytest

from imapbackup3.imapbackup import (
    IMAPBackup,
    MailServerHandler,
    parse_list,
    parse_paren_list,
    parse_string_list,
    pretty_byte_count,
)


class TestPrettyByteCount:
    def test_one_byte(self) -> None:
        assert pretty_byte_count(1) == "1 byte"

    def test_bytes(self) -> None:
        assert pretty_byte_count(500) == "500 bytes"

    def test_kilobytes(self) -> None:
        assert pretty_byte_count(2048) == "2.00 KB"

    def test_megabytes(self) -> None:
        assert pretty_byte_count(2 * 1048576) == "2.000 MB"

    def test_gigabytes(self) -> None:
        assert pretty_byte_count(2 * 1073741824) == "2.000 GB"

    def test_terabytes(self) -> None:
        assert pretty_byte_count(2 * 1099511627776) == "2.000 TB"


class TestParsing:
    def test_parse_paren_list_flat(self) -> None:
        result, rest = parse_paren_list(r"(\HasNoChildren) ")
        assert result == [r"\HasNoChildren"]
        assert rest == " "

    def test_parse_paren_list_multiple(self) -> None:
        result, rest = parse_paren_list(r"(\Noselect \HasChildren) rest")
        assert result == [r"\Noselect", r"\HasChildren"]
        assert rest == " rest"

    def test_parse_string_list_quoted(self) -> None:
        assert parse_string_list(' "." "INBOX.Sent"') == [".", "INBOX.Sent"]

    def test_parse_string_list_unquoted_root(self) -> None:
        assert parse_string_list(' "." INBOX') == [".", "INBOX"]

    def test_parse_list(self) -> None:
        row = rb'(\HasNoChildren) "." "INBOX"'
        assert parse_list(row) == [[r"\HasNoChildren"], ".", "INBOX"]


class TestGetMailboxFilename:
    def _make_backup(self, fmt: str = "mbox", thunderbird: bool = False) -> IMAPBackup:
        return IMAPBackup(
            host="localhost",
            user="user",
            password="pw",
            fmt=fmt,
            thunderbird=thunderbird,
        )

    def test_mbox(self) -> None:
        imb = self._make_backup(fmt="mbox")
        assert imb.get_mailbox_filename("INBOX.Sent", ".", "mbox") == "INBOX.Sent.mbox"

    def test_maildir(self) -> None:
        imb = self._make_backup(fmt="maildir")
        assert imb.get_mailbox_filename("INBOX.Sent", ".", "maildir") == ".INBOX.Sent"

    def test_thunderbird(self) -> None:
        imb = self._make_backup(fmt="mbox", thunderbird=True)
        filename = imb.get_mailbox_filename("INBOX.Sent", ".", "mbox")
        assert filename == "Inbox.sbd/Sent"

    def test_unknown_format(self) -> None:
        imb = self._make_backup(fmt="bogus")
        with pytest.raises(ValueError):
            imb.get_mailbox_filename("INBOX", ".", "bogus")


class TestDownloadMessages:
    def test_no_new_messages_is_noop(self) -> None:
        imb = IMAPBackup(host="localhost", user="user", password="pw")
        imb.mailserver = MagicMock(spec=MailServerHandler)
        mbox = MagicMock(spec=mailbox.mbox)

        imb.download_messages(mbox, "INBOX", {})

        mbox.lock.assert_not_called()
        mbox.add.assert_not_called()

    def test_downloads_and_stores_message(self) -> None:
        imb = IMAPBackup(host="localhost", user="user", password="pw")
        imb.mailserver = MagicMock(spec=MailServerHandler)
        imb.mailserver.fetch_message.return_value = (
            "Message-Id: <abc@example.com>\r\nSubject: hi\r\n\r\nbody"
        )
        mbox = MagicMock(spec=mailbox.mbox)
        mbox._path = "INBOX.mbox"

        imb.download_messages(mbox, "INBOX", {"<abc@example.com>": 1})

        mbox.lock.assert_called_once()
        mbox.add.assert_called_once()
        mbox.flush.assert_called_once()
        mbox.unlock.assert_called_once()

    def test_msg_filter_can_drop_message(self) -> None:
        imb = IMAPBackup(host="localhost", user="user", password="pw")
        imb.mailserver = MagicMock(spec=MailServerHandler)
        imb.mailserver.fetch_message.return_value = (
            "Message-Id: <abc@example.com>\r\nSubject: SPAM\r\n\r\nbody"
        )
        mbox = MagicMock(spec=mailbox.mbox)
        mbox._path = "INBOX.mbox"

        imb.download_messages(
            mbox,
            "INBOX",
            {"<abc@example.com>": 1},
            msg_filter=lambda msg: None,
        )

        mbox.add.assert_not_called()


class TestNamesCaching:
    def test_empty_folder_list_is_still_cached(self) -> None:
        """Regression test: `if not self._names` treated an empty (but
        successfully fetched) folder list as "not yet cached", so it kept
        re-querying the IMAP server on every access."""
        imb = IMAPBackup(host="localhost", user="user", password="pw")
        imb.mailserver = MagicMock(spec=MailServerHandler)
        imb.mailserver.get_folder_names.return_value = []
        imb.mailserver.get_hierarchy_delimiter.return_value = "."

        assert imb.names == []
        assert imb.names == []

        imb.mailserver.get_folder_names.assert_called_once()

    def test_nonempty_folder_list_is_cached(self) -> None:
        imb = IMAPBackup(host="localhost", user="user", password="pw")
        imb.mailserver = MagicMock(spec=MailServerHandler)
        imb.mailserver.get_folder_names.return_value = ["INBOX"]
        imb.mailserver.get_hierarchy_delimiter.return_value = "."

        assert imb.names == [("INBOX", "INBOX.mbox")]
        assert imb.names == [("INBOX", "INBOX.mbox")]

        imb.mailserver.get_folder_names.assert_called_once()
