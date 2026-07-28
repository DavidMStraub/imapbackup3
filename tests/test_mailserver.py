"""Tests for MailServerHandler: login, folder scanning, folder listing."""

from __future__ import annotations

import imaplib
import socket
from unittest.mock import MagicMock

import pytest

from imapbackup3.imapbackup import (
    IMAPCommandError,
    IMAPConnectionError,
    MailServerHandler,
    SkipFolderException,
    _quote_mailbox,
)


def _make_handler(**kwargs) -> MailServerHandler:
    defaults = dict(host="localhost", user="user", password="pw")
    defaults.update(kwargs)
    return MailServerHandler(**defaults)


class TestLogin:
    def test_ssl_login_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_server = MagicMock()
        fake_server.sock = MagicMock()
        ssl_ctor = MagicMock(return_value=fake_server)
        monkeypatch.setattr(imaplib, "IMAP4_SSL", ssl_ctor)

        handler = _make_handler(usessl=True)
        server = handler.login()

        ssl_ctor.assert_called_once_with("localhost", 993, timeout=None)
        fake_server.login.assert_called_once_with("user", "pw")
        assert server is fake_server

    def test_plain_login_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_server = MagicMock()
        fake_server.sock = MagicMock()
        ctor = MagicMock(return_value=fake_server)
        monkeypatch.setattr(imaplib, "IMAP4", ctor)

        handler = _make_handler(usessl=False, port=143)
        handler.login()

        ctor.assert_called_once_with("localhost", 143, timeout=None)
        fake_server.login.assert_called_once_with("user", "pw")

    def test_login_with_key_and_cert(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_server = MagicMock()
        fake_server.sock = MagicMock()
        ssl_ctor = MagicMock(return_value=fake_server)
        monkeypatch.setattr(imaplib, "IMAP4_SSL", ssl_ctor)

        handler = _make_handler(
            usessl=True, keyfilename="key.pem", certfilename="cert.pem"
        )
        handler.login()

        ssl_ctor.assert_called_once_with(
            "localhost", 993, "key.pem", "cert.pem", timeout=None
        )

    def test_timeout_passed_to_constructor_not_global_socket(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression test: login() must not call socket.setdefaulttimeout(),
        which would leak into unrelated sockets in the same process."""
        fake_server = MagicMock()
        fake_server.sock = MagicMock()
        ssl_ctor = MagicMock(return_value=fake_server)
        monkeypatch.setattr(imaplib, "IMAP4_SSL", ssl_ctor)
        set_default_timeout = MagicMock()
        monkeypatch.setattr(socket, "setdefaulttimeout", set_default_timeout)

        handler = _make_handler(usessl=True, timeout=30)
        handler.login()

        ssl_ctor.assert_called_once_with("localhost", 993, timeout=30)
        set_default_timeout.assert_not_called()

    def test_gaierror_raises_connection_error_not_sys_exit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression test: login() must raise a catchable exception so the
        package remains usable as a library, not call sys.exit()."""

        def raise_gaierror(*args, **kwargs):
            raise socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(imaplib, "IMAP4_SSL", raise_gaierror)

        handler = _make_handler(usessl=True)
        with pytest.raises(IMAPConnectionError):
            handler.login()

    def test_socket_error_raises_connection_error_not_sys_exit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def raise_oserror(*args, **kwargs):
            raise OSError("could not connect")

        monkeypatch.setattr(imaplib, "IMAP4_SSL", raise_oserror)

        handler = _make_handler(usessl=True)
        with pytest.raises(IMAPConnectionError):
            handler.login()


class TestRequireLogin:
    def test_logs_in_lazily_and_only_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_server = MagicMock()
        fake_server.sock = MagicMock()
        fake_server.list.return_value = ("OK", [])
        monkeypatch.setattr(imaplib, "IMAP4_SSL", MagicMock(return_value=fake_server))

        handler = _make_handler(usessl=True)
        assert handler.logged_in is False

        handler.get_folder_names()
        assert handler.logged_in is True
        fake_server.list.assert_called_once()

        # second call should not trigger another login
        handler.get_folder_names()
        assert fake_server.login.call_count == 1


class TestScanFolder:
    def _handler_with_server(self) -> tuple[MailServerHandler, MagicMock]:
        handler = _make_handler()
        handler.server = MagicMock()
        handler.logged_in = True
        return handler, handler.server

    def test_reads_message_ids(self) -> None:
        handler, server = self._handler_with_server()
        server.select.return_value = ("OK", [b"1"])
        server.fetch.return_value = (
            "OK",
            [(b"1 (BODY[...] {10})", b"Message-Id: <a@x.com>\r\n\r\n")],
        )

        messages = handler.scan_folder("INBOX")

        assert messages == {"<a@x.com>": 1}

    def test_deduplicates_message_ids(self) -> None:
        handler, server = self._handler_with_server()
        server.select.return_value = ("OK", [b"2"])
        server.fetch.return_value = (
            "OK",
            [(b"1 (...)", b"Message-Id: <dupe@x.com>\r\n\r\n")],
        )

        messages = handler.scan_folder("INBOX")

        # both message 1 and 2 report the same id; only the first is kept
        assert messages == {"<dupe@x.com>": 1}

    def test_synthesizes_id_when_missing(self) -> None:
        handler, server = self._handler_with_server()
        server.select.return_value = ("OK", [b"1"])

        def fetch(num: str, spec: str):
            if "MESSAGE-ID" in spec:
                return ("OK", [(b"1 (...)", b"\r\n\r\n")])
            return ("OK", [(b"1 (...)", b"From: a@b.com\r\nSubject: hi\r\n")])

        server.fetch.side_effect = fetch

        messages = handler.scan_folder("INBOX")

        assert len(messages) == 1
        (synthesized_id,) = messages.keys()
        assert synthesized_id.startswith("<19AF1258-1AAF-44EF-9D9A-731079D6FAD7.")

    def test_select_failure_raises_skip_folder(self) -> None:
        handler, server = self._handler_with_server()
        server.select.return_value = ("NO", [b"folder does not exist"])

        with pytest.raises(SkipFolderException):
            handler.scan_folder("Missing")

    def test_folder_name_with_quote_is_escaped_in_select(self) -> None:
        """Regression test: a folder name containing a `"` used to be spliced
        unescaped into the IMAP command string, breaking its syntax."""
        handler, server = self._handler_with_server()
        server.select.return_value = ("OK", [b"0"])

        handler.scan_folder('Weird"Folder')

        server.select.assert_called_once_with('"Weird\\"Folder"', readonly=True)


class TestQuoteMailbox:
    def test_plain_name_is_just_quoted(self) -> None:
        assert _quote_mailbox("INBOX.Sent") == '"INBOX.Sent"'

    def test_double_quote_is_escaped(self) -> None:
        assert _quote_mailbox('Weird"Folder') == '"Weird\\"Folder"'

    def test_backslash_is_escaped(self) -> None:
        assert _quote_mailbox("Weird\\Folder") == '"Weird\\\\Folder"'


class TestFetchMessage:
    def test_returns_decoded_text(self) -> None:
        handler = _make_handler()
        handler.server = MagicMock()
        handler.logged_in = True
        handler.server.fetch.return_value = (
            "OK",
            [(b"1 (RFC822 {20})", b"Subject: hi\r\n\r\nbody")],
        )

        text = handler.fetch_message("INBOX", 1)

        assert text == "Subject: hi\n\nbody"

    def test_non_ok_raises_command_error_not_assertion_error(self) -> None:
        """Regression test: a non-OK FETCH must raise a real exception, not
        rely on a bare `assert` that is stripped when running under -O."""
        handler = _make_handler()
        handler.server = MagicMock()
        handler.logged_in = True
        handler.server.fetch.return_value = ("NO", [b"server busy"])

        with pytest.raises(IMAPCommandError):
            handler.fetch_message("INBOX", 1)


class TestGetFolderNames:
    def test_parses_folder_names(self) -> None:
        handler = _make_handler()
        handler.server = MagicMock()
        handler.logged_in = True
        handler.server.list.return_value = (
            "OK",
            [
                rb'(\HasNoChildren) "." "INBOX"',
                rb'(\HasChildren) "." "INBOX.Sent"',
            ],
        )

        names = handler.get_folder_names()

        assert names == ["INBOX", "INBOX.Sent"]

    def test_non_ok_raises_command_error(self) -> None:
        handler = _make_handler()
        handler.server = MagicMock()
        handler.logged_in = True
        handler.server.list.return_value = ("NO", [b"unavailable"])

        with pytest.raises(IMAPCommandError):
            handler.get_folder_names()


class TestGetHierarchyDelimiter:
    def test_extracts_delimiter(self) -> None:
        handler = _make_handler()
        handler.server = MagicMock()
        handler.logged_in = True
        handler.server.list.return_value = ("OK", [rb'(\HasNoChildren) "." "INBOX"'])

        assert handler.get_hierarchy_delimiter() == "."

    def test_nil_delimiter_defaults_to_dot(self) -> None:
        handler = _make_handler()
        handler.server = MagicMock()
        handler.logged_in = True
        handler.server.list.return_value = ("OK", [rb'(\Noselect) NIL "INBOX"'])

        assert handler.get_hierarchy_delimiter() == "."

    def test_non_ok_raises_command_error(self) -> None:
        handler = _make_handler()
        handler.server = MagicMock()
        handler.logged_in = True
        handler.server.list.return_value = ("NO", [b"unavailable"])

        with pytest.raises(IMAPCommandError):
            handler.get_hierarchy_delimiter()
