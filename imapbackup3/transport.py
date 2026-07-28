"""IMAP transport: connecting to and reading from an IMAP server."""

from __future__ import annotations

import hashlib
import imaplib
import logging
import re
import socket
from collections.abc import Callable
from typing import Any

from .exceptions import IMAPCommandError, IMAPConnectionError, SkipFolderException
from .parsing import parse_list

logger = logging.getLogger("imapbackup3")

# Regular expressions for parsing
MSGID_RE = re.compile(r"^Message\-Id\: (.+)", re.IGNORECASE + re.MULTILINE)
BLANKS_RE = re.compile(r"\s+", re.MULTILINE)

# Constants
UUID = "19AF1258-1AAF-44EF-9D9A-731079D6FAD7"  # Used to generate Message-Ids


def _fetch_payload(item: bytes | tuple[bytes, bytes] | None) -> bytes:
    """Extract the message payload from one element of an IMAP FETCH response."""
    assert isinstance(item, tuple)
    return item[1]


def _quote_mailbox(name: str) -> str:
    """Quote a mailbox name as an IMAP quoted-string (RFC 3501 section 4.3),
    escaping any backslash or double-quote it contains."""
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def require_login(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator for methods that require login."""

    def wrapper(instance: MailServerHandler, *args: Any, **kwargs: Any) -> Any:
        if not instance.logged_in:
            instance.login()
            instance.logged_in = True
        return f(instance, *args, **kwargs)

    return wrapper


class MailServerHandler:
    """Handle the connection to and reading from an IMAP server."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        port: int = 993,
        usessl: bool = True,
        keyfilename: str | None = None,
        certfilename: str | None = None,
        timeout: int | None = None,
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.usessl = usessl
        self.keyfilename = keyfilename
        self.certfilename = certfilename
        self.timeout = timeout
        self.server: imaplib.IMAP4 | None = None
        self.logged_in: bool = False

    def logout(self) -> None:
        if self.logged_in and self.server is not None:
            self.server.logout()

    @require_login
    def fetch_message(self, folder: str, num: int) -> str:
        """Fetch the message number `num` for the IMAP folder `folder`.

        Returns a string."""
        assert self.server is not None
        self.server.select(_quote_mailbox(folder), readonly=True)
        typ, data = self.server.fetch(str(num), "RFC822")
        if typ != "OK":
            raise IMAPCommandError(f"FETCH {num} in folder {folder!r} failed: {data}")
        raw = _fetch_payload(data[0])
        text: str | None = None
        for encoding in ["utf-8", "latin1"]:
            try:
                text = raw.decode(encoding)
            except UnicodeDecodeError:
                text = None
        if text is None:
            text = raw.decode("utf-8", "backslashreplace")
        text = text.strip().replace("\r", "")
        return text

    def login(self) -> imaplib.IMAP4:
        """Connects to the server and logs in.

        Returns IMAP4 object.

        Raises `IMAPConnectionError` if the connection cannot be established."""
        try:
            if self.usessl and self.keyfilename:
                logger.info(
                    "Connecting to '%s' TCP port %d, SSL, key from %s, cert from %s",
                    self.host,
                    self.port,
                    self.keyfilename,
                    self.certfilename,
                )
                server: imaplib.IMAP4 = imaplib.IMAP4_SSL(
                    self.host,
                    self.port,
                    self.keyfilename,
                    self.certfilename,
                    timeout=self.timeout,
                )
            elif self.usessl:
                logger.info("Connecting to '%s' TCP port %d, SSL", self.host, self.port)
                server = imaplib.IMAP4_SSL(self.host, self.port, timeout=self.timeout)
            else:
                logger.info("Connecting to '%s' TCP port %d", self.host, self.port)
                server = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)

            # speed up interactions on TCP connections using small packets
            server.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            logger.info("Logging in as '%s'", (self.user))
            server.login(self.user, self.password)
        except socket.gaierror as err:
            (err_no, desc) = err.args
            raise IMAPConnectionError(
                f"Problem looking up server '{self.host}' ({err_no} {desc})"
            ) from err
        except OSError as err:
            if str(err) == "SSL_CTX_use_PrivateKey_file error":
                message = f"Error reading private key file '{self.keyfilename}'"
            elif str(err) == "SSL_CTX_use_certificate_chain_file error":
                message = f"Error reading certificate chain file '{self.keyfilename}'"
            else:
                message = f"Could not connect to '{self.host}' ({err})"
            raise IMAPConnectionError(message) from err

        self.server = server
        return server

    @require_login
    def scan_folder(self, foldername: str) -> dict[str, int]:
        """Gets IDs of messages in the specified folder, returns id:num dict"""
        assert self.server is not None
        messages: dict[str, int] = {}
        logger.info("Folder %s ...", foldername)

        typ, list_data = self.server.select(_quote_mailbox(foldername), readonly=True)
        if typ != "OK":
            raise SkipFolderException(f"SELECT failed: {list_data}")
        num_msgs_raw = list_data[0]
        assert num_msgs_raw is not None
        num_msgs = int(num_msgs_raw)

        # each message
        for num in range(1, num_msgs + 1):
            # Retrieve Message-Id, making sure we don't mark all messages as read
            typ, fetch_data = self.server.fetch(
                str(num), "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])"
            )
            if typ != "OK" or not fetch_data[0]:
                raise SkipFolderException(f"FETCH {num} failed: {fetch_data}")
            header = _fetch_payload(fetch_data[0]).strip()
            # remove newlines inside Message-Id (a dumb Exchange trait)
            header_str = BLANKS_RE.sub(" ", header.decode())
            match = MSGID_RE.match(header_str)
            try:
                msg_id = match.group(1)  # type: ignore[union-attr]
                if msg_id not in messages:
                    # avoid adding dupes
                    messages[msg_id] = num
            except (IndexError, AttributeError):
                # Some messages may have no Message-Id, so we'll synthesise one
                # (this usually happens with Sent, Drafts and .Mac news)
                typ, fetch_data = self.server.fetch(
                    str(num), "(BODY[HEADER.FIELDS (FROM TO CC DATE SUBJECT)])"
                )
                if typ != "OK":
                    raise SkipFolderException(
                        f"FETCH {num} failed: {fetch_data}"
                    ) from None
                header_str = _fetch_payload(fetch_data[0]).decode().strip()
                header_str = header_str.replace("\r\n", "\t")
                messages[
                    "<"
                    + UUID
                    + "."
                    + hashlib.sha1(header_str.encode()).hexdigest()
                    + ">"
                ] = num

        # done
        logger.info("Found %d messages", len(messages))
        return messages

    @require_login
    def get_hierarchy_delimiter(self) -> str:
        """Queries the imapd for the hierarchy delimiter, eg. '.' in INBOX.Sent"""
        # see RFC 3501 page 39 paragraph 4
        assert self.server is not None
        typ, data = self.server.list()
        if typ != "OK":
            raise IMAPCommandError(f"LIST failed: {data}")
        lst = parse_list(data[0])  # [attribs, hierarchy delimiter, root name]
        hierarchy_delim = lst[1]
        # NIL if there is no hierarchy
        if hierarchy_delim == "NIL":
            hierarchy_delim = "."
        return hierarchy_delim

    @require_login
    def get_folder_names(self) -> list[str]:
        """Get list of folders"""
        assert self.server is not None

        logger.info("Finding Folders ...")

        # Get LIST of all folders
        typ, data = self.server.list()
        if typ != "OK":
            raise IMAPCommandError(f"LIST failed: {data}")

        names = []

        # parse each LIST, find folder name
        for row in data:
            lst = parse_list(row)
            foldername = lst[2]
            names.append(foldername)

        # done

        logger.info("Found %s folders", len(names))
        return names
