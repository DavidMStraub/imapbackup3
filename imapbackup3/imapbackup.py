"""IMAP Incremental Backup Tool"""

# Forked from https://github.com/rcarmo/imapbackup
# Original code (C) 2006-2018 Rui Carmo. Code under MIT License.(C)

from __future__ import annotations

import email
import email.message
import email.policy
import gc
import hashlib
import imaplib
import logging
import mailbox
import os
import re
import socket
from collections.abc import Callable
from typing import IO, Any

logger = logging.getLogger("imapbackup3")

MsgFilter = Callable[[email.message.EmailMessage], "email.message.EmailMessage | None"]


class SkipFolderException(Exception):
    """Indicates aborting processing of current folder, continue with next folder."""


class IMAPConnectionError(Exception):
    """Raised when a connection to the IMAP server cannot be established."""


class IMAPCommandError(Exception):
    """Raised when an IMAP command response is not ``OK``."""


def pretty_byte_count(num: int) -> str:
    """Converts integer into a human friendly count of bytes, eg: 12.243 MB"""
    if num == 1:
        return "1 byte"
    elif num < 1024:
        return f"{num} bytes"
    elif num < 1048576:
        return "%.2f KB" % (num / 1024.0)
    elif num < 1073741824:
        return "%.3f MB" % (num / 1048576.0)
    elif num < 1099511627776:
        return "%.3f GB" % (num / 1073741824.0)
    else:
        return "%.3f TB" % (num / 1099511627776.0)


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


def parse_paren_list(row: str) -> tuple[list[Any], str]:
    """Parses the nested list of attributes at the start of a LIST response"""
    # eat starting paren
    assert row[0] == "("
    row = row[1:]

    result: list[Any] = []

    # NOTE: RFC3501 doesn't fully define the format of name attributes
    name_attrib_re = re.compile(r"^\s*(\\[a-zA-Z0-9_]+)\s*")

    # eat name attributes until ending paren
    while row[0] != ")":
        # recurse
        if row[0] == "(":
            paren_list, row = parse_paren_list(row)
            result.append(paren_list)
        # consume name attribute
        else:
            match = name_attrib_re.search(row)
            assert match is not None
            name_attrib = row[match.start() : match.end()]
            row = row[match.end() :]
            # logger.info "MATCHED '%s' '%s'" % (name_attrib, row)
            name_attrib = name_attrib.strip()
            result.append(name_attrib)

    # eat ending paren
    assert row[0] == ")"
    row = row[1:]

    # done!
    return result, row


def parse_string_list(row: str) -> list[str]:
    """Parses the quoted and unquoted strings at the end of a LIST response"""
    slist = re.compile(r'\s*(?:"([^"]+)")\s*|\s*(\S+)\s*').split(row)
    return [s for s in slist if s]


def parse_list(row: bytes | tuple[bytes, bytes] | None) -> list[Any]:
    """Prases response of LIST command into a list"""
    assert isinstance(row, bytes)
    row_str = row.strip().decode()
    paren_list, row_str = parse_paren_list(row_str)
    string_list = parse_string_list(row_str)
    assert len(string_list) == 2
    return [paren_list] + string_list


class IMAPBackup:
    """Main class to back up E-mail messages from an IMAP server."""

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
        thunderbird: bool = False,
        folders: list[str] | None = None,
        overwrite: bool = False,
        fmt: str = "mbox",
    ) -> None:
        self.mailserver = MailServerHandler(
            host=host,
            user=user,
            password=password,
            port=port,
            usessl=usessl,
            keyfilename=keyfilename,
            certfilename=certfilename,
            timeout=timeout,
        )
        self._names: list[tuple[str, str]] | None = None
        self.thunderbird = thunderbird
        self.folders = folders
        self.overwrite = overwrite
        self.fmt = fmt

    def __enter__(self) -> IMAPBackup:
        self.mailserver.login()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.mailserver.logout()

    def get_mailbox_filename(
        self, imap_foldername: str, hierarchy_delimiter: str, fmt: str
    ) -> str:
        """Get the file (or directory) name of the mailbox file (or directory)."""
        delim = hierarchy_delimiter
        suffix = ""  # no compression
        if self.fmt == "mbox":
            if self.thunderbird:
                filename = ".sbd/".join(imap_foldername.split(delim)) + suffix
                if filename.startswith("INBOX"):
                    filename = filename.replace("INBOX", "Inbox")
            else:
                filename = ".".join(imap_foldername.split(delim)) + ".mbox" + suffix
        elif self.fmt == "maildir":
            # no extension, with leading dot
            filename = "." + ".".join(imap_foldername.split(delim))
        else:
            raise ValueError(f"Mailbox format {fmt} not understood")
        return filename

    def create_folder_structure(self) -> None:
        """Create the folder structure on disk"""
        for _imap_foldername, filename in sorted(self.names):
            disk_foldername = os.path.split(filename)[0]
            if disk_foldername:
                os.makedirs(disk_foldername, exist_ok=True)

    @property
    def names(self) -> list[tuple[str, str]]:
        """Return a (cached) list of IMAP folder name and file/directory name tuples."""
        if self._names is None:
            self._names = self._get_names()
        return self._names

    def _get_names(self) -> list[tuple[str, str]]:
        """Return a list of IMAP folder name and file/directory name tuples."""
        folders = self.mailserver.get_folder_names()
        if self.folders is not None:
            folders = [f for f in folders if f in self.folders]
            # Get hierarchy delimiter
        delim = self.mailserver.get_hierarchy_delimiter()
        names = [(f, self.get_mailbox_filename(f, delim, self.fmt)) for f in folders]
        return names

    def download_message(
        self,
        mbox: mailbox.Mailbox,
        folder: str,
        num: int,
        msg_filter: MsgFilter | None = None,
        msg_id: str | None = None,
    ) -> int | None:
        """Download message no. `num` from the IMAP `folder` to the Mailbox
        instance `mbox`.

        Returns the size of the message."""

        # fetch message
        text = self.mailserver.fetch_message(folder, num)

        msg = email.message_from_string(text, policy=email.policy.default)
        if "message-id" not in msg and msg_id is not None:
            msg["message-id"] = msg_id
            text = msg.as_string()

        if msg_filter is not None:
            filtered_msg = msg_filter(msg)
            if filtered_msg is None:
                # if there is a message filter and the msg is filtered out, return
                logger.info("Skipping filtered message")
                return None
            # the filter modified the message
            text = filtered_msg.as_string()

        encoded = text.encode()
        mbox.add(encoded)

        return len(encoded)

    def download_messages(
        self,
        mbox: mailbox.Mailbox,
        folder: str,
        messages: dict[str, int],
        msg_filter: MsgFilter | None = None,
    ) -> None:
        """Download messages from folder and append to mailbox"""

        if self.overwrite:
            mbox.clear()

        if not messages:
            logger.info("New messages: 0")
            return

        mbox.lock()

        logger.info("Downloading %s new messages to %s ...", len(messages), mbox._path)

        total = biggest = 0

        try:
            # each new message
            for i, msg_id in enumerate(messages, start=1):
                size = self.download_message(
                    mbox,
                    folder,
                    messages[msg_id],
                    msg_filter=msg_filter,
                    msg_id=msg_id,
                )

                if size is None:  # msg filtered out
                    continue

                biggest = max(size, biggest)
                total += size

                logger.info(
                    "%s total, %s for largest message",
                    pretty_byte_count(total),
                    pretty_byte_count(biggest),
                )

                # periodic, not per-message, to avoid needless GC overhead
                if i % 500 == 0:
                    gc.collect()
        finally:
            # runs exactly once, whether the loop finished, raised, or was
            # interrupted (e.g. Ctrl-C, which then propagates to the caller)
            mbox.flush()
            mbox.unlock()

    def download_folder_messages(
        self,
        mbox: mailbox.Mailbox,
        foldername: str,
        msg_filter: MsgFilter | None = None,
    ) -> None:
        """Download all messages from the IMAP folder with `foldername` to the
        Mailbox instance `mbox`."""
        fol_messages = self.mailserver.scan_folder(foldername)
        fil_messages = {
            msg["message-id"].strip(): num
            for num, msg in mbox.items()
            if msg["message-id"] is not None
        }
        new_messages = {}
        for msg_id in fol_messages:
            if msg_id not in fil_messages:
                new_messages[msg_id] = fol_messages[msg_id]

        self.download_messages(mbox, foldername, new_messages, msg_filter=msg_filter)

    def download_all_messages(self, msg_filter: MsgFilter | None = None) -> None:
        """Download all messages to a new mailbox with format `fmt`."""
        self.create_folder_structure()
        for name_pair in self.names:
            try:
                foldername, filename = name_pair
                mbox: mailbox.Mailbox
                if self.fmt == "mbox":
                    mbox = mailbox.mbox(
                        filename,
                        factory=email_message_factory,  # type: ignore[arg-type]
                    )
                elif self.fmt == "maildir":
                    mbox = mailbox.Maildir(
                        filename,
                        factory=email_message_factory,  # type: ignore[arg-type]
                    )
                else:
                    raise ValueError(f"Mailbox format {self.fmt} not understood")
                self.download_folder_messages(mbox, foldername, msg_filter=msg_filter)

            except SkipFolderException as err:
                logger.error(err)


def email_message_factory(f: IO[bytes]) -> email.message.EmailMessage:
    """Factory to create EmailMessage objects instead of Message objects"""
    return email.message_from_binary_file(f, policy=email.policy.default)
