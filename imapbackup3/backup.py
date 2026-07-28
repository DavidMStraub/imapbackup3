"""Local mailbox orchestration: diffing folders and downloading messages."""

from __future__ import annotations

import email
import email.message
import email.policy
import gc
import logging
import mailbox
import os
from collections.abc import Callable
from typing import IO, Any

from .exceptions import SkipFolderException
from .transport import MailServerHandler

logger = logging.getLogger("imapbackup3")

MsgFilter = Callable[[email.message.EmailMessage], "email.message.EmailMessage | None"]


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
