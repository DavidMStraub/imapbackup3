"""Exceptions raised by imapbackup3."""

from __future__ import annotations


class SkipFolderException(Exception):
    """Indicates aborting processing of current folder, continue with next folder."""


class IMAPConnectionError(Exception):
    """Raised when a connection to the IMAP server cannot be established."""


class IMAPCommandError(Exception):
    """Raised when an IMAP command response is not ``OK``."""
