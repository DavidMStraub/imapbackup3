from .imapbackup import (
    IMAPBackup,
    IMAPCommandError,
    IMAPConnectionError,
    SkipFolderException,
)

try:
    from ._version import version as __version__
except ImportError:
    __version__ = "0.0.0"

__all__ = [
    "IMAPBackup",
    "IMAPCommandError",
    "IMAPConnectionError",
    "SkipFolderException",
    "__version__",
]
