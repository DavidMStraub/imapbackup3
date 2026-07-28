from .imapbackup import IMAPBackup, SkipFolderException

try:
    from ._version import version as __version__
except ImportError:
    __version__ = "0.0.0"

__all__ = ["IMAPBackup", "SkipFolderException", "__version__"]
