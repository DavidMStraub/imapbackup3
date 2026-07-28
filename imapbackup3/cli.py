"""Command line interface"""

from __future__ import annotations

import argparse
import getpass
import imaplib
import logging
import os
import sys

from .backup import IMAPBackup
from .exceptions import IMAPCommandError, IMAPConnectionError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("imapbackup3")


def string_from_file(value: str) -> str:
    """
    Read a string from a file or return the string unchanged.

    If the string begins with '@', the remainder of the string
    will be treated as a path to the file to be read.  Precede
    the '@' with a '\' to treat it as a literal.
    """

    assert isinstance(value, str)

    if not value or value[0] not in ["\\", "@"]:
        return value

    if value[0] == "\\":
        return value[1:]

    with open(os.path.expanduser(value[1:])) as content:
        return content.read().strip()


def get_config() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Back up E-mail messages from an IMAP server. mbox files are created in the current working directory."  # noqa: E501
    )
    parser.add_argument(
        "-y",
        "--yes-overwrite-mboxes",
        action="store_true",
        help="Overwite existing mbox files instead of appending",
    )
    parser.add_argument(
        "-f", "--folders", help="Specifify which folders use.  Comma separated list."
    )
    parser.add_argument(
        "-e", "--ssl", action="store_true", help="Use SSL.  Port defaults to 993."
    )
    parser.add_argument(
        "-k",
        "--key",
        help="Path to PEM private key file for SSL.  Specify cert, too.",
    )
    parser.add_argument(
        "-c",
        "--cert",
        help="Path to PEM certificate chain for SSL.  Specify key, too.  Python's SSL module doesn't check the cert chain.",  # noqa: E501
    )
    parser.add_argument(
        "-s",
        "--server",
        required=True,
        metavar="HOST",
        help="Address of server (without port)",
    )
    parser.add_argument(
        "-P",
        "--port",
        type=int,
        help="Server port (defaults to 143 without and 993 with SSL)",
    )
    parser.add_argument(
        "-u", "--user", required=True, help="Username to log into server"
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Prompts for password if not specified. If the first character is '@', treat the rest as a path to a file containing the password.  Leading '' makes it literal.",  # noqa: E501
    )
    parser.add_argument(
        "-m",
        "--mailbox",
        default="mbox",
        help="Local e-mail storage format. Possible values: mbox (default), Maildir",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        metavar="SECS",
        type=int,
        help="Sets socket timeout to SECS seconds.",
    )
    parser.add_argument(
        "--thunderbird",
        action="store_true",
        help="Create Mozilla Thunderbird compatible mailbox",
    )

    args = parser.parse_args()
    if not args.port:
        if not args.ssl:
            args.port = 143
        else:
            args.port = 993

    if args.folders:
        args.folders = [x.strip() for x in args.folders.split(",")]
        if args.thunderbird:
            args.folders = [
                x.replace("Inbox", "INBOX", 1) if x.startswith("Inbox") else x
                for x in args.folders
            ]

    if not args.password:
        args.password = getpass.getpass()

    try:
        args.password = string_from_file(args.password)
    except Exception as err:
        raise ValueError(f"Can't read password: {err}") from err

    return args


def main() -> None:
    """Main entry point"""
    try:
        config = get_config()
        with IMAPBackup(
            host=config.server,
            user=config.user,
            password=config.password,
            port=config.port,
            usessl=config.ssl,
            keyfilename=config.key,
            certfilename=config.cert,
            thunderbird=config.thunderbird,
            folders=config.folders,
            fmt=config.mailbox,
        ) as imb:
            imb.download_all_messages()
    except KeyboardInterrupt:
        sys.exit(0)
    except (OSError, imaplib.IMAP4.error, IMAPConnectionError, IMAPCommandError) as err:
        logger.error("ERROR: %s", err)
        sys.exit(5)
