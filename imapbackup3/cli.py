"""Command line interface"""

import argparse
import getpass
import imaplib
import logging
import os
import socket
import sys

from .imapbackup import MailBoxHandler, MailServerHandler, SkipFolderException

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("imapbackup3")


def string_from_file(value):
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

    with open(os.path.expanduser(value[1:]), "r") as content:
        return content.read().strip()


def create_folder_structure(names):
    """ Create the folder structure on disk """
    for imap_foldername, filename in sorted(names):
        disk_foldername = os.path.split(filename)[0]
        if disk_foldername:
            try:
                # print "*** mkdir:", disk_foldername  # *DEBUG
                os.mkdir(disk_foldername)
            except OSError as err:
                if err.errno != 17:
                    raise


def get_config():
    parser = argparse.ArgumentParser(
        description="Back up E-mail messages from an IMAP server. mbox files are created in the current working directory."
    )
    parser.add_argument(
        "-y",
        "--yes-overwrite-mboxes",
        action="store_true",
        help="Overwite existing mbox files instead of appending",
    )
    parser.add_argument(
        "-f", "--folder", help="Specifify which folders use.  Comma separated list."
    )
    parser.add_argument(
        "-e", "--ssl", action="store_true", help="Use SSL.  Port defaults to 993."
    )
    parser.add_argument(
        "-k",
        "--key",
        type=argparse.FileType("r"),
        help="PEM private key file for SSL.  Specify cert, too.",
    )
    parser.add_argument(
        "-c",
        "--cert",
        type=argparse.FileType("r"),
        help="PEM certificate chain for SSL.  Specify key, too.  Python's SSL module doesn't check the cert chain.",
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
        help="Prompts for password if not specified. If the first character is '@', treat the rest as a path to a file containing the password.  Leading '' makes it literal.",
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

    if not args.password:
        args.password = getpass.getpass()

    try:
        args.password = string_from_file(args.password)
    except Exception as err:
        raise ValueError("Can't read password: {}".format(err))

    return args


def _main():
    """Main entry point"""
    try:
        config = get_config()
        server = MailServerHandler(
            host=config.server,
            user=config.user,
            password=config.password,
            port=config.port,
            usessl=config.ssl,
        )
        server.connect_and_login()
        names = server.get_names()
        if config.folder:
            dirs = [x.strip() for x in config.folder.split(",")]
            if config["thunderbird"]:
                dirs = [
                    i.replace("Inbox", "INBOX", 1) if i.startswith("Inbox") else i
                    for i in dirs
                ]
            names = [x for x in names if x[0] in dirs]

        create_folder_structure(names)

        for name_pair in names:
            try:
                foldername, filename = name_pair
                fol_messages = server.scan_folder(foldername)
                box = MailBoxHandler(filename, server, foldername)
                fil_messages = box.scan_file()
                new_messages = {}
                for msg_id in list(fol_messages.keys()):
                    if msg_id not in fil_messages:
                        new_messages[msg_id] = fol_messages[msg_id]

                # for f in new_messages:
                #  print "%s : %s" % (f, new_messages[f])

                box.download_messages(new_messages)

            except SkipFolderException as err:
                logger.error(err)

        logger.info("Disconnecting")
        server.server.logout()
    except (socket.error, imaplib.IMAP4.error) as err:
        logger.error("ERROR: %s", err)
        sys.exit(5)


def main():
    """Main entry point"""
    try:
        _main()
    except KeyboardInterrupt:
        pass
