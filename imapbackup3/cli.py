"""Command line interface"""

import getopt
import getpass
import imaplib
import logging
import os
import socket
import sys

from .imapbackup import MailBoxHandler, MailServerHandler, SkipFolderException

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('imapbackup3')


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


def print_usage():
    """Prints usage, exits"""
    #     "                                                                               "
    print("Usage: imapbackup [OPTIONS] -s HOST -u USERNAME [-p PASSWORD]")
    print(" -a --append-to-mboxes     Append new messages to mbox files. (default)")
    print(
        " -y --yes-overwrite-mboxes Overwite existing mbox files instead of appending."
    )
    print(
        " -n --compress=none        Use one plain mbox file for each folder. (default)"
    )
    print(" -z --compress=gzip        Use mbox.gz files.  Appending may be very slow.")
    print(
        " -b --compress=bzip2       Use mbox.bz2 files. Appending not supported: use -y."
    )
    print(
        " -f --=folder              Specifify which folders use.  Comma separated list."
    )
    print(" -e --ssl                  Use SSL.  Port defaults to 993.")
    print(
        " -k KEY --key=KEY          PEM private key file for SSL.  Specify cert, too."
    )
    print(
        " -c CERT --cert=CERT       PEM certificate chain for SSL.  Specify key, too."
    )
    print(
        "                           Python's SSL module doesn't check the cert chain."
    )
    print(
        " -s HOST --server=HOST     Address of server, port optional, eg. mail.com:143"
    )
    print(" -u USER --user=USER       Username to log into server")
    print(
        " -p PASS --pass=PASS       Prompts for password if not specified.  If the first"
    )
    print(
        "                           character is '@', treat the rest as a path to a file"
    )
    print(
        "                           containing the password.  Leading '' makes it literal."
    )
    print(" -t SECS --timeout=SECS    Sets socket timeout to SECS seconds.")
    print(" --thunderbird             Create Mozilla Thunderbird compatible mailbox")
    print(" --nospinner               Disable spinner (makes output log-friendly)")
    print("\nNOTE: mbox files are created in the current working directory.")
    sys.exit(2)


def process_cline():
    """Uses getopt to process command line, returns (config, warnings, errors)"""
    # read command line
    try:
        short_args = "aynzbekt:c:s:u:p:f:"
        long_args = [
            "append-to-mboxes",
            "yes-overwrite-mboxes",
            "compress=",
            "ssl",
            "timeout",
            "keyfile=",
            "certfile=",
            "server=",
            "user=",
            "pass=",
            "folders=",
            "thunderbird",
            "nospinner",
        ]
        opts, extraargs = getopt.getopt(sys.argv[1:], short_args, long_args)
    except getopt.GetoptError:
        print_usage()

    warnings = []
    config = {
        "compress": "none",
        "overwrite": False,
        "usessl": False,
        "thunderbird": False,
        "nospinner": False,
    }
    errors = []

    # empty command line
    if not opts and not extraargs:
        print_usage()

    # process each command line option, save in config
    for option, value in opts:
        if option in ("-a", "--append-to-mboxes"):
            config["overwrite"] = False
        elif option in ("-y", "--yes-overwrite-mboxes"):
            warnings.append("Existing mbox files will be overwritten!")
            config["overwrite"] = True
        elif option == "-n":
            config["compress"] = "none"
        elif option == "-z":
            config["compress"] = "gzip"
        elif option == "-b":
            config["compress"] = "bzip2"
        elif option == "--compress":
            if value in ("none", "gzip", "bzip2"):
                config["compress"] = value
            else:
                errors.append("Invalid compression type specified.")
        elif option in ("-e", "--ssl"):
            config["usessl"] = True
        elif option in ("-k", "--keyfile"):
            config["keyfilename"] = value
        elif option in ("-f", "--folders"):
            config["folders"] = value
        elif option in ("-c", "--certfile"):
            config["certfilename"] = value
        elif option in ("-s", "--server"):
            config["server"] = value
        elif option in ("-u", "--user"):
            config["user"] = value
        elif option in ("-p", "--pass"):
            try:
                config["pass"] = string_from_file(value)
            except Exception as ex:
                errors.append("Can't read password: %s" % (str(ex)))
        elif option in ("-t", "--timeout"):
            config["timeout"] = value
        elif option == "--thunderbird":
            config["thunderbird"] = True
        elif option == "--nospinner":
            config["nospinner"] = True
        else:
            errors.append("Unknown option: " + option)

    # don't ignore extra arguments
    for arg in extraargs:
        errors.append("Unknown argument: " + arg)

    # done processing command line
    return (config, warnings, errors)


def check_config(config, warnings, errors):
    """Checks the config for consistency, returns (config, warnings, errors)"""

    if config["compress"] != "none":
        errors.append("Compression not supported.")
    if "server" not in config:
        errors.append("No server specified.")
    if "user" not in config:
        errors.append("No username specified.")
    if ("keyfilename" in config) ^ ("certfilename" in config):
        errors.append("Please specify both key and cert or neither.")
    if "keyfilename" in config and not config["usessl"]:
        errors.append("Key specified without SSL.  Please use -e or --ssl.")
    if "certfilename" in config and not config["usessl"]:
        errors.append("Certificate specified without SSL.  Please use -e or --ssl.")
    if "server" in config and ":" in config["server"]:
        # get host and port strings
        bits = config["server"].split(":", 1)
        config["server"] = bits[0]
        # port specified, convert it to int
        if len(bits) > 1 and len(bits[1]) > 0:
            try:
                port = int(bits[1])
                if port > 65535 or port < 0:
                    raise ValueError
                config["port"] = port
            except ValueError:
                errors.append(
                    "Invalid port.  Port must be an integer between 0 and 65535."
                )
    if "timeout" in config:
        try:
            timeout = int(config["timeout"])
            if timeout <= 0:
                raise ValueError
            config["timeout"] = timeout
        except ValueError:
            errors.append("Invalid timeout value.  Must be an integer greater than 0.")
    return (config, warnings, errors)


def get_config():
    """Gets config from command line and console, returns config"""
    # config = {
    #   'compress': 'none' or 'gzip' or 'bzip2'
    #   'overwrite': True or False
    #   'server': String
    #   'port': Integer
    #   'user': String
    #   'pass': String
    #   'usessl': True or False
    #   'keyfilename': String or None
    #   'certfilename': String or None
    # }

    config, warnings, errors = process_cline()
    config, warnings, errors = check_config(config, warnings, errors)

    # show warnings
    for warning in warnings:
        logger.warn("WARNING:", warning)

    # show errors, exit
    for error in errors:
        logger.error("ERROR", error)
    if errors:
        sys.exit(2)

    # prompt for password, if necessary
    if "pass" not in config:
        config["pass"] = getpass.getpass()

    # defaults
    if not "port" in config:
        if config["usessl"]:
            config["port"] = 993
        else:
            config["port"] = 143
    if not "timeout" in config:
        config["timeout"] = 60

    # done!
    return config


def create_folder_structure(names):
    """ Create the folder structure on disk """
    for imap_foldername, filename in sorted(names):
        disk_foldername = os.path.split(filename)[0]
        if disk_foldername:
            try:
                # print "*** mkdir:", disk_foldername  # *DEBUG
                os.mkdir(disk_foldername)
            except OSError as e:
                if e.errno != 17:
                    raise


def _main():
    """Main entry point"""
    try:
        config = get_config()
        server = MailServerHandler(
            host=config["server"],
            user=config["user"],
            password=config["pass"],
            port=config["port"],
            usessl=config["usessl"],
        )
        server.connect_and_login()
        names = server.get_names()
        if config.get("folders"):
            dirs = [x.strip() for x in config.get("folders").split(",")]
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
        logger.error("ERROR:", err)
        sys.exit(5)


def main():
    try:
        _main()
    except KeyboardInterrupt:
        pass
