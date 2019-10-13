"""IMAP Incremental Backup Tool"""

# Forked from https://github.com/rcarmo/imapbackup
# Original code (C) 2006-2018 Rui Carmo. Code under MIT License.(C)


import email
import email.policy
import gc
import hashlib
import imaplib
import logging
import mailbox
import os
import re
import socket
import sys

logger = logging.getLogger("imapbackup3")


class SkipFolderException(Exception):
    """Indicates aborting processing of current folder, continue with next folder."""


def pretty_byte_count(num):
    """Converts integer into a human friendly count of bytes, eg: 12.243 MB"""
    if num == 1:
        return "1 byte"
    elif num < 1024:
        return "%s bytes" % (num)
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


def require_login(f):
    """Decorator for methods that require login."""

    def wrapper(instance, *args, **kwargs):
        if not instance.logged_in:
            instance.login()
            instance.logged_in = True
        return f(instance, *args, **kwargs)

    return wrapper


class MailServerHandler:
    """Handle the connection to and reading from an IMAP server."""

    def __init__(
        self,
        host,
        user,
        password,
        port=993,
        usessl=True,
        keyfilename=None,
        certfilename=None,
        timeout=None,
    ):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.usessl = usessl
        self.keyfilename = keyfilename
        self.certfilename = certfilename
        self.timeout = timeout
        self.server = None
        self.logged_in = None

    def logout(self):
        if self.logged_in:
            self.server.logout()

    @require_login
    def fetch_message(self, folder, num):
        """Fetch the message number `num` for the IMAP folder `folder`.
        
        Returns a string."""
        self.server.select(folder, readonly=True)
        typ, data = self.server.fetch(str(num), "RFC822")
        assert typ == "OK"
        for encoding in ["utf-8", "latin1"]:
            try:
                text = data[0][1].decode(encoding)
            except UnicodeDecodeError:
                text = None
        if text is None:
            text = data[0][1].decode("utf-8", "backslashreplace")
        text = text.strip().replace("\r", "")
        return text

    def login(self):
        """Connects to the server and logs in.
        
        Returns IMAP4 object."""
        try:
            if self.timeout:
                socket.setdefaulttimeout(self.timeout)
            if self.usessl and self.keyfilename:
                logger.info(
                    "Connecting to '%s' TCP port %d, SSL, key from %s, cert from %s",
                    self.host,
                    self.port,
                    self.keyfilename,
                    self.certfilename,
                )
                server = imaplib.IMAP4_SSL(
                    self.host, self.port, self.keyfilename, self.certfilename
                )
            elif self.usessl:
                logger.info(
                    "Connecting to '%s' TCP port %d, SSL" % (self.host, self.port)
                )
                server = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                logger.info("Connecting to '%s' TCP port %d", self.host, self.port)
                server = imaplib.IMAP4(self.host, self.port)

            # speed up interactions on TCP connections using small packets
            server.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            logger.info("Logging in as '%s'", (self.user))
            server.login(self.user, self.password)
        except socket.gaierror as err:
            (err, desc) = err
            logger.info(
                "ERROR: problem looking up server '%s' (%s %s)", self.host, err, desc
            )
            sys.exit(3)
        except socket.error as err:
            if str(err) == "SSL_CTX_use_PrivateKey_file error":
                logger.info(
                    "ERROR: error reading private key file '{}'".format(
                        self.keyfilename
                    )
                )
            elif str(err) == "SSL_CTX_use_certificate_chain_file error":
                logger.info(
                    "ERROR: error reading certificate chain file '%s'",
                    (self.keyfilename),
                )
            else:
                logger.info("ERROR: could not connect to '%s' (%s)", self.host, err)

            sys.exit(4)

        self.server = server
        return server

    @require_login
    def scan_folder(self, foldername):
        """Gets IDs of messages in the specified folder, returns id:num dict"""
        messages = {}
        logger.info("Folder %s ...", foldername)
        try:
            typ, data = self.server.select(foldername, readonly=True)
            if typ != "OK":
                raise SkipFolderException("SELECT failed: %s" % (data))
            num_msgs = int(data[0])

            # each message
            for num in range(1, num_msgs + 1):
                # Retrieve Message-Id, making sure we don't mark all messages as read
                typ, data = self.server.fetch(
                    str(num), "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])"
                )
                if typ != "OK":
                    raise SkipFolderException("FETCH {} failed: {}".format(num, data))

                header = data[0][1].strip()
                # remove newlines inside Message-Id (a dumb Exchange trait)
                header = BLANKS_RE.sub(" ", header.decode())
                try:
                    msg_id = MSGID_RE.match(header).group(1)
                    if msg_id not in list(messages.keys()):
                        # avoid adding dupes
                        messages[msg_id] = num
                except (IndexError, AttributeError):
                    # Some messages may have no Message-Id, so we'll synthesise one
                    # (this usually happens with Sent, Drafts and .Mac news)
                    typ, data = self.server.fetch(
                        str(num), "(BODY[HEADER.FIELDS (FROM TO CC DATE SUBJECT)])"
                    )
                    if typ != "OK":
                        raise SkipFolderException(
                            "FETCH {} failed: {}".format(num, data)
                        )
                    header = data[0][1].decode().strip()
                    header = header.replace("\r\n", "\t")
                    messages[
                        "<"
                        + UUID
                        + "."
                        + hashlib.sha1(header.encode()).hexdigest()
                        + ">"
                    ] = num
        finally:
            pass

        # done
        logger.info("Found %d messages", len(messages))
        return messages

    @require_login
    def get_hierarchy_delimiter(self):
        """Queries the imapd for the hierarchy delimiter, eg. '.' in INBOX.Sent"""
        # see RFC 3501 page 39 paragraph 4
        typ, data = self.server.list()
        assert typ == "OK"
        # assert len(data) == 1
        lst = parse_list(data[0])  # [attribs, hierarchy delimiter, root name]
        hierarchy_delim = lst[1]
        # NIL if there is no hierarchy
        if hierarchy_delim == "NIL":
            hierarchy_delim = "."
        return hierarchy_delim

    @require_login
    def get_folder_names(self):
        """Get list of folders"""

        logger.info("Finding Folders ...")

        # Get LIST of all folders
        typ, data = self.server.list()
        assert typ == "OK"

        names = []

        # parse each LIST, find folder name
        for row in data:
            lst = parse_list(row)
            foldername = lst[2]
            names.append(foldername)

        # done

        logger.info("Found %s folders", len(names))
        return names


def parse_paren_list(row):
    """Parses the nested list of attributes at the start of a LIST response"""
    # eat starting paren
    assert row[0] == "("
    row = row[1:]

    result = []

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


def parse_string_list(row):
    """Parses the quoted and unquoted strings at the end of a LIST response"""
    slist = re.compile(r'\s*(?:"([^"]+)")\s*|\s*(\S+)\s*').split(row)
    return [s for s in slist if s]


def parse_list(row):
    """Prases response of LIST command into a list"""
    row = row.strip().decode()
    paren_list, row = parse_paren_list(row)
    string_list = parse_string_list(row)
    assert len(string_list) == 2
    return [paren_list] + string_list


class IMAPBackup:
    """Main class to back up E-mail messages from an IMAP server."""

    def __init__(
        self,
        host,
        user,
        password,
        port=993,
        usessl=True,
        keyfilename=None,
        certfilename=None,
        timeout=None,
        thunderbird=False,
        folders=None,
        overwrite=False,
        fmt="mbox",
    ):
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
        self._names = None
        self.thunderbird = thunderbird
        self.folders = folders
        self.overwrite = overwrite
        self.fmt = fmt

    def __enter__(self):
        self.mailserver.login()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.mailserver.logout()

    def get_mailbox_filename(self, imap_foldername, hierarchy_delimiter, fmt):
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
            filename = ".".join(imap_foldername.split(delim))
        else:
            raise ValueError("Mailbox format {} not understood".format(fmt))
        return filename

    def create_folder_structure(self):
        """ Create the folder structure on disk """
        for imap_foldername, filename in sorted(self.names):
            disk_foldername = os.path.split(filename)[0]
            if disk_foldername:
                try:
                    # print "*** mkdir:", disk_foldername  # *DEBUG
                    os.mkdir(disk_foldername)
                except OSError as err:
                    if err.errno != 17:
                        raise

    @property
    def names(self):
        """Return a (cached) list of IMAP folder name and file/directory name tuples."""
        if not self._names:
            self._names = self._get_names()
        return self._names

    def _get_names(self):
        """Return a list of IMAP folder name and file/directory name tuples."""
        folders = self.mailserver.get_folder_names()
        if self.folders is not None:
            folders = [f for f in folders if f in self.folders]
            # Get hierarchy delimiter
        delim = self.mailserver.get_hierarchy_delimiter()
        names = [(f, self.get_mailbox_filename(f, delim, self.fmt)) for f in folders]
        return names

    def download_message(self, mbox, folder, num, msg_filter=None):
        """Download message no. `num` from the IMAP `folder` to the Mailbox instance `mbox`.
        
        Returns the size of the message."""

        # fetch message
        text = self.mailserver.fetch_message(folder, num)

        msg = email.message_from_string(text, policy=email.policy.default)
        if "message-id" not in msg:
            msg["message-id"] = (
                "<" + UUID + "." + hashlib.sha1(text.encode()).hexdigest() + ">"
            )
            text = msg.as_string()

        if msg_filter is not None:
            msg = msg_filter(msg)
            if msg is None:
                # if there is a message filter and the msg is filtered out, return
                logger.info("Skipping filtered message")
                return None
            # the filter modified the message
            text = msg.as_string()

        mbox.add(text.encode())

        size = sys.getsizeof(text)

        gc.collect()

        return size

    def download_messages(self, mbox, folder, messages, msg_filter=None):
        """Download messages from folder and append to mailbox"""

        if self.overwrite:
            mbox.clear()

        if not messages:
            logger.info("New messages: 0")
            return

        mbox.lock()

        logger.info("Downloading %s new messages to %s ...", len(messages), mbox._path)

        total = biggest = 0

        # each new message
        for msg_id in messages:
            try:
                size = self.download_message(
                    mbox, folder, messages[msg_id], msg_filter=msg_filter
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

            except KeyboardInterrupt:
                mbox.flush()
                mbox.unlock()
        mbox.flush()
        mbox.unlock()

    def download_folder_messages(self, mbox, foldername, msg_filter=None):
        """Download all messages from the IMAP folder with `foldername` to the
        Mailbox instance `mbox`."""
        fol_messages = self.mailserver.scan_folder(foldername)
        fil_messages = {msg["message-id"]: num for num, msg in mbox.items()}
        new_messages = {}
        for msg_id in list(fol_messages.keys()):
            if msg_id not in fil_messages:
                new_messages[msg_id] = fol_messages[msg_id]

        self.download_messages(mbox, foldername, new_messages, msg_filter=msg_filter)

    def download_all_messages(self, msg_filter=None):
        """Download all messages to a new mailbox with format `fmt`."""
        for name_pair in self.names:
            try:
                foldername, filename = name_pair
                if self.fmt == "mbox":
                    mbox = mailbox.mbox(filename, factory=email_message_factory)
                elif self.fmt == "maildir":
                    mbox = mailbox.Maildir(filename, factory=email_message_factory)
                else:
                    raise ValueError("Mailbox format {} not understood".format(fmt))
                self.download_folder_messages(mbox, foldername, msg_filter=msg_filter)

            except SkipFolderException as err:
                logger.error(err)


def email_message_factory(f):
    """Factory to create EmailMessage objects instead of Message objects"""
    return email.message_from_binary_file(f, policy=email.policy.default)
