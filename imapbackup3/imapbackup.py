"""IMAP Incremental Backup Tool"""

# Forked from https://github.com/rcarmo/imapbackup
# Original code (C) 2006-2018 Rui Carmo. Code under MIT License.(C)


import gc
import hashlib
import imaplib
import mailbox
import os
import re
import socket
import sys
import time


class SkipFolderException(Exception):
    """Indicates aborting processing of current folder, continue with next folder."""

    pass


class Spinner:
    """Prints out message with cute spinner, indicating progress"""

    def __init__(self, message, nospinner):
        """Spinner constructor"""
        self.glyphs = "|/-\\"
        self.pos = 0
        self.message = message
        self.nospinner = nospinner
        sys.stdout.write(message)
        sys.stdout.flush()
        self.spin()

    def spin(self):
        """Rotate the spinner"""
        if sys.stdin.isatty() and not self.nospinner:
            sys.stdout.write("\r" + self.message + " " + self.glyphs[self.pos])
            sys.stdout.flush()
            self.pos = (self.pos + 1) % len(self.glyphs)

    def stop(self):
        """Erase the spinner from the screen"""
        if sys.stdin.isatty() and not self.nospinner:
            sys.stdout.write("\r" + self.message + "  ")
            sys.stdout.write("\r" + self.message)
            sys.stdout.flush()


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


class MailBoxHandler:
    def __init__(self, path, mailserver, folder, overwrite=False):
        self.mailserver = mailserver
        self.path = path
        self.overwrite = overwrite
        self.folder = folder
        self.mbox = None

    def open_mbox(self):
        self.mbox = open(self.path, "ab")
        return self.mbox

    def close_mbox(self):
        if self.mbox is not None:
            self.mbox.close()

    def download_messages(self, messages):
        """Download messages from folder and append to mailbox"""

        if self.overwrite:
            if os.path.exists(self.path):
                print("Deleting", self.path)
                os.remove(self.path)
            return []

        if not messages:
            print("New messages: 0")
            return

        self.open_mbox()

        spinner = Spinner(
            "Downloading %s new messages to %s" % (len(messages), self.path), False
        )

        total = biggest = 0

        # each new message
        for msg_id in messages:
            total, biggest = self.download_message(
                self.mbox, msg_id, messages[msg_id], spinner, total, biggest
            )
        self.close_mbox()
        spinner.stop()
        print(
            ": {} total, {} for largest message".format(
                pretty_byte_count(total), pretty_byte_count(biggest)
            )
        )

    def download_message(self, mbox, msg_id, num, spinner, total, biggest):
        # This "From" and the terminating newline below delimit messages
        # in mbox files.  Note that RFC 4155 specifies that the date be
        # in the same format as the output of ctime(3), which is required
        # by ISO C to use English day and month abbreviations.
        buf = "From nobody {}\n".format(time.ctime())
        # If this is one of our synthesised Message-IDs, insert it before
        # the other headers
        if UUID in msg_id:
            buf = buf + "Message-Id: {}\n".format(msg_id)
        self.mbox.write(buf.encode())

        # fetch message
        text = self.mailserver.fetch_message(self.folder, num)
        self.mbox.write(text.encode())
        self.mbox.write(b"\n\n")

        size = len(text)
        biggest = max(size, biggest)
        total += size

        gc.collect()
        spinner.spin()

        spinner.stop()
        print(
            ": {} total, {} for largest message".format(
                pretty_byte_count(total), pretty_byte_count(biggest)
            )
        )

        return total, biggest

    def scan_file(self):
        """Gets IDs of messages in the specified mbox file"""
        # file will be overwritten
        nospinner = False
        if self.overwrite:
            return []

        spinner = Spinner("File %s" % (self.path), nospinner)

        self.open_mbox()

        messages = {}

        # each message
        i = 0
        for message in mailbox.mbox(self.path):
            # We assume all messages on disk have message-ids
            msg_id = message["message-id"]
            if not msg_id:
                print()
                print("WARNING: Message #{} in {}".format(i, self.path), end=" ")
                print("has no Message-Id header.")
                continue
            messages[msg_id] = msg_id
            spinner.spin()
            i = i + 1

        # done
        self.close_mbox()
        spinner.stop()
        print(": %d messages" % (len(list(messages.keys()))))
        return messages


class MailServerHandler:
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

    def fetch_message(self, folder, num):
        self.server.select(folder, readonly=True)
        typ, data = self.server.fetch(str(num), "RFC822")
        assert typ == "OK"
        for encoding in ["utf-8", "latin1"]:
            try:
                text = data[0][1].decode(encoding).strip().replace("\r", "")
            except:
                text = None
        if text is None:
            raise ValueError(data[0][1])
        del data
        return text

    def connect_and_login(self):
        """Connects to the server and logs in.  Returns IMAP4 object."""
        try:
            if self.timeout:
                socket.setdefaulttimeout(self.timeout)
            if self.usessl and self.keyfilename:
                print(
                    "Connecting to '%s' TCP port %d," % (self.host, self.port), end=" "
                )
                print("SSL, key from %s," % (self.keyfilename), end=" ")
                print("cert from %s " % (self.certfilename))
                server = imaplib.IMAP4_SSL(
                    self.host, self.port, self.keyfilename, self.certfilename
                )
            elif self.usessl:
                print("Connecting to '%s' TCP port %d, SSL" % (self.host, self.port))
                server = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                print("Connecting to '%s' TCP port %d" % (self.host, self.port))
                server = imaplib.IMAP4(self.host, self.port)

            # speed up interactions on TCP connections using small packets
            server.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            print("Logging in as '%s'" % (self.user))
            server.login(self.user, self.password)
        except socket.gaierror as err:
            (err, desc) = err
            print(
                "ERROR: problem looking up server '%s' (%s %s)" % (self.host, err, desc)
            )
            sys.exit(3)
        except socket.error as err:
            if str(err) == "SSL_CTX_use_PrivateKey_file error":
                print(
                    "ERROR: error reading private key file '{}'".format(
                        self.keyfilename
                    )
                )
            elif str(err) == "SSL_CTX_use_certificate_chain_file error":
                print(
                    "ERROR: error reading certificate chain file '%s'"
                    % (self.keyfilename)
                )
            else:
                print("ERROR: could not connect to '{}' ({})".format(self.host, err))

            sys.exit(4)

        self.server = server
        return server

    def scan_folder(self, foldername):
        """Gets IDs of messages in the specified folder, returns id:num dict"""
        nospinner = False
        messages = {}
        spinner = Spinner("Folder {}".format(foldername), nospinner)
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
                spinner.spin()
        finally:
            spinner.stop()
            print(":", end=" ")

        # done
        print("{} messages".format(len(list(messages.keys()))))
        return messages

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

    def get_names(self, thunderbird=False, compress="none"):
        """Get list of folders, returns [(FolderName,FileName)]"""
        nospinner = False

        spinner = Spinner("Finding Folders", nospinner)

        # Get hierarchy delimiter
        delim = self.get_hierarchy_delimiter()
        spinner.spin()

        # Get LIST of all folders
        typ, data = self.server.list()
        assert typ == "OK"
        spinner.spin()

        names = []

        # parse each LIST, find folder name
        for row in data:
            lst = parse_list(row)
            foldername = lst[2]
            suffix = {"none": "", "gzip": ".gz", "bzip2": ".bz2"}[compress]
            if thunderbird:
                filename = ".sbd/".join(foldername.split(delim)) + suffix
                if filename.startswith("INBOX"):
                    filename = filename.replace("INBOX", "Inbox")
            else:
                filename = ".".join(foldername.split(delim)) + ".mbox" + suffix
            # print "\n*** Folder:", foldername # *DEBUG
            # print "***   File:", filename # *DEBUG
            names.append((foldername, filename))

        # done
        spinner.stop()
        print(": %s folders" % (len(names)))
        return names


def parse_paren_list(row):
    """Parses the nested list of attributes at the start of a LIST response"""
    # eat starting paren
    assert row[0] == "("
    row = row[1:]

    result = []

    # NOTE: RFC3501 doesn't fully define the format of name attributes
    name_attrib_re = re.compile("^\s*(\\\\[a-zA-Z0-9_]+)\s*")

    # eat name attributes until ending paren
    while row[0] != ")":
        # recurse
        if row[0] == "(":
            paren_list, row = parse_paren_list(row)
            result.append(paren_list)
        # consume name attribute
        else:
            match = name_attrib_re.search(row)
            assert match != None
            name_attrib = row[match.start() : match.end()]
            row = row[match.end() :]
            # print "MATCHED '%s' '%s'" % (name_attrib, row)
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
