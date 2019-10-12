imapbackup3
===========

A Python package for creating full backups of IMAP mailboxes

## Installation

```
python3 -m pip install --user imapbackup3
```

## Command line usage

```
usage: imapbackup3 [-h] [-y] [-f FOLDERS] [-e] [-k KEY] [-c CERT] -s HOST
                   [-P PORT] -u USER [-p PASSWORD] [-m MAILBOX] [-t SECS]
                   [--thunderbird]

Back up E-mail messages from an IMAP server. mbox files are created in the
current working directory.

optional arguments:
  -h, --help            show this help message and exit
  -y, --yes-overwrite-mboxes
                        Overwite existing mbox files instead of appending
  -f FOLDERS, --folders FOLDERS
                        Specifify which folders use. Comma separated list.
  -e, --ssl             Use SSL. Port defaults to 993.
  -k KEY, --key KEY     PEM private key file for SSL. Specify cert, too.
  -c CERT, --cert CERT  PEM certificate chain for SSL. Specify key, too.
                        Python's SSL module doesn't check the cert chain.
  -s HOST, --server HOST
                        Address of server (without port)
  -P PORT, --port PORT  Server port (defaults to 143 without and 993 with SSL)
  -u USER, --user USER  Username to log into server
  -p PASSWORD, --password PASSWORD
                        Prompts for password if not specified. If the first
                        character is '@', treat the rest as a path to a file
                        containing the password. Leading '' makes it literal.
  -m MAILBOX, --mailbox MAILBOX
                        Local e-mail storage format. Possible values: mbox
                        (default), Maildir
  -t SECS, --timeout SECS
                        Sets socket timeout to SECS seconds.
  --thunderbird         Create Mozilla Thunderbird compatible mailbox
```

## Python usage

Minimal example (using SSL on port 993):

```python
from imapbackup3 import IMAPBackup
with IMAPBackup(host='mail.example.com', user='myuser', password='mypassword') as imb:
    imb.download_all_messages()
```

Full example:

```python
from imapbackup3 import IMAPBackup
with IMAPBackup(
    host='mail.example.com',
    user='myuser',
    password='mypassword',
    port=993,
    usessl=True,
    keyfilename='my_key.pem',
    certfilename='my_cert.pem',
    thunderbird=False,
    folders=['INBOX', 'INBOX.Sent'],
    fmt='Maildir',
) as imb:
    imb.download_all_messages()
```

## Background

This package is based on a script by [Rui Carmo](https://github.com/rcarmo/imapbackup). Original description: 

> This was first published around 2007 (probably earlier) [on my personal site][tao], and it was originally developed to work around the then rather limited (ok, inconsistent) Mac OS X Mail.app functionality and allow me to back up my old mailboxes in a fully standard `mbox` format (well, at least as much as `mbox` can be considered a standard...).

> Somewhat to my surprise it was considered useful by quite a few people throughout the years, and contributions started coming in. Given that there seems to be renewed interest in this as a systems administration tool, I'm posting the source code here and re-licensing it under the MIT license.

## Features

### Inherited from `imapbackup`

* ZERO dependencies.
* Copies every single message from every single folder (or a subset of folders) in your IMAP server to your disk.
* Does _incremental_ copying (i.e., tries very hard to not copy messages twice).
* Tries to do everything as safely as possible (only performs read operations on IMAP).
* Is completely and utterly free (distributed under the MIT license).

### New features

* Python 3 compatible
* Supports mbox or Maildir formats
* Can be imported and used as library

## Requirements

This package requires Python 3.

[tao]: http://taoofmac.com/space/projects/imapbackup
