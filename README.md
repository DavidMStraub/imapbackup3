imapbackup3
===========

A Python package for creating full backups of IMAP mailboxes

## Background

This package is based on a script by [Rui Carmo](https://github.com/rcarmo/imapbackup). Original description: 

> This was first published around 2007 (probably earlier) [on my personal site][tao], and it was originally developed to work around the then rather limited (ok, inconsistent) Mac OS X Mail.app functionality and allow me to back up my old mailboxes in a fully standard `mbox` format (well, at least as much as `mbox` can be considered a standard...).

> Somewhat to my surprise it was considered useful by quite a few people throughout the years, and contributions started coming in. Given that there seems to be renewed interest in this as a systems administration tool, I'm posting the source code here and re-licensing it under the MIT license.

## Features

* ZERO dependencies.
* Copies every single message from every single folder (or a subset of folders) in your IMAP server to your disk.
* Does _incremental_ copying (i.e., tries very hard to not copy messages twice).
* Tries to do everything as safely as possible (only performs read operations on IMAP).
* Generates `mbox` formatted files that can be imported into Mail.app (just choose "Other" on the import dialog).
* Optionally compresses the result files on the fly (and can append to them).
* Is completely and utterly free (distributed under the MIT license).

## Requirements

This package requires Python 3.

[tao]: http://taoofmac.com/space/projects/imapbackup
