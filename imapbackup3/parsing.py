"""Parsing of RFC 3501 IMAP LIST response strings."""

from __future__ import annotations

import re
from typing import Any


def parse_paren_list(row: str) -> tuple[list[Any], str]:
    """Parses the nested list of attributes at the start of a LIST response"""
    # eat starting paren
    assert row[0] == "("
    row = row[1:]

    result: list[Any] = []

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


def parse_string_list(row: str) -> list[str]:
    """Parses the quoted and unquoted strings at the end of a LIST response"""
    slist = re.compile(r'\s*(?:"([^"]+)")\s*|\s*(\S+)\s*').split(row)
    return [s for s in slist if s]


def parse_list(row: bytes | tuple[bytes, bytes] | None) -> list[Any]:
    """Prases response of LIST command into a list"""
    assert isinstance(row, bytes)
    row_str = row.strip().decode()
    paren_list, row_str = parse_paren_list(row_str)
    string_list = parse_string_list(row_str)
    assert len(string_list) == 2
    return [paren_list] + string_list
