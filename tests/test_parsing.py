"""Tests for RFC 3501 IMAP LIST response parsing."""

from __future__ import annotations

from imapbackup3.parsing import parse_list, parse_paren_list, parse_string_list


class TestParsing:
    def test_parse_paren_list_flat(self) -> None:
        result, rest = parse_paren_list(r"(\HasNoChildren) ")
        assert result == [r"\HasNoChildren"]
        assert rest == " "

    def test_parse_paren_list_multiple(self) -> None:
        result, rest = parse_paren_list(r"(\Noselect \HasChildren) rest")
        assert result == [r"\Noselect", r"\HasChildren"]
        assert rest == " rest"

    def test_parse_string_list_quoted(self) -> None:
        assert parse_string_list(' "." "INBOX.Sent"') == [".", "INBOX.Sent"]

    def test_parse_string_list_unquoted_root(self) -> None:
        assert parse_string_list(' "." INBOX') == [".", "INBOX"]

    def test_parse_list(self) -> None:
        row = rb'(\HasNoChildren) "." "INBOX"'
        assert parse_list(row) == [[r"\HasNoChildren"], ".", "INBOX"]
