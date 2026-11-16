"""Strict JSON parsing and canonical base64url helpers.

The verifier must reject duplicate object members and non-canonical base64url
instead of silently picking a winner.  Python's stock ``json`` accepts both,
so this module implements an explicit parser on top of ``json.JSONDecoder``'s
scanning primitives while keeping the value types (int/float/str/bool/null)
identical to the stdlib.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from .errors import TokenValidationError

# RFC 7515 permits only these characters in a base64url segment.
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_INT_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)$")

MAX_SEGMENT_CHARS = 64 * 1024


def b64url_decode_strict(segment: str, *, what: str = "segment") -> bytes:
    """Decode unpadded base64url, rejecting pad bits and illegal characters.

    Canonical encoding is enforced by re-encoding the decoded bytes and
    comparing with the input.  That rejects, for example, ``"QQ"`` (whose last
    character carries non-zero unused bits) and any ``'='`` padding, both of
    which some lenient decoders accept.
    """
    if not isinstance(segment, str):
        raise TokenValidationError("b64url_not_string", f"{what} must be a string")
    if len(segment) > MAX_SEGMENT_CHARS:
        raise TokenValidationError("b64url_too_long", f"{what} is too long")
    if not _B64URL_RE.match(segment):
        raise TokenValidationError(
            "b64url_bad_charset", f"{what} contains characters outside base64url"
        )
    if len(segment) % 4 == 1:
        raise TokenValidationError("b64url_bad_length", f"{what} has invalid length")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise TokenValidationError("b64url_bad_encoding", f"{what} is not base64url") from exc
    if b64url_encode(raw) != segment:
        raise TokenValidationError(
            "b64url_not_canonical", f"{what} is not canonical base64url"
        )
    return raw


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class _StrictJSONParser:
    """Recursive-descent parser that rejects duplicate names.

    Scalars are delegated to ``json.JSONDecoder``'s scanners so ints, floats,
    unicode escapes and exponents behave exactly like the standard library.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.decoder = json.JSONDecoder()

    def parse(self) -> Any:
        self._ws()
        value = self._value()
        self._ws()
        if self.pos != len(self.text):
            self._fail("trailing data after JSON value")
        return value

    # -- helpers -----------------------------------------------------------
    def _fail(self, message: str) -> None:
        raise TokenValidationError("json_invalid", message)

    def _ws(self) -> None:
        text = self.text
        while self.pos < len(text) and text[self.pos] in " \t\r\n":
            self.pos += 1

    def _expect(self, ch: str) -> None:
        if self.pos >= len(self.text) or self.text[self.pos] != ch:
            self._fail(f"expected {ch!r}")
        self.pos += 1

    def _scan_scalar(self) -> Any:
        try:
            value, end = self.decoder.raw_decode(self.text, self.pos)
        except json.JSONDecodeError as exc:
            raise TokenValidationError("json_invalid", "malformed JSON scalar") from exc
        if isinstance(value, (dict, list)):
            self._fail("unexpected container")
        self.pos = end
        return value

    # -- grammar -----------------------------------------------------------
    def _value(self) -> Any:
        if self.pos >= len(self.text):
            self._fail("unexpected end of JSON")
        ch = self.text[self.pos]
        if ch == "{":
            return self._object()
        if ch == "[":
            return self._array()
        if ch == '"':
            return self._scan_scalar()
        return self._scan_scalar()

    def _object(self) -> dict[str, Any]:
        self._expect("{")
        result: dict[str, Any] = {}
        self._ws()
        if self.pos < len(self.text) and self.text[self.pos] == "}":
            self.pos += 1
            return result
        while True:
            self._ws()
            if self.pos >= len(self.text) or self.text[self.pos] != '"':
                self._fail("object member name must be a string")
            key = self._scan_scalar()
            self._ws()
            self._expect(":")
            self._ws()
            if key in result:
                raise TokenValidationError(
                    "json_duplicate_member",
                    f"duplicate JSON member {key!r}",
                )
            result[key] = self._value()
            self._ws()
            if self.pos < len(self.text) and self.text[self.pos] == ",":
                self.pos += 1
                continue
            self._expect("}")
            return result

    def _array(self) -> list[Any]:
        self._expect("[")
        result: list[Any] = []
        self._ws()
        if self.pos < len(self.text) and self.text[self.pos] == "]":
            self.pos += 1
            return result
        while True:
            self._ws()
            result.append(self._value())
            self._ws()
            if self.pos < len(self.text) and self.text[self.pos] == ",":
                self.pos += 1
                continue
            self._expect("]")
            return result


def strict_json_loads(text: str | bytes) -> Any:
    """Parse JSON, rejecting duplicate object members at any nesting depth."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise TokenValidationError("json_not_utf8", "JSON is not valid UTF-8") from exc
    if not isinstance(text, str):
        raise TypeError("strict_json_loads expects str or bytes")
    return _StrictJSONParser(text).parse()


def parse_json_object(text: str | bytes, what: str) -> dict[str, Any]:
    value = strict_json_loads(text)
    if type(value) is not dict:
        raise TokenValidationError("json_not_object", f"{what} is not a JSON object")
    return value


def strict_int_member(obj: dict[str, Any], name: str, what: str) -> int | None:
    """Return an integer NumericDate member.

    ``bool`` is rejected explicitly: in Python ``True`` is an ``int``, but a
    JSON boolean is never an acceptable NumericDate.  Floats (even integral
    ones such as ``1e3``) are rejected as well, per the task's "must be
    integer" rule.
    """
    if name not in obj:
        return None
    value = obj[name]
    if type(value) is bool or not isinstance(value, int):
        raise TokenValidationError(
            "json_member_not_integer", f"{what}.{name} must be an integer"
        )
    return value
