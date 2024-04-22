# Copyright (c) 2018 Marco Giusti
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import datetime
import hashlib
import hmac
import os
import struct
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    ClassVar,
    NamedTuple,
    Protocol,
    runtime_checkable,
)
import uuid

import twofish

if TYPE_CHECKING:
    from hashlib import _Hash
    from hmac import _DigestMod
    from typing import Self

    HashFunction = Callable[[bytes], _Hash]


__version__ = "0.3.0"
__author__ = "Marco Giusti"
__license__ = "MIT"
__all__ = (
    # high level interface
    "PwsafeV3Reader",
    "PwsafeV3Writer",
    "Error",
    "NotPwsafeV3",
    "InvalidPassword",
    "DigestError",
    # Header Fields
    "Version",
    "UuidField",
    "NonDefaultPreferences",
    "TreeDisplayStatus",
    "LastSave",
    "WhoLastSave",
    "WhatLastSave",
    "LastSavedByUser",
    "LastSavedOnHost",
    "DatabaseName",
    "DatabaseDescription",
    "DatabaseFilters",
    "RecentlyUsedEntries",
    "NamedPasswordPolicies",
    "EmptyGroups",
    "Yubico",
    "End",
    # Record fields
    "Group",
    "Title",
    "Username",
    "Note",
    "Password",
    "CreationTime",
    "PasswordModificationTime",
    "LastAccessTime",
    "PasswordExpiryTime",
    "LastModificationTime",
    "Url",
    "Autotype",
    "PasswordHistory",
    "PasswordPolicy",
    "PasswordExpiryInterval",
    "RunCommand",
    "DoubleClickAction",
    "EmailAddress",
    "ProtectedEntry",
    "OwnSymbolsPassword",
    "ShiftDoubleClickAction",
    "EntryKeyboardShortcut",
    "TwoFactorKey",
    "CreditCardNumber",
    "CreditCardExpiration",
    "CreditCardVerification",
    "CreditCardPin",
    "QRCode",
    "Unknown",
    # Miscellaneous
    "PwsafeV3Base",
    "Field",
    "RawField",
    "IntField",
    "TextField",
    "TimeField",
    "PasswordPolicyName",
    "END",
    "Header",
    "RECORDS_MAP",
    "RECORD_TYPES",
    "HEADERS_MAP",
    "HEADER_TYPES",
    "xor_bytes",
    "_EOF",
    "__author__",
    "__version__",
    "__license__",
)


Error = ValueError


class NotPwsafeV3(Error):
    pass


class InvalidPassword(Error):
    pass


class DigestError(Error):
    pass


class _EOF(Exception):
    pass


HEADER_STRUCT = struct.Struct("<4s32sI32s16s16s16s16s16s")


class Header(NamedTuple):
    tag: bytes
    salt: bytes
    iterations: int
    hp1: bytes
    b1: bytes
    b2: bytes
    b3: bytes
    b4: bytes
    iv: bytes

    @classmethod
    def from_file(cls, fp: BinaryIO) -> Self:
        data = fp.read(HEADER_STRUCT.size)
        try:
            return cls.from_bytes(data)
        except struct.error:
            raise NotPwsafeV3("truncated file")

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls._make(HEADER_STRUCT.unpack(data))

    def to_bytes(self) -> bytes:
        return HEADER_STRUCT.pack(*self)


def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    assert len(b1) == len(b2)
    return bytes(c1 ^ c2 for c1, c2 in zip(b1, b2))


def stretch_key(
    key: bytes, salt: bytes, iterations: int, _hash: HashFunction = hashlib.sha256
) -> bytes:
    x = _hash(key + salt).digest()
    for i in range(iterations):
        x = _hash(x).digest()
    return x


class PwsafeV3Base:

    TAG: bytes = b"PWS3"
    EOF: bytes = b"PWS3-EOFPWS3-EOF"  # 16 bytes
    DIGESTMOD: _DigestMod = hashlib.sha256
    MIN_HASH_ITERATIONS: int = 2**11

    def stretch_key(
        self,
        key: bytes,
        salt: bytes,
        iterations: int,
        _hash: HashFunction = hashlib.sha256,
    ) -> bytes:
        assert iterations >= self.MIN_HASH_ITERATIONS
        return stretch_key(key, salt, iterations, _hash)


class PwsafeV3Reader(PwsafeV3Base):
    """
    Look [1] for the file format.

    https://github.com/pwsafe/pwsafe/blob/HEAD/docs/formatV3.txt
    """

    _should_close = False

    @classmethod
    def is_pwsafe(cls, filename: str) -> bool:
        try:
            with cls.open(filename, b""):
                pass
        except NotPwsafeV3:
            return False
        except InvalidPassword:
            pass
        return True

    @classmethod
    def open(cls, filename: str, key: bytes) -> Self:
        fp = open(filename, "rb")
        try:
            self = cls(fp, key)
        except:  # noqa
            fp.close()
            raise
        self._should_close = True
        return self

    def __init__(self, fp: BinaryIO, key: bytes):
        self._fp = fp
        header = Header.from_file(fp)
        if header.tag != self.TAG:
            raise NotPwsafeV3(f"invalid tag {header.tag!r}")
        p1 = self.stretch_key(key, header.salt, header.iterations)
        if not hmac.compare_digest(hashlib.sha256(p1).digest(), header.hp1):
            raise InvalidPassword()
        ff = twofish.Twofish(p1)
        K = ff.decrypt(header.b1) + ff.decrypt(header.b2)
        L = ff.decrypt(header.b3) + ff.decrypt(header.b4)
        self._hmac = hmac.new(L, digestmod=self.DIGESTMOD)
        self._fishfish = twofish.Twofish(K)
        self._iv = header.iv

    def __del__(self) -> None:
        if self._should_close:
            self.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._fp.close()

    def __iter__(self) -> Iterable[list[Field]]:
        # header
        yield list(self._read_record(HEADERS_MAP))
        while 1:
            try:
                yield list(self._read_record(RECORDS_MAP))
            except _EOF:
                self._check_digest()
                return

    def _read_record(self, field_types: dict[int, type[Field]]) -> Iterable[Field]:
        field = self._read_field(field_types)
        while field is not END:
            yield field
            field = self._read_field(field_types)

    def _read_field(
        self, field_types: dict[int, type[Field]], block_size: int = 16
    ) -> Field:
        first_block = self._read_block(block_size)
        length = int.from_bytes(first_block[:4], "little")
        # TODO: refactor
        if not 0 <= length <= 65536:
            raise Error(f"field length {length} looks insane")
        type_id = first_block[4]
        rest = length - (block_size - 5)
        data = first_block[5 : length + 5]
        while rest > 0:
            data += self._read_block(block_size)[:rest]
            rest -= block_size
        self._hmac.update(data)
        if type_id in field_types:
            return field_types[type_id].from_bytes(data)
        name = f"RawField{type_id}"
        field_types[type_id] = T = subclass(RawField, name, type_id)
        return T.from_bytes(data)

    def _read_block(self, block_size: int) -> bytes:
        block = self._fp.read(block_size)
        if block == self.EOF:
            raise _EOF()
        data = xor_bytes(self._fishfish.decrypt(block), self._iv)
        self._iv = block
        return data

    def _check_digest(self) -> None:
        digest = self._fp.read(self._hmac.block_size)
        if not hmac.compare_digest(self._hmac.digest(), digest):
            raise DigestError("invalid hmac")


class PwsafeV3Writer(PwsafeV3Base):

    _eof_written = False

    def __init__(self, fp: BinaryIO, key: bytes, iterations: int | None = None):
        self._fp = fp
        if iterations is None or iterations < self.MIN_HASH_ITERATIONS:
            iterations = self.MIN_HASH_ITERATIONS
        salt = os.urandom(32)
        K = os.urandom(32)
        L = os.urandom(32)
        p1 = self.stretch_key(key, salt, iterations)
        hp1 = hashlib.sha256(p1).digest()
        ff = twofish.Twofish(p1)
        b1 = ff.encrypt(K[:16])
        b2 = ff.encrypt(K[16:])
        b3 = ff.encrypt(L[:16])
        b4 = ff.encrypt(L[16:])
        self._fishfish = twofish.Twofish(K)
        self._hmac = hmac.new(L, digestmod=self.DIGESTMOD)
        self._iv = iv = os.urandom(16)
        header = Header(self.TAG, salt, iterations, hp1, b1, b2, b3, b4, iv)
        fp.write(header.to_bytes())

    def _write_eof(self) -> None:
        assert not self._eof_written, "writer closed"
        self._fp.write(self.EOF)
        self._fp.write(self._hmac.digest())
        self._eof_written = True

    def close(self) -> None:
        self._write_eof()

    def _write_field(self, field: Field, block_size: int = 16) -> None:
        raw = field.to_bytes()
        self._hmac.update(raw)
        length = len(raw)
        padding_length = (block_size - (length + 5) % block_size) % block_size
        padding = os.urandom(padding_length)
        data = (
            length.to_bytes(length=4, byteorder="little")
            + field.type_id.to_bytes(length=1, byteorder="little")
            + raw
            + padding
        )
        assert len(data) % block_size == 0
        for i in range(len(data) // block_size):
            block = data[i * block_size : (i + 1) * block_size]
            enc = self._fishfish.encrypt(xor_bytes(block, self._iv))
            self._fp.write(enc)
            self._iv = enc

    def write_record(self, fields: Iterable[Field]) -> None:
        for field in fields:
            self._write_field(field)
            if field is END:
                break
        else:
            self._write_field(END)


def subclass(cls: type[Field], name: str, type_id: int, **kwargs: Any) -> type[Field]:
    attrs = {"type_id": type_id, "__slots__": (), "__module__": __name__, **kwargs}
    T = type(name, (cls,), attrs)
    return T


@runtime_checkable
class Field(Protocol):
    type_id: ClassVar[int] = 0xDF

    def to_bytes(self) -> bytes: ...

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self: ...


@dataclass
class TextField(Field):
    value: str

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(str(raw, encoding="utf-8"))

    def to_bytes(self) -> bytes:
        return self.value.encode("utf-8")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self.value)})"


@dataclass
class TimeField(Field):
    value: datetime.datetime

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        timestamp = int.from_bytes(raw, byteorder="little")
        return cls(datetime.datetime.fromtimestamp(timestamp))

    def to_bytes(self) -> bytes:
        return int(self.value.timestamp()).to_bytes(4, byteorder="little")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self.value)})"


@dataclass
class IntField(Field):
    size: ClassVar[int]
    value: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(int.from_bytes(raw, byteorder="little"))

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(self.size, byteorder="little")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self.value)})"


@dataclass
class UuidField(Field):
    type_id: ClassVar[int] = 0x01
    value: uuid.UUID

    @classmethod
    def uuid4(cls) -> Self:
        return cls(uuid.UUID(bytes=os.urandom(16), version=4))

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(uuid.UUID(bytes_le=raw))

    def to_bytes(self) -> bytes:
        return self.value.bytes_le

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self.value)})"


@dataclass
class RawField(Field):
    value: bytes

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(raw)

    def to_bytes(self) -> bytes:
        return self.value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self.value)})"


@dataclass
class End(Field):
    type_id: ClassVar[int] = 0xFF

    @classmethod
    def from_bytes(cls, raw: bytes) -> End:
        return END

    def to_bytes(self) -> bytes:
        return b""

    def __repr__(self) -> str:
        return "End()"


Version = subclass(IntField, "Version", 0x00, size=2)
NonDefaultPreferences = subclass(TextField, "NonDefaultPreferences", 0x02)
TreeDisplayStatus = subclass(TextField, "TreeDisplayStatus", 0x03)
LastSave = subclass(TextField, "LastSave", 0x04)
WhoLastSave = subclass(TextField, "WhoLastSave", 0x05)
WhatLastSave = subclass(TextField, "WhatLastSave", 0x06)
LastSavedByUser = subclass(TextField, "LastSavedByUser", 0x07)
LastSavedOnHost = subclass(TextField, "LastSavedOnHost", 0x08)
DatabaseName = subclass(TextField, "DatabaseName", 0x0A)
DatabaseDescription = subclass(TextField, "DatabaseDescription", 0x0A)
DatabaseFilters = subclass(TextField, "DatabaseFilters", 0x0B)
# 0x0c to 0x0e are reserved
RecentlyUsedEntries = subclass(TextField, "RecentlyUsedEntries", 0x0F)
NamedPasswordPolicies = subclass(TextField, "NamedPasswordPolicies", 0x10)
EmptyGroups = subclass(TextField, "EmptyGroups", 0x11)
Yubico = subclass(TextField, "Yubico", 0x12)
END = End()
# record fields
Group = subclass(TextField, "Group", 0x02)
Title = subclass(TextField, "Title", 0x03)
Username = subclass(TextField, "Username", 0x04)
Note = subclass(TextField, "Note", 0x05)
Password = subclass(TextField, "Password", 0x06)
CreationTime = subclass(TimeField, "CreationTime", 0x07)
PasswordModificationTime = subclass(TimeField, "PasswordModificationTime", 0x08)
LastAccessTime = subclass(TimeField, "LastAccessTime", 0x09)
PasswordExpiryTime = subclass(TimeField, "PasswordExpiryTime", 0x0A)
# _Reserved = subclass(IntField, '_Reserved', 0x0b, size=4)
LastModificationTime = subclass(TimeField, "LastModificationTime", 0x0C)
Url = subclass(TextField, "Url", 0x0D)
Autotype = subclass(TextField, "Autotype", 0x0E)
PasswordHistory = subclass(TextField, "PasswordHistory", 0x0F)
PasswordPolicy = subclass(TextField, "PasswordPolicy", 0x10)
PasswordExpiryInterval = subclass(IntField, "PasswordExpiryInterval", 0x11, size=4)
RunCommand = subclass(TextField, "RunCommand", 0x12)
DoubleClickAction = subclass(IntField, "DoubleClickAction", 0x13, size=2)
EmailAddress = subclass(TextField, "EmailAddress", 0x14)
ProtectedEntry = subclass(IntField, "ProtectedEntry", 0x15, size=1)
OwnSymbolsPassword = subclass(TextField, "OwnSymbolsPassword", 0x16)
ShiftDoubleClickAction = subclass(IntField, "ShiftDoubleClickAction", 0x17, size=2)
PasswordPolicyName = subclass(TextField, "PasswordPolicyName", 0x18)
EntryKeyboardShortcut = subclass(IntField, "EntryKeyboardShortcut", 0x19, size=4)
# _Reserved = subclass(UuidField, '_Reserved', 0x1a)
TwoFactorKey = subclass(RawField, "TwoFactorKey", 0x1B)
CreditCardNumber = subclass(TextField, "CreditCardNumber", 0x1C)
CreditCardExpiration = subclass(TextField, "CreditCardExpiration", 0x1D)
CreditCardVerification = subclass(TextField, "CreditCardVerification", 0x1E)
CreditCardPin = subclass(TextField, "CreditCardPin", 0x1F)
QRCode = subclass(TextField, "QRCode", 0x20)
Unknown = subclass(RawField, "Unknown", 0xDF)

HEADER_TYPES: tuple[type[Field], ...] = (
    Version,
    UuidField,
    NonDefaultPreferences,
    TreeDisplayStatus,
    LastSave,
    WhoLastSave,
    WhatLastSave,
    LastSavedByUser,
    LastSavedOnHost,
    DatabaseName,
    DatabaseDescription,
    DatabaseFilters,
    RecentlyUsedEntries,
    NamedPasswordPolicies,
    EmptyGroups,
    Yubico,
    End,
)
RECORD_TYPES: tuple[type[Field], ...] = (
    UuidField,
    Group,
    Title,
    Username,
    Note,
    Password,
    CreationTime,
    PasswordModificationTime,
    LastAccessTime,
    PasswordExpiryTime,
    LastModificationTime,
    Url,
    Autotype,
    PasswordHistory,
    PasswordPolicy,
    PasswordExpiryInterval,
    RunCommand,
    DoubleClickAction,
    EmailAddress,
    ProtectedEntry,
    OwnSymbolsPassword,
    ShiftDoubleClickAction,
    EntryKeyboardShortcut,
    TwoFactorKey,
    CreditCardNumber,
    CreditCardExpiration,
    CreditCardVerification,
    CreditCardPin,
    QRCode,
    Unknown,
    End,
)
HEADERS_MAP = {f.type_id: f for f in HEADER_TYPES}
RECORDS_MAP = {f.type_id: f for f in RECORD_TYPES}
