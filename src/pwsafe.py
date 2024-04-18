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

import os
import abc
import datetime
import hashlib
import hmac
import struct
import uuid
from collections import namedtuple

import twofish


__version__ = "0.2.0"
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
    "UUID",
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
    "AField",
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


class Header(namedtuple("_Header", "tag salt iterations hp1 b1 b2 b3 b4 iv")):

    __slots__ = ()
    struct = struct.Struct("<4s32sI32s16s16s16s16s16s")

    @classmethod
    def from_file(cls, fp):
        data = fp.read(cls.struct.size)
        try:
            return cls.from_bytes(data)
        except struct.error:
            raise NotPwsafeV3("truncated file")

    @classmethod
    def from_bytes(cls, data):
        return cls._make(cls.struct.unpack(data))

    def to_bytes(self):
        return self.struct.pack(*self)


def xor_bytes(b1, b2):
    assert len(b1) == len(b2)
    return bytes(c1 ^ c2 for c1, c2 in zip(b1, b2))


class PwsafeV3Base:

    TAG = b"PWS3"
    EOF = b"PWS3-EOFPWS3-EOF"  # 16 bytes
    DIGESTMOD = hashlib.sha256
    MIN_HASH_ITERATIONS = 2**11

    def stretch_key(self, key, salt, iterations, _hash=hashlib.sha256):
        assert iterations >= self.MIN_HASH_ITERATIONS
        x = _hash(key + salt).digest()
        for i in range(iterations):
            x = _hash(x).digest()
        return x


class PwsafeV3Reader(PwsafeV3Base):
    """
    Look [1] for the file format.

    https://github.com/pwsafe/pwsafe/blob/HEAD/docs/formatV3.txt
    """

    _should_close = False

    @classmethod
    def is_pwsafe(cls, filename):
        try:
            with cls.open(filename, b""):
                pass
        except NotPwsafeV3:
            return False
        except InvalidPassword:
            pass
        return True

    @classmethod
    def open(cls, filename, key):
        fp = open(filename, "rb")
        try:
            self = cls(fp, key)
        except:  # noqa
            fp.close()
            raise
        self._should_close = True
        return self

    def __init__(self, fp, key):
        self._fp = fp
        header = Header.from_file(fp)
        if header.tag != self.TAG:
            raise NotPwsafeV3('invalid tag "%s"' % header.tag)
        p1 = self.stretch_key(key, header.salt, header.iterations)
        if not hmac.compare_digest(hashlib.sha256(p1).digest(), header.hp1):
            raise InvalidPassword()
        ff = twofish.Twofish(p1)
        K = ff.decrypt(header.b1) + ff.decrypt(header.b2)
        L = ff.decrypt(header.b3) + ff.decrypt(header.b4)
        self._hmac = hmac.new(L, digestmod=self.DIGESTMOD)
        self._fishfish = twofish.Twofish(K)
        self._iv = header.iv

    def __del__(self):
        if self._should_close:
            self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        self._fp.close()

    def __iter__(self):
        # header
        yield list(self._read_record(HEADERS_MAP))
        while 1:
            try:
                yield list(self._read_record(RECORDS_MAP))
            except _EOF:
                self._check_digest()
                return

    def _read_record(self, field_types):
        field = self._read_field(field_types)
        while field is not END:
            yield field
            field = self._read_field(field_types)

    def _read_field(self, field_types, block_size=16):
        first_block = self._read_block(block_size)
        length = int.from_bytes(first_block[:4], "little")
        # TODO: refactor
        if not 0 <= length <= 65536:
            raise Error("field length {} looks insane".format(length))
        type_id = first_block[4]
        rest = length - (block_size - 5)
        data = first_block[5 : length + 5]
        while rest > 0:
            data += self._read_block(block_size)[:rest]
            rest -= block_size
        self._hmac.update(data)
        if type_id in field_types:
            return field_types[type_id].from_bytes(data)
        name = "RawField{}".format(type_id)
        field_types[type_id] = T = RawField.subclass(name, type_id)
        return T.from_bytes(data)

    def _read_block(self, block_size):
        block = self._fp.read(block_size)
        if block == self.EOF:
            raise _EOF()
        data = xor_bytes(self._fishfish.decrypt(block), self._iv)
        self._iv = block
        return data

    def _check_digest(self):
        digest = self._fp.read(self._hmac.block_size)
        if not hmac.compare_digest(self._hmac.digest(), digest):
            raise DigestError("invalid hmac")


class PwsafeV3Writer(PwsafeV3Base):

    _eof_written = False

    def __init__(self, fp, key, iterations=None):
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

    def _write_eof(self):
        assert not self._eof_written, "writer closed"
        self._fp.write(self.EOF)
        self._fp.write(self._hmac.digest())
        self._eof_written = True

    def close(self):
        self._write_eof()

    def _write_field(self, field, block_size=16):
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

    def write_record(self, fields):
        for field in fields:
            self._write_field(field)
            if field is END:
                break
        else:
            self._write_field(END)


class AField(metaclass=abc.ABCMeta):

    __slots__ = ()

    @property
    @abc.abstractmethod
    def type_id(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def to_bytes(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, raw):
        raise NotImplementedError()

    @classmethod
    def subclass(cls, name, type_id):
        attrs = {"type_id": type_id, "__slots__": (), "__module__": __name__}
        T = type(name, (cls,), attrs)
        return T

    def __repr__(self):
        return "{0.__class__.__name__}({1})".format(self, super().__repr__())


class TextField(AField, str):

    __slots__ = ()

    @classmethod
    def from_bytes(cls, raw):
        return cls(raw, encoding="utf-8")

    def to_bytes(self):
        return self.encode("utf-8")


class TimeField(AField, datetime.datetime):

    __slots__ = ()

    @classmethod
    def from_bytes(cls, raw):
        return cls.fromtimestamp(int.from_bytes(raw, byteorder="little"))

    def to_bytes(self):
        return int(self.timestamp()).to_bytes(4, byteorder="little")

    def __repr__(self):
        return datetime.datetime.__repr__(self)


class IntField(AField, int):

    __slots__ = ()

    @classmethod
    def subclass(cls, name, type_id, size):
        T = super().subclass(name, type_id)
        T.size = size
        return T

    @classmethod
    def from_bytes(cls, raw):
        return cls(int.from_bytes(raw, byteorder="little"))

    def to_bytes(self):
        return int(self).to_bytes(self.size, byteorder="little")


class UUID(AField, uuid.UUID):

    __slots__ = ()
    type_id = 0x01

    @classmethod
    def uuid4(cls):
        return cls(bytes=os.urandom(16), version=4)

    @classmethod
    def from_bytes(cls, raw):
        return cls(bytes_le=raw)

    def to_bytes(self):
        return self.bytes_le

    def __repr__(self):
        return uuid.UUID.__repr__(self)


class RawField(AField, bytes):

    __slots__ = ()

    @classmethod
    def from_bytes(cls, raw):
        return cls(raw)

    def to_bytes(self):
        return self


class End(AField):

    __slots__ = ()
    type_id = 0xFF

    @classmethod
    def from_bytes(cls, raw):
        return END

    def to_bytes(self):
        return b""

    def __repr__(self):
        return "{0.__class__.__name__}()".format(self)


Version = IntField.subclass("Version", 0x00, 2)
NonDefaultPreferences = TextField.subclass("NonDefaultPreferences", 0x02)
TreeDisplayStatus = TextField.subclass("TreeDisplayStatus", 0x03)
LastSave = TextField.subclass("LastSave", 0x04)
WhoLastSave = TextField.subclass("WhoLastSave", 0x05)
WhatLastSave = TextField.subclass("WhatLastSave", 0x06)
LastSavedByUser = TextField.subclass("LastSavedByUser", 0x07)
LastSavedOnHost = TextField.subclass("LastSavedOnHost", 0x08)
DatabaseName = TextField.subclass("DatabaseName", 0x0A)
DatabaseDescription = TextField.subclass("DatabaseDescription", 0x0A)
DatabaseFilters = TextField.subclass("DatabaseFilters", 0x0B)
# 0x0c to 0x0e are reserved
RecentlyUsedEntries = TextField.subclass("RecentlyUsedEntries", 0x0F)
NamedPasswordPolicies = TextField.subclass("NamedPasswordPolicies", 0x10)
EmptyGroups = TextField.subclass("EmptyGroups", 0x11)
Yubico = TextField.subclass("Yubico", 0x12)
END = End()
# record fields
Group = TextField.subclass("Group", 0x02)
Title = TextField.subclass("Title", 0x03)
Username = TextField.subclass("Username", 0x04)
Note = TextField.subclass("Note", 0x05)
Password = TextField.subclass("Password", 0x06)
CreationTime = TimeField.subclass("CreationTime", 0x07)
PasswordModificationTime = TimeField.subclass("PasswordModificationTime", 0x08)
LastAccessTime = TimeField.subclass("LastAccessTime", 0x09)
PasswordExpiryTime = TimeField.subclass("PasswordExpiryTime", 0x0A)
# _Reserved = IntField.subclass('_Reserved', 0x0b, 4)
LastModificationTime = TimeField.subclass("LastModificationTime", 0x0C)
Url = TextField.subclass("Url", 0x0D)
Autotype = TextField.subclass("Autotype", 0x0E)
PasswordHistory = TextField.subclass("PasswordHistory", 0x0F)
PasswordPolicy = TextField.subclass("PasswordPolicy", 0x10)
PasswordExpiryInterval = IntField.subclass("PasswordExpiryInterval", 0x11, 4)
RunCommand = TextField.subclass("RunCommand", 0x12)
DoubleClickAction = IntField.subclass("DoubleClickAction", 0x13, 2)
EmailAddress = TextField.subclass("EmailAddress", 0x14)
ProtectedEntry = IntField.subclass("ProtectedEntry", 0x15, 1)
OwnSymbolsPassword = TextField.subclass("OwnSymbolsPassword", 0x16)
ShiftDoubleClickAction = IntField.subclass("ShiftDoubleClickAction", 0x17, 2)
PasswordPolicyName = TextField.subclass("PasswordPolicyName", 0x18)
EntryKeyboardShortcut = IntField.subclass("EntryKeyboardShortcut", 0x19, 4)
# _Reserved = UUID.subclass('_Reserved', 0x1a)
TwoFactorKey = RawField.subclass("TwoFactorKey", 0x1B)
CreditCardNumber = TextField.subclass("CreditCardNumber", 0x1C)
CreditCardExpiration = TextField.subclass("CreditCardExpiration", 0x1D)
CreditCardVerification = TextField.subclass("CreditCardVerification", 0x1E)
CreditCardPin = TextField.subclass("CreditCardPin", 0x1F)
QRCode = TextField.subclass("QRCode", 0x20)
Unknown = RawField.subclass("Unknown", 0xDF)

HEADER_TYPES = (
    Version,
    UUID,
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
RECORD_TYPES = (
    UUID,
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
