# Copyright (c) 2018 Marco Giusti

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

import datetime
import io
from os.path import abspath, dirname, join as joinpath
import unittest
import uuid

from pwsafe import (
    END,
    End,
    Field,
    Group,
    IntField,
    LastModificationTime,
    NonDefaultPreferences,
    Note,
    Password,
    PasswordModificationTime,
    PwsafeV3Reader,
    PwsafeV3Writer,
    TextField,
    Title,
    Url,
    Username,
    UuidField,
    Version,
    subclass,
)


TESTS_DIR = dirname(__file__)


class TestFields(unittest.TestCase):

    def test_str(self):
        self.assertIsInstance(Username("marco"), Field)
        expected = bytes.fromhex("6d6172636f")
        self.assertEqual(Username("marco").to_bytes(), expected)

    def test_datetime(self):
        dt = datetime.datetime(2017, 5, 15, 22, 18, 48)
        self.assertIsInstance(LastModificationTime(dt), Field)
        expected = bytes.fromhex("280d1a59")
        modified = LastModificationTime(dt)
        self.assertEqual(modified.to_bytes(), expected)

    def test_uuid(self):
        uid = UuidField(uuid.UUID("665c6795-a54d-1345-b3c3-6229091c85bf"))
        self.assertIsInstance(uid, Field)
        exp = bytes.fromhex("95675c664da54513b3c36229091c85bf")
        self.assertEqual(uid.to_bytes(), exp)

    def test_int(self):
        self.assertIsInstance(Version(1), Field)
        expected = b"\x00\x03"
        self.assertEqual(Version(768).to_bytes(), expected)

    def test_end(self):
        self.assertIs(End.from_bytes(b"~~noise~~"), END)
        self.assertEqual(END.to_bytes(), b"")

    def test_subclass(self):
        MyField = subclass(TextField, "MyField", 0x0C)
        self.assertIsInstance(MyField("foo"), Field)

    def test_int_subclass(self):
        MyIntField = subclass(IntField, "MyIntField", 0x0C, size=4)
        self.assertIsInstance(MyIntField(123), Field)
        expected = b"\x00\x03\x00\x00"
        self.assertEqual(MyIntField(768).to_bytes(), expected)


class TestReadWrite(unittest.TestCase):

    EMPTY_DB = abspath(joinpath(TESTS_DIR, "empty.psafe3"))
    TEST_DB = abspath(joinpath(TESTS_DIR, "test.psafe3"))
    PWD = b"test"

    def test_is_pwsafe(self):
        self.assertTrue(PwsafeV3Reader.is_pwsafe(self.EMPTY_DB))

    def test_is_no_pwsafev3(self):
        self.assertFalse(PwsafeV3Reader.is_pwsafe(abspath(joinpath(TESTS_DIR, "zero"))))

    def test_empty_db(self):
        with PwsafeV3Reader.open(self.EMPTY_DB, self.PWD) as dbfile:
            header, *records = list(dbfile)
            self.assertEqual(
                header,
                [
                    Version(0x300),
                    UuidField(uuid.UUID(int=0)),
                    NonDefaultPreferences("B 24 1"),
                ],
            )
            self.assertEqual(records, [])

    def test_db(self):
        with PwsafeV3Reader.open(self.TEST_DB, self.PWD) as dbfile:
            header, r1, r2 = list(dbfile)
            self.assertEqual(
                header,
                [
                    Version(0x300),
                    UuidField(uuid.UUID(int=0)),
                    NonDefaultPreferences("B 24 1"),
                ],
            )
            self.assertEqual(
                r1,
                [
                    UuidField(uuid.UUID("665c6795-a54d-1345-b3c3-6229091c85bf")),
                    Title("test"),
                    Username("marco"),
                    Note("some notes"),
                    Password("qwerty"),
                    PasswordModificationTime(datetime.datetime(2017, 5, 7, 9, 20, 23)),
                    LastModificationTime(datetime.datetime(2017, 5, 7, 9, 20, 23)),
                    Url("http://www.example.com/"),
                ],
            )
            self.assertEqual(
                r2,
                [
                    UuidField(uuid.UUID("12084a3c-d97d-2346-a089-322777c3e016")),
                    Group("group1.group2.group3"),
                    Title("test nested"),
                    Username("marco"),
                    Password("qwerty"),
                    PasswordModificationTime(datetime.datetime(2017, 5, 7, 9, 21, 33)),
                    LastModificationTime(datetime.datetime(2017, 5, 7, 9, 21, 33)),
                ],
            )

    def test_write(self):
        fp = io.BytesIO()
        KEY = b"secret"
        writer = PwsafeV3Writer(fp, KEY)
        header = [Version(3), UuidField.uuid4()]
        writer.write_record(header)
        uuid = UuidField.uuid4()
        title = Title("Github account")
        url = Url("https://github.com")
        username = Username("marcogiusti")
        password = Password("qwerty")
        record = [uuid, title, url, username, password]
        writer.write_record(record)
        writer.close()
        fp.seek(0)
        reader = PwsafeV3Reader(fp, KEY)
        expected_header, *records = list(reader)
        self.assertEqual(header, expected_header)
        self.assertEqual(records, [record])
