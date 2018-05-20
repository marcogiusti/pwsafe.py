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
import sys
import unittest
import uuid

from pwsafe import (
    PwsafeV3Reader, PwsafeV3Writer, AField, Version, END, UUID, Title,
    Username, Password, NonDefaultPreferences, Url, LastModificationTime, End,
    TextField, IntField
)


is_linux = sys.platform == 'linux'


class TestFields(unittest.TestCase):

    def test_str(self):
        self.assertTrue(issubclass(Username, AField))
        self.assertTrue(issubclass(Username, str))

    def test_str_serialize(self):
        expected = bytes.fromhex('6d6172636f')
        self.assertEqual(Username('marco').to_bytes(), expected)

    def test_datetime(self):
        self.assertTrue(issubclass(LastModificationTime, AField))
        self.assertTrue(issubclass(LastModificationTime, datetime.datetime))

    def test_datetime_serialize(self):
        expected = bytes.fromhex('280d1a59')
        modified = LastModificationTime(2017, 5, 15, 22, 18, 48)
        self.assertEqual(modified.to_bytes(), expected)

    def test_uuid(self):
        self.assertTrue(issubclass(UUID, AField))
        self.assertTrue(issubclass(UUID, uuid.UUID))

    def test_uuid_serialize(self):
        exp = bytes.fromhex('95675c664da54513b3c36229091c85bf')
        uid = UUID('665c6795-a54d-1345-b3c3-6229091c85bf')
        self.assertEqual(uid.to_bytes(), exp)

    def test_int(self):
        self.assertTrue(issubclass(Version, AField))
        self.assertTrue(issubclass(Version, int))

    def test_int_serialize(self):
        expected = bytes.fromhex('0003')
        self.assertEqual(Version(768).to_bytes(), expected)

    def test_end(self):
        self.assertIs(End.from_bytes(b'~~noise~~'), END)

    def test_end_serialize(self):
        self.assertEqual(END.to_bytes(), b'')

    def test_subclass(self):
        MyField = TextField.subclass('MyField', 0x0c)
        self.assertTrue(issubclass(MyField, AField))
        self.assertTrue(issubclass(MyField, str))

    def test_int_subclass(self):
        MyIntField = IntField.subclass('MyIntField', 0x0c, 4)
        self.assertTrue(issubclass(MyIntField, AField))
        self.assertTrue(issubclass(MyIntField, int))


class TestReadWrite(unittest.TestCase):

    EMPTY_DB = abspath(joinpath(dirname(__file__), 'empty.psafe3'))
    TEST_DB = abspath(joinpath(dirname(__file__), 'test.psafe3'))
    PWD = b'test'

    def test_is_pwsafe(self):
        self.assertTrue(PwsafeV3Reader.is_pwsafe(self.EMPTY_DB))

    @unittest.skipUnless(is_linux, 'test supported only on linux')
    def test_is_no_pwsafev3(self):
        self.assertFalse(PwsafeV3Reader.is_pwsafe('/dev/zero'))

    def test_empty_db(self):
        with PwsafeV3Reader.open(self.EMPTY_DB, self.PWD) as dbfile:
            header, *records = list(dbfile)
            self.assertEqual(header, [0x300, UUID(int=0), 'B 24 1'])
            self.assertEqual(records, [])

    def test_db(self):
        with PwsafeV3Reader.open(self.TEST_DB, self.PWD) as dbfile:
            header, r1, r2 = list(dbfile)
            self.assertEqual(header, [0x300, UUID(int=0), 'B 24 1'])
            self.assertEqual(
                r1,
                [
                    uuid.UUID('665c6795-a54d-1345-b3c3-6229091c85bf'),
                    'test',
                    'marco',
                    'some notes',
                    'qwerty',
                    datetime.datetime(2017, 5, 7, 9, 20, 23),
                    datetime.datetime(2017, 5, 7, 9, 20, 23),
                    'http://www.example.com/'
                ]
            )
            self.assertEqual(
                r2,
                [
                    uuid.UUID('12084a3c-d97d-2346-a089-322777c3e016'),
                    'group1.group2.group3',
                    'test nested',
                    'marco',
                    'qwerty',
                    datetime.datetime(2017, 5, 7, 9, 21, 33),
                    datetime.datetime(2017, 5, 7, 9, 21, 33)
                ]
            )

    def test_write(self):
        fp = io.BytesIO()
        KEY = b'secret'
        writer = PwsafeV3Writer(fp, KEY)
        header = [Version(3), UUID.uuid4()]
        writer.write_record(header)
        uuid = UUID.uuid4()
        title = Title('Github account')
        url = Url('https://github.com')
        username = Username('marcogiusti')
        password = Password('qwerty')
        record = [uuid, title, url, username, password]
        writer.write_record(record)
        writer.close()
        fp.seek(0)
        reader = PwsafeV3Reader(fp, KEY)
        expected_header, *records = list(reader)
        self.assertEqual(header, expected_header)
        self.assertEqual(records, [record])
