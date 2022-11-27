# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Test module testing :py:class:`~django_ca.subject.Subject`."""

import typing
from contextlib import contextmanager

from cryptography import x509
from cryptography.x509.oid import NameOID

from django.test import TestCase

from ..deprecation import RemovedInDjangoCA124Warning
from ..subject import Subject


class TestSubject(TestCase):
    """Main test case class for :py:class:`~django_ca.subject.Subject`."""

    @contextmanager
    def assertRemovedSubjectWarning(self) -> typing.Iterator[None]:  # pylint: disable=invalid-name
        """Temporary manager for removed extension wrapper classes."""
        msg = r"^django_ca\.subject\.Subject will be removed in 1\.24\.0\.$"
        with self.assertWarnsRegex(RemovedInDjangoCA124Warning, msg):
            yield

    def test_init_str(self) -> None:
        """Test creation with a str."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(str(Subject("/CN=example.com")), "/CN=example.com")
            self.assertEqual(
                str(Subject("/C=AT/L=Vienna/O=example/CN=example.com")),
                "/C=AT/L=Vienna/O=example/CN=example.com",
            )
            self.assertEqual(str(Subject("/O=/CN=example.com")), "/CN=example.com")

    def test_init_dict(self) -> None:
        """Test creation with a dict."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(str(Subject({"CN": "example.com"})), "/CN=example.com")
            self.assertEqual(
                str(Subject({"C": "AT", "L": "Vienna", "O": "example", "CN": "example.com"})),
                "/C=AT/L=Vienna/O=example/CN=example.com",
            )
            self.assertEqual(str(Subject({"C": "", "CN": "example.com"})), "/CN=example.com")

    def test_init_list(self) -> None:
        """Test creation with a list or tuple."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(str(Subject([("CN", "example.com")])), "/CN=example.com")
            self.assertEqual(
                str(Subject([("C", "AT"), ("L", "Vienna"), ("O", "example"), ("CN", "example.com")])),
                "/C=AT/L=Vienna/O=example/CN=example.com",
            )
            self.assertEqual(str(Subject([("C", "")])), "/")

            # we also accept tuples
            self.assertEqual(str(Subject((("CN", "example.com"),))), "/CN=example.com")
            self.assertEqual(
                str(Subject((("C", "AT"), ("L", "Vienna"), ("O", "example"), ("CN", "example.com")))),
                "/C=AT/L=Vienna/O=example/CN=example.com",
            )
            self.assertEqual(
                str(
                    Subject(
                        (
                            ("C", ""),
                            ("CN", "example.com"),
                        )
                    )
                ),
                "/CN=example.com",
            )

    def test_init_empty(self) -> None:
        """Test creating an empty subject."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(str(Subject()), "/")
            self.assertEqual(str(Subject([])), "/")
            self.assertEqual(str(Subject({})), "/")
            self.assertEqual(str(Subject("")), "/")
            self.assertEqual(str(Subject(x509.Name(attributes=[]))), "/")

    def test_init_name(self) -> None:
        """Test creation with an x509.Name."""
        name = x509.Name(
            attributes=[
                x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="AT"),
                x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com"),
            ]
        )
        with self.assertRemovedSubjectWarning():
            self.assertEqual(str(Subject(name)), "/C=AT/CN=example.com")

    def test_init_order(self) -> None:
        """Test that order is honored."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(
                str(
                    Subject(
                        [
                            ("C", "AT"),
                            ("O", "example"),
                            ("L", "Vienna"),
                            ("CN", "example.com"),
                        ]
                    )
                ),
                "/C=AT/L=Vienna/O=example/CN=example.com",
            )

    def test_init_multiple(self) -> None:
        """Test creating a subject with multiple OUs."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(
                str(
                    Subject(
                        [
                            ("C", "AT"),
                            ("OU", "foo"),
                            ("OU", "bar"),
                            ("L", "Vienna"),
                            ("CN", "example.com"),
                        ]
                    )
                ),
                "/C=AT/L=Vienna/OU=foo/OU=bar/CN=example.com",
            )

        # C should not occur multiple times
        with self.assertRaisesRegex(ValueError, r"^C: Must not occur multiple times$"):
            with self.assertRemovedSubjectWarning():
                Subject([("C", "AT"), ("C", "US")])

    def test_init_invalid_type(self) -> None:
        """Test creating a subject with an invalid type."""
        with self.assertRemovedSubjectWarning():
            with self.assertRaisesRegex(ValueError, r"^Invalid subject: 33$"):
                Subject(33)  # type: ignore[arg-type]

    def test_unknown_oid(self) -> None:
        """Test passing an unknown OID."""

        with self.assertRemovedSubjectWarning():
            with self.assertRaisesRegex(ValueError, r"^Invalid OID: UNKNOWN$"):
                Subject([("UNKNOWN", "none")])

    def test_contains(self) -> None:
        """Test the ``in`` operator."""
        with self.assertRemovedSubjectWarning():
            self.assertIn("CN", Subject("/CN=example.com"))
            self.assertIn(NameOID.COMMON_NAME, Subject("/CN=example.com"))
            self.assertNotIn(NameOID.LOCALITY_NAME, Subject("/CN=example.com"))
            self.assertNotIn(NameOID.COUNTRY_NAME, Subject("/CN=example.com"))
            self.assertIn(NameOID.COUNTRY_NAME, Subject("/C=AT/CN=example.com"))
            self.assertIn(NameOID.COMMON_NAME, Subject("/C=AT/CN=example.com"))

    def test_getitem(self) -> None:
        """Test dictionary-style value lookup (s['a'])."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(Subject("/CN=example.com")["CN"], "example.com")
            self.assertEqual(Subject("/C=AT/CN=example.com")["C"], "AT")
            self.assertEqual(Subject("/C=AT/CN=example.com")["CN"], "example.com")

            # try NameOID:
            self.assertEqual(Subject("/CN=example.com")[NameOID.COMMON_NAME], "example.com")
            self.assertEqual(Subject("/C=AT/CN=example.com")[NameOID.COUNTRY_NAME], "AT")
            self.assertEqual(Subject("/C=AT/CN=example.com")[NameOID.COMMON_NAME], "example.com")

            # OUs
            self.assertEqual(Subject("/C=AT/OU=foo/CN=example.com")["OU"], ["foo"])
            self.assertEqual(Subject("/C=AT/OU=foo/OU=bar/CN=example.com")["OU"], ["foo", "bar"])

            # test keyerror
            with self.assertRaisesRegex(KeyError, r"^'L'$"):
                # pylint: disable=expression-not-assigned
                Subject("/C=AT/OU=foo/CN=example.com")["L"]

            with self.assertRaisesRegex(KeyError, r"^'L'$"):
                # pylint: disable=expression-not-assigned
                Subject("/C=AT/OU=foo/CN=example.com")[NameOID.LOCALITY_NAME]

    def test_eq(self) -> None:
        """Test subject equality."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(Subject("/CN=example.com"), Subject([("CN", "example.com")]))
            self.assertNotEqual(Subject("/CN=example.com"), Subject([("CN", "example.org")]))

            # Also make sure that objects are equal regardless of added order
            self.assertEqual(Subject("/CN=example.com"), Subject("/CN=example.com"))
            self.assertEqual(Subject("/C=AT/CN=example.com"), Subject("/CN=example.com/C=AT"))

    def test_len(self) -> None:
        """Test the len() function."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(len(Subject("")), 0)
            self.assertEqual(len(Subject("/C=AT")), 1)
            self.assertEqual(len(Subject("/C=AT/CN=example.com")), 2)
            self.assertEqual(len(Subject("/C=AT/OU=foo/CN=example.com")), 3)
            self.assertEqual(len(Subject("/C=AT/OU=foo/OU=bar/CN=example.com")), 3)

    def test_repr(self) -> None:
        """Test repr()."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(repr(Subject("/C=AT/CN=example.com")), 'Subject("/C=AT/CN=example.com")')
            self.assertEqual(repr(Subject("/CN=example.com/C=AT")), 'Subject("/C=AT/CN=example.com")')
            self.assertEqual(repr(Subject("/cn=example.com/c=AT")), 'Subject("/C=AT/CN=example.com")')

    def test_setitem(self) -> None:
        """Test dictionary style item setting (s['a'] = b)."""
        with self.assertRemovedSubjectWarning():
            subj = Subject("")
            subj["C"] = "AT"
            self.assertEqual(subj, Subject("/C=AT"))
            subj["C"] = "DE"
            self.assertEqual(subj, Subject("/C=DE"))
            subj[NameOID.COUNTRY_NAME] = ["AT"]
            self.assertEqual(subj, Subject("/C=AT"))

            subj = Subject("/CN=example.com")
            subj[NameOID.COUNTRY_NAME] = ["AT"]
            self.assertEqual(subj, Subject("/C=AT/CN=example.com"))

            # also test multiples
            subj = Subject("/C=AT/CN=example.com")
            subj["OU"] = ["foo", "bar"]
            self.assertEqual(subj, Subject("/C=AT/OU=foo/OU=bar/CN=example.com"))

            with self.assertRaisesRegex(ValueError, r"L: Must not occur multiple times"):
                subj["L"] = ["foo", "bar"]
            self.assertEqual(subj, Subject("/C=AT/OU=foo/OU=bar/CN=example.com"))

            # setting an empty str or list effectively removes the value
            subj = Subject("/C=AT/CN=example.com")
            subj["C"] = None
            self.assertEqual(subj, Subject("/CN=example.com"))

            subj = Subject("/C=AT/CN=example.com")
            subj["C"] = ""
            self.assertEqual(subj, Subject("/CN=example.com"))

            subj = Subject("/C=AT/CN=example.com")
            subj["C"] = []
            self.assertEqual(subj, Subject("/CN=example.com"))

        with self.assertRaisesRegex(ValueError, r"^Value must be str or list$"):
            subj["C"] = 33  # type: ignore[assignment]

    def test_get(self) -> None:
        """Test Subject.get()."""
        with self.assertRemovedSubjectWarning():
            self.assertEqual(Subject("/CN=example.com").get("CN"), "example.com")
            self.assertEqual(Subject("/C=AT/CN=example.com").get("C"), "AT")
            self.assertEqual(Subject("/C=AT/CN=example.com").get("CN"), "example.com")

            # try NameOID:
            self.assertEqual(Subject("/CN=example.com").get(NameOID.COMMON_NAME), "example.com")
            self.assertEqual(Subject("/C=AT/CN=example.com").get(NameOID.COUNTRY_NAME), "AT")
            self.assertEqual(Subject("/C=AT/CN=example.com").get(NameOID.COMMON_NAME), "example.com")

            # OUs
            self.assertEqual(Subject("/C=AT/OU=foo/CN=example.com").get("OU"), ["foo"])
            self.assertEqual(Subject("/C=AT/OU=foo/OU=bar/CN=example.com").get("OU"), ["foo", "bar"])

            # test that default doesn't overwrite anytying
            self.assertEqual(Subject("/CN=example.com").get("CN", "x"), "example.com")
            self.assertEqual(Subject("/C=AT/CN=example.com").get("C", "x"), "AT")
            self.assertEqual(Subject("/C=AT/CN=example.com").get("CN", "x"), "example.com")

            # test default value
            self.assertIsNone(Subject("/C=AT/OU=foo/CN=example.com").get("L"))
            self.assertEqual(Subject("/C=AT/OU=foo/CN=example.com").get("L", "foo"), "foo")
            self.assertIsNone(Subject("/C=AT/OU=foo/CN=example.com").get(NameOID.LOCALITY_NAME))
            self.assertEqual(Subject("/C=AT/OU=foo/CN=example.com").get(NameOID.LOCALITY_NAME, "foo"), "foo")

    def test_iters(self) -> None:
        """Test various iterators (keys(), values(), items())."""
        with self.assertRemovedSubjectWarning():
            subj = Subject("/CN=example.com")
        self.assertCountEqual(subj.keys(), ["CN"])
        self.assertCountEqual(subj.values(), ["example.com"])
        self.assertCountEqual(subj.items(), [("CN", "example.com")])

        with self.assertRemovedSubjectWarning():
            subj = Subject("/C=AT/O=Org/OU=foo/OU=bar/CN=example.com")
        self.assertCountEqual(subj.keys(), ["C", "O", "OU", "CN"])
        self.assertCountEqual(subj.values(), ["AT", "Org", "foo", "bar", "example.com"])
        self.assertCountEqual(
            subj.items(), [("C", "AT"), ("O", "Org"), ("OU", "foo"), ("OU", "bar"), ("CN", "example.com")]
        )

        keys = ["C", "O", "OU", "CN"]
        for i, key in enumerate(subj):
            self.assertEqual(key, keys[i])

    def test_setdefault(self) -> None:
        """Test Subject.setdefault()."""
        with self.assertRemovedSubjectWarning():
            subj = Subject("/CN=example.com")
            subj.setdefault("CN", "example.org")
            self.assertEqual(subj, Subject("/CN=example.com"))

            subj.setdefault(NameOID.COMMON_NAME, "example.org")
            self.assertEqual(subj, Subject("/CN=example.com"))

            # set a new value
            subj.setdefault("C", "AT")
            self.assertEqual(subj, Subject("/C=AT/CN=example.com"))
            subj.setdefault("C", "DE")
            self.assertEqual(subj, Subject("/C=AT/CN=example.com"))

            # ok, now set multiple OUs
            subj = Subject("/C=AT/CN=example.com")
            subj.setdefault("OU", ["foo", "bar"])
            self.assertEqual(subj, Subject("/C=AT/OU=foo/OU=bar/CN=example.com"))

        # We can't set multiple C's
        with self.assertRaisesRegex(ValueError, r"L: Must not occur multiple times"):
            subj.setdefault("L", ["AT", "DE"])
        with self.assertRemovedSubjectWarning():
            self.assertEqual(subj, Subject("/C=AT/OU=foo/OU=bar/CN=example.com"))

        with self.assertRemovedSubjectWarning():
            subj = Subject()
        with self.assertRaisesRegex(ValueError, r"^Value must be str or list$"):
            subj.setdefault("C", 33)  # type: ignore[arg-type]

    def test_clear_copy(self) -> None:
        """Test that a subjects clear() does not affect the copy."""
        with self.assertRemovedSubjectWarning():
            subj = Subject("/O=Org/CN=example.com")
            subj2 = subj.copy()
            subj.clear()
            self.assertFalse(subj)
            self.assertTrue(subj2)

    def test_update(self) -> None:
        """Test Subject.update()."""
        with self.assertRemovedSubjectWarning():
            merged = Subject("/C=AT/O=Org/CN=example.net")

            subj = Subject("/O=Org/CN=example.com")
            subj.update(Subject("/C=AT/CN=example.net"))
            self.assertEqual(subj, merged)

            subj = Subject("/O=Org/CN=example.com")
            subj.update(Subject("/C=AT/CN=example.net").name)
            self.assertEqual(subj, merged)

            subj = Subject("/O=Org/CN=example.com")
            subj.update({"C": "AT", "CN": "example.net"})
            self.assertEqual(subj, merged)

            subj = Subject("/O=Org/CN=example.com")
            subj.update([("C", "AT"), ("CN", "example.net")])
            self.assertEqual(subj, merged)

            subj = Subject("/O=Org/CN=example.com")
            subj.update([("C", "AT")], CN="example.net")
            self.assertEqual(subj, merged)

            subj = Subject("/O=Org/CN=example.com")
            subj.update(C="AT", CN="example.net")
            self.assertEqual(subj, merged)

            subj = Subject("/O=Org/CN=example.com")
            subj.update([("C", "DE")], C="AT", CN="example.net")
            self.assertEqual(subj, merged)

            subj = Subject("/O=Org/CN=example.com")
            subj.update("/C=AT/CN=example.net")
            self.assertEqual(subj, merged)

    def test_fields(self) -> None:
        """Test the fields property."""
        with self.assertRemovedSubjectWarning():
            subj = Subject("")
            self.assertEqual(list(subj.fields), [])

            subj = Subject("/C=AT")
            self.assertEqual(list(subj.fields), [(NameOID.COUNTRY_NAME, "AT")])

            subj = Subject("/C=AT/CN=example.com")
            self.assertEqual(
                list(subj.fields), [(NameOID.COUNTRY_NAME, "AT"), (NameOID.COMMON_NAME, "example.com")]
            )

            subj = Subject("/C=AT/OU=foo/CN=example.com")
            self.assertEqual(
                list(subj.fields),
                [
                    (NameOID.COUNTRY_NAME, "AT"),
                    (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                    (NameOID.COMMON_NAME, "example.com"),
                ],
            )
            subj = Subject("/C=AT/OU=foo/OU=bar/CN=example.com")
            self.assertEqual(
                list(subj.fields),
                [
                    (NameOID.COUNTRY_NAME, "AT"),
                    (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                    (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar"),
                    (NameOID.COMMON_NAME, "example.com"),
                ],
            )

            # Also test order
            subj = Subject("/CN=example.com/C=AT/OU=foo/OU=bar")
            self.assertEqual(
                list(subj.fields),
                [
                    (NameOID.COUNTRY_NAME, "AT"),
                    (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                    (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar"),
                    (NameOID.COMMON_NAME, "example.com"),
                ],
            )
