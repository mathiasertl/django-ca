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

"""Various type aliases used throught different models."""

# pylint: disable=unsubscriptable-object; https://github.com/PyCQA/pylint/issues/3882

from typing import TYPE_CHECKING
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Union

from cryptography import x509

DistributionPointType = Dict[str, Union[List[str], str]]

SerializedNoticeReference = Dict[str, Union[str, List[int]]]
SerializedPolicyQualifier = Union[str, Dict[str, Union[str, SerializedNoticeReference]]]
SerializedPolicyQualifiers = Optional[List[SerializedPolicyQualifier]]

# Looser variants of the above for incoming arguments
LooseNoticeReference = Mapping[str, Union[str, Iterable[int]]]  # List->Iterable/Dict->Mapping
LoosePolicyQualifier = Union[str, Mapping[str, Union[str, LooseNoticeReference]]]  # Dict->Mapping

# Parsable arguments
ParsablePolicyQualifier = Union[str, x509.UserNotice, LoosePolicyQualifier]
ParsablePolicyIdentifier = Union[str, x509.ObjectIdentifier]
ParsablePolicyInformation = Dict[str, Union[ParsablePolicyQualifier, ParsablePolicyQualifier]]
PolicyQualifier = Union[str, x509.UserNotice]

# extensions
if TYPE_CHECKING:
    GenericExtensionType = x509.Extension[x509.ExtensionType]
    SubjectAlternativeNameType = x509.Extension[x509.SubjectAlternativeName]
    IssuerAlternativeNameType = x509.Extension[x509.IssuerAlternativeName]
    AlternativeNameType = Union[SubjectAlternativeNameType, IssuerAlternativeNameType]
else:
    GenericExtensionType = x509.Extension
    SubjectAlternativeNameType = x509.Extension
    IssuerAlternativeNameType = x509.Extension
    AlternativeNameType = x509.Extension
