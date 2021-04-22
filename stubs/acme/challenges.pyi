# pylint: skip-file
from typing import Type

import josepy as jose
from cryptography.hazmat.primitives import hashes

from acme.mixins import ResourceMixin
from acme.mixins import TypeMixin


class Challenge(jose.TypedJSONObjectWithFields):
    ...


class ChallengeResponse(ResourceMixin, TypeMixin, jose.TypedJSONObjectWithFields):
    ...


class _TokenChallenge(Challenge):
    TOKEN_SIZE: int
    token = str


class KeyAuthorizationChallengeResponse(ChallengeResponse):
    thumbprint_hash_function = Type[hashes.HashAlgorithm]


class KeyAuthorizationChallenge(_TokenChallenge):
    typ: str

    def __init__(self, token: bytes):
        ...


class DNS01(KeyAuthorizationChallenge):
    ...


class HTTP01(KeyAuthorizationChallenge):
    ...


class HTTP01Response(KeyAuthorizationChallengeResponse):
    ...


class TLSALPN01(KeyAuthorizationChallenge):
    ...


class TLSALPN01Response(KeyAuthorizationChallengeResponse):
    ...
