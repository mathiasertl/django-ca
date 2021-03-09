# pylint: skip-file
import josepy as jose

from acme.mixins import ResourceMixin
from acme.mixins import TypeMixin


class Challenge(jose.TypedJSONObjectWithFields):
    ...


class ChallengeResponse(ResourceMixin, TypeMixin, jose.TypedJSONObjectWithFields):
    ...


class _TokenChallenge(Challenge):
    ...


class KeyAuthorizationChallengeResponse(ChallengeResponse):
    ...


class KeyAuthorizationChallenge(_TokenChallenge):
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
