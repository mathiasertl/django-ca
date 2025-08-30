###################################
``django_ca.constants`` - constants
###################################

.. automapping:: django_ca.constants.ACCESS_METHOD_TYPES
   :annotation:

.. automapping:: django_ca.constants.CERTIFICATE_EXTENSION_KEYS
   :no-value:

.. automapping:: django_ca.constants.CERTIFICATE_REVOCATION_LIST_ENCODING_TYPES
   :no-value:

.. automapping:: django_ca.constants.ELLIPTIC_CURVE_TYPES
   :annotation:

.. automapping:: django_ca.constants.END_ENTITY_CERTIFICATE_EXTENSION_KEYS
   :no-value:

.. automapping:: django_ca.constants.EXTENDED_KEY_USAGE_NAMES
   :no-value:

.. automapping:: django_ca.constants.EXTENSION_DEFAULT_CRITICAL
   :no-value:

.. automapping:: django_ca.constants.EXTENSION_KEYS
   :no-value:

.. autodata:: django_ca.constants.EXTENSION_KEY_OIDS
   :no-value:

.. automapping:: django_ca.constants.GENERAL_NAME_TYPES
   :no-value:

.. automapping:: django_ca.constants.HASH_ALGORITHM_NAMES
   :annotation:
   :no-value:

.. autodata:: django_ca.constants.HASH_ALGORITHM_TYPES
   :no-value:
   :annotation:

.. automapping:: django_ca.constants.KEY_USAGE_NAMES
   :no-value:

.. autodata:: django_ca.constants.MULTIPLE_OIDS
   :no-value:

.. automapping:: django_ca.constants.NAME_OID_NAMES
   :no-value:

.. automapping:: django_ca.constants.NAME_OID_TYPES
   :no-value:

.. automapping:: django_ca.constants.TLS_FEATURE_NAMES
   :no-value:

.. autoclass:: django_ca.constants.ReasonFlags

.. automapping:: django_ca.constants.SIGNATURE_HASH_ALGORITHM_NAMES_WITH_LEGACY
   :annotation:
   :no-value:

.. autodata:: django_ca.constants.SIGNATURE_HASH_ALGORITHM_TYPES_WITH_LEGACY
   :no-value:
   :annotation:

.. _constants-other-names:

****************
OtherName values
****************

The two mappings given here give a list of types that can be used for specifying OtherName values. They are a
subset of the values supported in :manpage:`ASN1_GENERATE_NCONF(3SSL)`.

.. automapping:: django_ca.constants.OTHER_NAME_TYPES
   :no-value:

Aliases are shortcuts for other types, for example ``BOOL`` is equivalent to ``BOOLEAN``:

.. automapping:: django_ca.constants.OTHER_NAME_ALIASES
   :no-value:
