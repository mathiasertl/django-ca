CA_OCSP_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.storages.StoragesOCSPBackend",
        "OPTIONS": {"storage_alias": "django-ca"},
    },
}
