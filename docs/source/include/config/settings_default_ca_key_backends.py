STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
    "django-ca": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {
            "location": "files/",
            "file_permissions_mode": 0o600,
            "directory_permissions_mode": 0o700,
        },
    },
}

CA_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.storages.StoragesBackend",
        "OPTIONS": {"storage_alias": "django-ca"},
    }
}
