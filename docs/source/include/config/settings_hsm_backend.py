CA_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.hsm.HSMBackend",
        "OPTIONS": {
            "library_path": "/usr/lib/softhsm/libsofthsm2.so",
            "token": "my_token_label",
            "user_pin": "secret_user_pin",
        },
    },
}