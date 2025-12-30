INSTALLED_APPS = [
    # ... your other apps...
    "django_object_actions",
    "django_ca",
]

# You must configure STORAGES and add a "django-ca" alias.
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
            "location": "/where/to/store/certificates",
            "file_permissions_mode": 0o600,
            "directory_permissions_mode": 0o700,
        },
    },
}

# If you use ACMEv2 or Celery, you must configure a cache which shares data
# between different processes (e.g. between different Gunicorn worker processes).
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379",
        "OPTIONS": {"db": 1},
    }
}

# The hostname used by default for URLs in certificates. Your Django project
# should be available under this URL using HTTP (see below). If you use
# ACMEv2, you will also need HTTPS.
CA_DEFAULT_HOSTNAME = "ca.example.com"

# RECOMMENDED: Use Celery as an asynchronous task worker
CELERY_BROKER_URL = "redis://127.0.0.1:6379/0"
