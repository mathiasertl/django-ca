EXTEND_URL_PATTERNS = [
    # Add a simple view, equivalent to:
    #   path("/path", yourapp.views.YourView.as_view())
    {
        "route": "/path",
        "view": {
            # Can be a function or class-based view:
            "view": "yourapp.views.YourView",
            # Optional: Additional arguments for django.urls.path()
            # "name": "simple-view"
            # "kwargs": {
            #     "foo": "bar",
            # }
        },
    },
    # Add an URL with re_path(),equivalent to:
    #   re_path("^path/(?P<username>\\w+)/$", yourapp.views.YourView.as_view())
    {
        "func": "re_path",
        "route": r"^path/(?P<username>\w+)/$",
        "view": {
            # Can be a function or class-based view:
            "view": "yourapp.views.YourView",
            # Optional: Additional arguments passed to as_view():
            # "initkwargs": {
            #   "foo": "bar",
            # }
        },
        # Optional: Additional arguments for django.urls.re_path()
        # "name": "re-simple-view",
        # "kwargs": {
        #     "foo": "bar",
        # }
    },
    # Add a path via django.urls.include(), equivalent to:
    #   path("/included-path/", include("yourapp.urls"))
    {
        "route": "/included-path/",
        "view": {
            "module": "yourapp.urls",
            # Optional: override the namespace
            # "namespace": "yourapp",
        },
    },
]
