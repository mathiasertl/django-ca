CA_PROFILES = {
    "example-profile": {
        "extensions": {
            # NOTE: "1.3.6.1.5.5.7.3.1" is equivalent to "serverAuth", but any valid
            # dotted string can be given here.
            "extended_key_usage": {"value": ["clientAuth", "1.3.6.1.5.5.7.3.1"]},
        }
    }
}
