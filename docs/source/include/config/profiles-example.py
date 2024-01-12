CA_PROFILES = {
    "example": {  # actually a duplicate of the predefined "client" profile
        "description": "An example profile.",
        "extensions": {
            "key_usage": {"value": ["digitalSignature"]},
            "extended_key_usage": {"value": ["clientAuth"]},
        },
    },
}
