CA_PROFILES = {
    "example-profile": {
        "extensions": {
            "authority_information_access": {
                "value": [
                    {
                        "access_method": "ocsp",
                        "access_location": {
                            "type": "URI",
                            "value": "http://ocsp.example.com",
                        },
                    },
                    {
                        "access_method": "ca_issuers",
                        "access_location": {"type": "URI", "value": "http://example.com"},
                    },
                ],
            }
        },
    },
}
