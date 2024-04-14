CA_PROFILES = {
    "example-profile": {
        "extensions": {
            "certificate_policies": {
                "value": [
                    {"policy_identifier": "2.5.29.32.0"},
                    {
                        "policy_identifier": "1.3.6.1.5.5.7.2.1",
                        "policy_qualifiers": [
                            "https://ca.example.com/cps",
                            {"explicit_text": "my text"},
                        ],
                    },
                ],
            }
        }
    }
}
