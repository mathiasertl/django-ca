CA_PROFILES = {
    "example-profile": {
        "extensions": {
            "crl_distribution_points": {
                "value": [
                    {
                        "full_name": [
                            {"type": "URI", "value": "https://ca.example.com/crl"}
                        ],
                    },
                    {
                        "relative_name": [{"oid": "commonName", "value": "example.com"}],
                        "crl_issuer": [
                            {"type": "URI", "value": "https://ca.example.com/issuer"}
                        ],
                        "reasons": ["key_compromise"],
                    },
                ],
            }
        }
    }
}
