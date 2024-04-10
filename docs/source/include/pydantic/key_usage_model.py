from django_ca.pydantic import KeyUsageModel

# Use key OR value from KEY_USAGE_NAMES:
KeyUsageModel(value=["key_agreement", "keyEncipherment"])
