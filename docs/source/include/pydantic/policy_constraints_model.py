from django_ca.pydantic import PolicyConstraintsModel, PolicyConstraintsValueModel

value = PolicyConstraintsValueModel(require_explicit_policy=0, inhibit_policy_mapping=1)
PolicyConstraintsModel(value=value)
