from django_ca.pydantic import UnrecognizedExtensionModel, UnrecognizedExtensionValueModel

value = UnrecognizedExtensionValueModel(value="MTIz", oid="1.2.3")
UnrecognizedExtensionModel(critical=True, value=value)
