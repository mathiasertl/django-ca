# pylint: skip-file
import josepy as jose


class ResourceBody(jose.JSONObjectWithFields):
    resource_type: str


class Order(ResourceBody):
    ...


class NewOrder(Order):
    ...
