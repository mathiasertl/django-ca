from django_ca.pydantic import GeneralNameModel, OtherNameModel

other_name = OtherNameModel(oid="1.2.3", type="UTF8String", value="some_string")
GeneralNameModel(type="otherName", value=other_name)
