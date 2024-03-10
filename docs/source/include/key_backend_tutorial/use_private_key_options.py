from pydantic import BaseModel


class UsePrivateKeyOptions(BaseModel):
    """Options for using a private key."""

    password: bytes | None
