from pathlib import Path

from pydantic import BaseModel


class StorePrivateKeyOptions(BaseModel):
    """Options for storing a private key."""

    path: Path
    password: bytes | None
