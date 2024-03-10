from pathlib import Path

from pydantic import BaseModel


class CreatePrivateKeyOptions(BaseModel):
    """Options for creating private keys."""

    password: bytes | None
    path: Path
    key_size: int
