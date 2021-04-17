from typing import Any
from typing import List
from typing import Optional
from typing import Tuple


class Display:
    def __init__(
        self,
        backend: Optional[str] = None,
        visible: bool = False,
        size: Tuple[int, int] = (1024, 768),
        color_depth: int = 24,
        bgcolor: str = "black",
        use_xauth: bool = False,
        # check_startup=False,
        retries: int = 10,
        extra_args: List[str] = [],
        manage_global_env: bool = True,
        **kwargs: Any
    ) -> None:
        ...

    def start(self) -> "Display":
        ...

    def stop(self) -> "Display":
        ...
