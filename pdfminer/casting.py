from typing import Any, Optional


def safe_int(o: Any) -> Optional[int]:
    try:
        return int(o)
    except (TypeError, ValueError):
        return None
