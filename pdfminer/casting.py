from typing import Optional, Any


def safe_int(o: Any) -> Optional[int]:
    try:
        return int(o)
    except (TypeError, ValueError):
        return None
