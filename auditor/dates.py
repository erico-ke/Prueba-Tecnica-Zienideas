"""Utilidades de fechas de Graph."""
from datetime import datetime, timezone
from typing import Optional


def parse_graph_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parsea fechas de Graph ('2025-01-01T10:00:00.1234567Z').

    Python 3.10 no acepta la 'Z' ni más de 6 decimales en fromisoformat.
    """
    if not value:
        return None
    value = value.rstrip("Z")
    if "." in value:
        main, frac = value.split(".", 1)
        value = f"{main}.{frac[:6]}"
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
