from .constants import HEADER_DATE_FORMAT
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path


# Parse HTTP header date format
def from_http_date(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value, HEADER_DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# Convert datetime to HTTP header date format
def to_http_date(value: datetime) -> str:
    return value.strftime(HEADER_DATE_FORMAT)


# Generate weak ETag
def file_etag(path: Path) -> str:
    stat = path.stat()
    return f'W/"{stat.st_size}-{stat.st_mtime_ns}"'
