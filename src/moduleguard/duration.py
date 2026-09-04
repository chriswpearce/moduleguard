"""Strict licence-duration parsing and UTC calendar arithmetic."""

import calendar
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .errors import DurationError

_DURATION_RE = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>d|mo|y)$")


@dataclass(frozen=True)
class Duration:
    """A positive, normalized licence duration."""

    amount: int
    unit: str

    def __str__(self) -> str:
        return "{}{}".format(self.amount, self.unit)


def ensure_utc(value: datetime) -> datetime:
    """Normalize an aware datetime to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise DurationError("A timezone-aware UTC date and time is required")
    return value.astimezone(timezone.utc)


def parse_duration(value: str) -> Duration:
    """Parse durations such as 7d, 1mo, 6mo, or 1y."""
    match = _DURATION_RE.fullmatch(value.strip())
    if match is None:
        raise DurationError(
            "Invalid duration {!r}; use a positive value such as 7d, 1mo, 6mo, or 1y".format(
                value
            )
        )
    amount = int(match.group("amount"))
    if amount > 12000:
        raise DurationError("Duration is unreasonably large")
    return Duration(amount=amount, unit=match.group("unit"))


def _add_months(value: datetime, months: int) -> datetime:
    month_index = value.year * 12 + value.month - 1 + months
    year, zero_based_month = divmod(month_index, 12)
    if not 1 <= year <= 9999:
        raise DurationError("Duration produces a date outside the supported range")
    month = zero_based_month + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def calculate_expiry(starts_at: datetime, duration: Duration) -> datetime:
    """Calculate expiry using exact days and clipped calendar months/years."""
    starts_at = ensure_utc(starts_at)
    try:
        if duration.unit == "d":
            return starts_at + timedelta(days=duration.amount)
        if duration.unit == "mo":
            return _add_months(starts_at, duration.amount)
        if duration.unit == "y":
            return _add_months(starts_at, duration.amount * 12)
    except (OverflowError, ValueError) as exc:
        raise DurationError("Duration produces an unsupported expiry date") from exc
    raise DurationError("Unsupported duration unit: {}".format(duration.unit))


def parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 date/time that includes a UTC offset or trailing Z."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise DurationError(
            "Invalid date/time {!r}; use ISO-8601, for example 2027-09-03T12:00:00Z".format(
                value
            )
        ) from exc
    return ensure_utc(parsed).replace(microsecond=0)


def to_utc_text(value: datetime) -> str:
    """Format an aware datetime as canonical second-precision UTC text."""
    return ensure_utc(value).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
