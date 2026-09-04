"""Duration and expiry behavior."""

from datetime import datetime, timezone

import pytest

from moduleguard.duration import calculate_expiry, parse_duration, parse_utc, to_utc_text
from moduleguard.errors import DurationError

UTC = timezone.utc


@pytest.mark.parametrize(
    ("text", "amount", "unit"),
    [("7d", 7, "d"), ("1mo", 1, "mo"), ("6mo", 6, "mo"), ("1y", 1, "y")],
)
def test_parse_duration(text, amount, unit):
    duration = parse_duration(text)
    assert duration.amount == amount
    assert duration.unit == unit
    assert str(duration) == text


@pytest.mark.parametrize("text", ["", "0d", "-1d", "1m", "d7", "1.5d", " 0mo ", "12001d"])
def test_reject_invalid_durations(text):
    with pytest.raises(DurationError):
        parse_duration(text)


def test_days_are_exact_24_hour_periods():
    start = datetime(2026, 9, 3, 12, 30, tzinfo=UTC)
    assert calculate_expiry(start, parse_duration("7d")) == datetime(
        2026, 9, 10, 12, 30, tzinfo=UTC
    )


def test_calendar_month_clips_to_month_end():
    start = datetime(2027, 1, 31, 9, 0, tzinfo=UTC)
    assert calculate_expiry(start, parse_duration("1mo")) == datetime(
        2027, 2, 28, 9, 0, tzinfo=UTC
    )


def test_six_calendar_months():
    start = datetime(2026, 9, 30, 9, 0, tzinfo=UTC)
    assert calculate_expiry(start, parse_duration("6mo")) == datetime(
        2027, 3, 30, 9, 0, tzinfo=UTC
    )


def test_calendar_year_clips_leap_day():
    start = datetime(2028, 2, 29, 9, 0, tzinfo=UTC)
    assert calculate_expiry(start, parse_duration("1y")) == datetime(
        2029, 2, 28, 9, 0, tzinfo=UTC
    )


def test_parse_and_format_utc():
    parsed = parse_utc("2027-09-03T13:00:00+01:00")
    assert to_utc_text(parsed) == "2027-09-03T12:00:00Z"


def test_reject_naive_timestamp():
    with pytest.raises(DurationError):
        parse_utc("2027-09-03T12:00:00")
