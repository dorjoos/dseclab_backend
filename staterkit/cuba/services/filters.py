from datetime import date, datetime, timedelta
from typing import Tuple


def build_date_filter(query, column, date_filter: str) -> Tuple[object, str]:
    """
    Apply a reusable date filter on a SQLAlchemy query.

    Args:
        query: Base SQLAlchemy query.
        column: Model datetime column to filter on.
        date_filter: One of 'today', 'week', 'month', 'all' or ''.

    Returns:
        (query, normalized_date_filter)
    """
    today = date.today()
    normalized = (date_filter or "").strip().lower() or "all"

    if normalized == "today":
        query = query.filter(column >= datetime.combine(today, datetime.min.time()))
    elif normalized == "week":
        week_ago = today - timedelta(days=7)
        query = query.filter(
            column >= datetime.combine(week_ago, datetime.min.time())
        )
    elif normalized == "month":
        month_ago = today - timedelta(days=30)
        query = query.filter(
            column >= datetime.combine(month_ago, datetime.min.time())
        )
    elif normalized == "all":
        # No date restriction
        pass
    else:
        # Fallback to all
        normalized = "all"

    return query, normalized


