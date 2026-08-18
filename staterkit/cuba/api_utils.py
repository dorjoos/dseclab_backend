import html
from typing import Any

from flask import Response, jsonify


def json_error(message: str, status_code: int = 400, **extra: Any) -> Response:
    """
    Return a standardized JSON error response.

    Shape:
        {
          "success": False,
          "error": "<message>",
          ...extra
        }
    """
    payload: dict[str, Any] = {"success": False, "error": message}
    if extra:
        payload.update(extra)
    response = jsonify(payload)
    response.status_code = status_code
    return response


def json_success(data: dict[str, Any] | None = None,
                 status_code: int = 200) -> Response:
    """
    Return a standardized JSON success response.

    Shape:
        {
          "success": True,
          ...data
        }
    """
    payload: dict[str, Any] = {"success": True}
    if data:
        payload.update(data)
    response = jsonify(payload)
    response.status_code = status_code
    return response


def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent XSS."""
    if not text:
        return ""
    return html.escape(str(text).strip())


def escape_like(value: str) -> str:
    """Escape SQL LIKE wildcard characters."""
    if not value:
        return ""
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
