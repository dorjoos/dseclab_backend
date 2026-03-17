from typing import Any, Dict

from flask import jsonify


def json_error(message: str, status_code: int = 400, **extra: Any):
    """
    Return a standardized JSON error response.

    Shape:
        {
          "success": False,
          "error": "<message>",
          ...extra
        }
    """
    payload: Dict[str, Any] = {"success": False, "error": message}
    if extra:
        payload.update(extra)
    response = jsonify(payload)
    response.status_code = status_code
    return response


def json_success(data: Dict[str, Any] | None = None, status_code: int = 200):
    """
    Return a standardized JSON success response.

    Shape:
        {
          "success": True,
          ...data
        }
    """
    payload: Dict[str, Any] = {"success": True}
    if data:
        payload.update(data)
    response = jsonify(payload)
    response.status_code = status_code
    return response


import html


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
