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


