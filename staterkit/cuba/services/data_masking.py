"""Data masking service — controls which fields are masked per role."""
import logging
from flask import current_app
from flask_login import current_user

logger = logging.getLogger(__name__)

DEFAULT_MASK = '********'


def get_masked_fields():
    """Get list of fields that should be masked for current user."""
    if not current_user.is_authenticated:
        return ['password']

    masking = current_app.config.get('DATA_MASKING', {})
    role = current_user.role if not current_user.is_admin_user else 'admin'
    return masking.get(role, ['password'])


def mask_value(field_name, value):
    """Mask a value if the field should be masked for current user."""
    if not value:
        return value

    masked_fields = get_masked_fields()
    if field_name in masked_fields:
        return DEFAULT_MASK

    return value


def should_mask(field_name):
    """Check if a field should be masked for current user."""
    return field_name in get_masked_fields()
