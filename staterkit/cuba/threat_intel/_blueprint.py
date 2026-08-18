"""The one blueprint every threat-intelligence module registers onto.

Kept in its own module so the submodules can import it without importing
each other, and so splitting the package never renames an endpoint —
templates reference url_for('threat_intel.*') throughout.
"""
from flask import Blueprint

threat_intel = Blueprint('threat_intel', __name__)
