"""IP geolocation service using free ip-api.com."""
import ipaddress
import logging
import requests

logger = logging.getLogger(__name__)

GEO_API = "http://ip-api.com/json/"


def is_safe_ip(ip):
    """Validate that an IP address is a public/global address (not private/internal)."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def get_location(ip_address):
    """Get location info for an IP address. Returns dict or None."""
    if not ip_address or ip_address in ('127.0.0.1', '::1', 'localhost'):
        return {'country': 'Local', 'city': 'localhost', 'lat': 0, 'lon': 0}

    if not is_safe_ip(ip_address):
        logger.warning("Blocked geo lookup for non-global IP: %s", ip_address)
        return None

    try:
        resp = requests.get(
            GEO_API + ip_address,
            params={'fields': 'status,country,city,lat,lon,isp'},
            timeout=3
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'isp': data.get('isp', ''),
                }
        return None
    except Exception as e:
        logger.error("Geo lookup failed for %s: %s", ip_address, e)
        return None


def format_location(geo_data):
    """Format geo data into a readable string."""
    if not geo_data:
        return 'Unknown'
    city = geo_data.get('city', '')
    country = geo_data.get('country', '')
    if city and country:
        return f"{city}, {country}"
    return country or city or 'Unknown'
