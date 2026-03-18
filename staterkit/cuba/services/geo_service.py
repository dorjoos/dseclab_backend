"""IP geolocation service using free ip-api.com."""
import logging
import requests

logger = logging.getLogger(__name__)

GEO_API = "http://ip-api.com/json/"


def get_location(ip_address):
    """Get location info for an IP address. Returns dict or None."""
    if not ip_address or ip_address in ('127.0.0.1', '::1', 'localhost'):
        return {'country': 'Local', 'city': 'localhost', 'lat': 0, 'lon': 0}

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
