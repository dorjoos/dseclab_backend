"""WebSocket events for real-time breach notifications."""
from flask_login import current_user
from flask_socketio import emit

from . import socketio


@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False  # Reject unauthenticated connections
    emit('connected', {'status': 'ok', 'user': current_user.username})
    return True  # only False rejects; explicit accept beats falling off the end


@socketio.on('disconnect')
def handle_disconnect():
    pass


def broadcast_new_breach(breach_data):
    """Log new breach event. Broadcast disabled to prevent data leakage across companies."""
    import logging
    logging.getLogger(__name__).info("New breach event (broadcast disabled): %s", breach_data.get('es_id', ''))


def broadcast_stats_update(stats):
    """Log stats update. Broadcast disabled to prevent data leakage across companies."""
    import logging
    logging.getLogger(__name__).info("Stats update event (broadcast disabled)")
