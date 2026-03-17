"""WebSocket events for real-time breach notifications."""
from flask_socketio import emit
from flask_login import current_user
from . import socketio


@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False  # Reject unauthenticated connections
    emit('connected', {'status': 'ok', 'user': current_user.username})


@socketio.on('disconnect')
def handle_disconnect():
    pass


def broadcast_new_breach(breach_data):
    """Broadcast a new breach event to all connected clients."""
    socketio.emit('new_breach', breach_data, namespace='/')


def broadcast_stats_update(stats):
    """Broadcast updated stats to all connected clients."""
    socketio.emit('stats_update', stats, namespace='/')
