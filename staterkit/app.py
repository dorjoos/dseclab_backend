from cuba import create_app, socketio

app = create_app()

if __name__ == '__main__':
    # allow_unsafe_werkzeug: this is the local dev entry point (production uses
    # wsgi.py); newer Flask-SocketIO refuses the Werkzeug dev server without it.
    socketio.run(app, debug=True, port=8003, allow_unsafe_werkzeug=True)
