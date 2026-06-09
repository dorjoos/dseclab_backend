from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_assets import Environment
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix
import os

from dotenv import load_dotenv
load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
cache = Cache()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
socketio = SocketIO()


def create_app(config_name=None):
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'development')
    from config import config as config_dict
    app.config.from_object(config_dict[config_name])

    if config_name == 'production' and not app.config.get('SECRET_KEY'):
        raise RuntimeError('SECRET_KEY must be set in production')

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    cache.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    socketio.init_app(app, cors_allowed_origins=[])
    Environment(app)

    # Init Elasticsearch service
    from .services.breached_creds_service import breached_creds_service as es_service
    es_service.init_app(app)

    # Swagger API docs - only in non-production environments
    if config_name != 'production':
        from flasgger import Swagger
        swagger_config = {
            "headers": [],
            "specs": [{
                "endpoint": "apispec",
                "route": "/apispec.json",
            }],
            "static_url_path": "/flasgger_static",
            "swagger_ui": True,
            "specs_route": "/api/docs/",
            "title": "D-SECLAB API",
            "description": "Threat Intelligence Platform API",
            "version": "1.0.0",
        }
        swagger_template = {
            "info": {
                "title": "D-SECLAB API",
                "description": "API endpoints for the D-SECLAB Threat Intelligence Platform",
                "version": "1.0.0",
            },
            "securityDefinitions": {
                "Bearer": {
                    "type": "apiKey",
                    "name": "Authorization",
                    "in": "header",
                    "description": "JWT token: Bearer <token>"
                }
            },
            "security": [{"Bearer": []}],
        }
        Swagger(app, config=swagger_config, template=swagger_template)

        csrf.exempt(app.view_functions.get('flasgger.apispec', lambda: None))

    @app.context_processor
    def inject_csrf_token():
        from flask_wtf.csrf import generate_csrf
        return dict(csrf_token=generate_csrf)

    @app.context_processor
    def inject_default_breadcrumb():
        return dict(breadcrumb=None)

    @app.template_filter('format_number')
    def format_number_filter(value):
        try:
            return f"{int(value):,}"
        except (ValueError, TypeError):
            return value

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "script-src-elem 'self' 'unsafe-inline'; "
            # Google Fonts stylesheet host (style-src-elem covers <link>).
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            # Inter font files load from fonts.gstatic.com per googleapis.com CSS.
            "font-src 'self' data: https://fonts.gstatic.com; "
            "connect-src 'self';",
        )
        return response

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return db.session.get(User, user_id)

    from .routes import main as main_bp
    app.register_blueprint(main_bp)
    from .auth import auth as auth_bp
    app.register_blueprint(auth_bp)
    from .threat_intel import threat_intel as threat_intel_bp
    app.register_blueprint(threat_intel_bp)
    from .vulnerabilities import vulnerabilities as vulnerabilities_bp
    app.register_blueprint(vulnerabilities_bp)
    from .admin_routes import admin_bp
    app.register_blueprint(admin_bp)
    from .search_routes import search_bp
    app.register_blueprint(search_bp)
    from .notification_routes import notification_bp
    app.register_blueprint(notification_bp)

    # Register WebSocket events
    from . import ws_events  # noqa: F401

    @app.errorhandler(403)
    def forbidden_error(error):
        from flask import render_template
        return render_template('pages/error-pages/error-403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        from flask import render_template
        return render_template('pages/error-pages/error-404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        from flask import render_template
        db.session.rollback()
        return render_template('pages/error-pages/error-500.html'), 500

    return app
