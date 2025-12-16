from flask import Flask, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
# Admin panel removed - Flask-Admin imports commented out
# from flask_admin import Admin, AdminIndexView
# from flask_admin.contrib.sqla import ModelView
from flask_assets import Environment
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
import os

app = Flask(__name__)


assets = Environment(app)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'e5b446169dd49e3b7f1bb841-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cuba.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Performance: Disable modification tracking
app.config['SQLALCHEMY_ECHO'] = False  # Performance: Disable SQL query logging in production
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Performance: Caching configuration
app.config['CACHE_TYPE'] = 'simple'  # Use 'redis' or 'memcached' in production
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 5 minutes

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Make CSRF token available in all templates
@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)

# Provide default breadcrumb if not set
@app.context_processor
def inject_default_breadcrumb():
    return dict(breadcrumb=None)

# Custom Jinja2 filter for number formatting
@app.template_filter('format_number')
def format_number_filter(value):
    """Format number with commas"""
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value


db = SQLAlchemy(app)

# Initialize caching for performance
cache = Cache(app)

# Optional: SassMiddleware for on-the-fly SCSS compilation
# Note: CSS files are already compiled and available in static/assets/css
# Uncomment the following lines if you need live SCSS compilation:
# try:
#     from sassutils.wsgi import SassMiddleware
#     app.wsgi_app = SassMiddleware(app.wsgi_app, {
#         'cuba': ('static/assets/scss', 'static/assets/css', '/static/assets/css')
#     })
# except ImportError:
#     # SassMiddleware not available, using pre-compiled CSS files
#     pass


# Admin panel removed
# class UserModelView(ModelView):
#     def is_accessible(self):
#         isAdmin = False
#         if current_user.is_authenticated:
#             isAdmin = current_user.isAdmin
#         return isAdmin
#     
#     def inaccessible_callback(self, name, **kwargs):
#         from flask import url_for
#         return redirect(url_for('auth.login'))
#
# class cubaAdminIndexView(AdminIndexView):
#     def is_accessible(self):
#         isAdmin = True
#         if current_user.is_authenticated:
#             isAdmin = current_user.isAdmin
#         return isAdmin
#     
#     def inaccessible_callback(self, name, **kwargs):
#         from flask import url_for
#         return redirect(url_for('auth.login'))
#
# admin = Admin(app,index_view=cubaAdminIndexView())


login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = "warning"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from .routes import main as main_blueprint
app.register_blueprint(main_blueprint)

from .auth import auth as auth_blueprint
app.register_blueprint(auth_blueprint)

from .threat_intel import threat_intel as threat_intel_blueprint
app.register_blueprint(threat_intel_blueprint)

from .admin_routes import admin_bp as admin_blueprint
app.register_blueprint(admin_blueprint)

from .search_routes import search_bp as search_blueprint
app.register_blueprint(search_blueprint)

from .notification_routes import notification_bp as notification_blueprint
app.register_blueprint(notification_blueprint)

from .models import User, Todo, BreachedCredential, Company, Notification
# admin.add_view(ModelView(Todo,db.session))
# admin.add_view(ModelView(User,db.session))

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))