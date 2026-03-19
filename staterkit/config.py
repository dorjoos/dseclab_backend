import os
from datetime import timedelta


class BaseConfig:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    CACHE_DEFAULT_TIMEOUT = 300

    # Elasticsearch
    ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL', 'https://localhost:9200')
    ELASTICSEARCH_USER = os.environ.get('ELASTICSEARCH_USER', 'elastic')
    ELASTICSEARCH_PASSWORD = os.environ.get('ELASTICSEARCH_PASSWORD', '')
    ELASTICSEARCH_INDEX = os.environ.get('ELASTICSEARCH_INDEX', 'main')
    ELASTICSEARCH_VERIFY_CERTS = os.environ.get('ELASTICSEARCH_VERIFY_CERTS', 'false').lower() == 'true'

    # Email (SMTP)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@dseclab.com')

    # Data masking rules per role
    DATA_MASKING = {
        'member': ['password'],  # Members see masked passwords
        'analyst': [],           # Analysts see everything
        'admin': [],             # Admins see everything
    }

    # Feature flags
    ALLOW_SELF_REGISTRATION = os.environ.get('ALLOW_SELF_REGISTRATION', 'false').lower() == 'true'


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'cuba.db')
    )
    SESSION_COOKIE_SECURE = False
    CACHE_TYPE = 'simple'
    ALLOW_SELF_REGISTRATION = True


class ProductionConfig(BaseConfig):
    SECRET_KEY = os.environ.get('SECRET_KEY', '')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', os.environ.get('SECRET_KEY', ''))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', '')
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
    CACHE_REDIS_URL = os.environ.get('CACHE_REDIS_URL')
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
