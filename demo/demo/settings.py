"""Django settings for the demo project."""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/stable/howto/deployment/checklist/

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "django-insecure-demo-key-change-me")

DEBUG = os.environ.get("DJANGO_DEBUG", "true").lower() == "true"

ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "user",
    "client",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "demo.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "demo.wsgi.application"


# Database
# https://docs.djangoproject.com/en/stable/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# Password validation
# https://docs.djangoproject.com/en/stable/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/stable/topics/i18n/

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/stable/howto/static-files/

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]

# Default primary key field type
# https://docs.djangoproject.com/en/stable/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Custom user model
AUTH_USER_MODEL = "user.User"

# Authentication backends
AUTHENTICATION_BACKENDS = [
    "lasuite.oidc_login.backends.OIDCAuthenticationBackend",
]

# OIDC Login settings
# All values are read from environment variables for easy configuration.
# See https://github.com/suitenumerique/django-lasuite for more details.

OIDC_AUTHENTICATE_CLASS = "lasuite.oidc_login.views.OIDCAuthenticationRequestView"
OIDC_CALLBACK_CLASS = "lasuite.oidc_login.views.OIDCAuthenticationCallbackView"

# Required OIDC provider endpoints
OIDC_OP_URL = os.environ.get("OIDC_OP_URL")
OIDC_OP_AUTHORIZATION_ENDPOINT = os.environ.get("OIDC_OP_AUTHORIZATION_ENDPOINT")
OIDC_OP_TOKEN_ENDPOINT = os.environ.get("OIDC_OP_TOKEN_ENDPOINT")
OIDC_OP_USER_ENDPOINT = os.environ.get("OIDC_OP_USER_ENDPOINT")
OIDC_OP_LOGOUT_ENDPOINT = os.environ.get("OIDC_OP_LOGOUT_ENDPOINT")
OIDC_OP_JWKS_ENDPOINT = os.environ.get("OIDC_OP_JWKS_ENDPOINT")

# Client credentials
OIDC_RP_CLIENT_ID = os.environ.get("OIDC_RP_CLIENT_ID")
OIDC_RP_CLIENT_SECRET = os.environ.get("OIDC_RP_CLIENT_SECRET")
OIDC_RP_SIGN_ALGO = os.environ.get("OIDC_RP_SIGN_ALGO")
OIDC_RP_IDP_SIGN_KEY = os.environ.get("OIDC_RP_IDP_SIGN_KEY")

# Optional OIDC settings
OIDC_RP_SCOPES = os.environ.get("OIDC_RP_SCOPES", "openid email profile")
LOGIN_REDIRECT_URL = os.environ.get("LOGIN_REDIRECT_URL")
LOGIN_REDIRECT_URL_FAILURE = os.environ.get("LOGIN_REDIRECT_URL_FAILURE")
LOGOUT_REDIRECT_URL = os.environ.get("LOGOUT_REDIRECT_URL")
OIDC_VERIFY_SSL = os.environ.get("OIDC_VERIFY_SSL", "true").lower() == "true"
OIDC_TIMEOUT = int(os.environ.get("OIDC_TIMEOUT", "10"))
ALLOW_LOGOUT_GET_METHOD = True

# Token storage - required for the demo to call the resource server
OIDC_STORE_ACCESS_TOKEN = True
OIDC_STORE_ID_TOKEN = True
OIDC_STORE_REFRESH_TOKEN = True
OIDC_STORE_REFRESH_TOKEN_KEY = os.environ.get(
    "OIDC_STORE_REFRESH_TOKEN_KEY",
    "demo-refresh-token-key-must-be-32-bytes-long!!",
)

# User info mapping
OIDC_USERINFO_FULLNAME_FIELDS = ["first_name", "last_name"]
OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = True

# OIDC Resource Server settings (used when this app also acts as a resource server)
OIDC_RS_AUDIENCE_CLAIM = os.environ.get("OIDC_RS_AUDIENCE_CLAIM", "client_id")
OIDC_RS_BACKEND_CLASS = "lasuite.oidc_resource_server.backend.ResourceServerBackend"
OIDC_RS_CLIENT_ID = os.environ.get("OIDC_RS_CLIENT_ID", "")
OIDC_RS_CLIENT_SECRET = os.environ.get("OIDC_RS_CLIENT_SECRET", "")
OIDC_RS_ENCRYPTION_ENCODING = os.environ.get("OIDC_RS_ENCRYPTION_ENCODING", "A256GCM")
OIDC_RS_ENCRYPTION_ALGO = os.environ.get("OIDC_RS_ENCRYPTION_ALGO", "RSA-OAEP")
OIDC_RS_ENCRYPTION_KEY_TYPE = os.environ.get("OIDC_RS_ENCRYPTION_KEY_TYPE", "RSA")
OIDC_RS_SIGNING_ALGO = os.environ.get("OIDC_RS_SIGNING_ALGO", "ES256")
OIDC_RS_SCOPES = os.environ.get("OIDC_RS_SCOPES", "groups").split(",")

# Resource server client settings
# Base URL of the resource server to consume
RESOURCE_SERVER_BASE_URL = os.environ.get("RESOURCE_SERVER_BASE_URL", "")

# Logging
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}
