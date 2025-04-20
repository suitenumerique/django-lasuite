"""Django settings for test project."""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-test-key-for-development-only"  # noqa: S105

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["*"]

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "test_project.user",
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

ROOT_URLCONF = "test_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
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

WSGI_APPLICATION = "test_project.wsgi.application"

# Database
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Storage
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.InMemoryStorage",
    }
}

# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = "/static/"

# Default primary key field type
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Logging Configuration
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


# Test variables
AUTH_USER_MODEL = "user.User"

AUTHENTICATION_BACKENDS = [
    "lasuite.oidc_login.backends.OIDCAuthenticationBackend",
]

#  - OIDC module
OIDC_AUTHENTICATE_CLASS = "lasuite.oidc_login.views.OIDCAuthenticationRequestView"
OIDC_CALLBACK_CLASS = "lasuite.oidc_login.views.OIDCAuthenticationCallbackView"

OIDC_OP_TOKEN_ENDPOINT = None
OIDC_OP_USER_ENDPOINT = None
OIDC_OP_LOGOUT_ENDPOINT = None
OIDC_OP_AUTHORIZATION_ENDPOINT = None
OIDC_RP_CLIENT_ID = "lasuite"
OIDC_RP_CLIENT_SECRET = "lasuite"
OIDC_USERINFO_FULLNAME_FIELDS = ["first_name", "last_name"]
OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = True

#  - OIDC resource server module
OIDC_RS_AUDIENCE_CLAIM = "client_id"
OIDC_RS_BACKEND_CLASS = "lasuite.oidc_resource_server.backend.ResourceServerBackend"
OIDC_RS_ENCRYPTION_ENCODING = "A256GCM"
OIDC_RS_ENCRYPTION_ALGO = "RSA-OAEP"
OIDC_RS_SIGNING_ALGO = "ES256"
OIDC_RS_SCOPES = ["groups"]
