from config.settings.base import *

DEBUG = True

ALLOWED_HOSTS = ["*"]

# Allow all CORS origins for easier initial frontend development
CORS_ALLOW_ALL_ORIGINS = True

REST_FRAMEWORK = {
    **REST_FRAMEWORK,
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",
    ],
}
