"""ASGI entry-point for uvicorn / Gunicorn+UvicornWorker.

Dev:
    uv run uvicorn config.asgi:application --host 127.0.0.1 --port 8000 --reload

Production (Gunicorn supervisor command):
    gunicorn config.asgi:application \\
        --worker-class uvicorn.workers.UvicornWorker \\
        --workers 4 --bind 127.0.0.1:8000 \\
        --timeout 120 --graceful-timeout 30
"""
import os
from pathlib import Path

import django
import environ
from django.core.asgi import get_asgi_application

BASE_DIR = Path(__file__).resolve().parent.parent
environ.Env.read_env(os.path.join(BASE_DIR, ".env"))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

# Explicit setup ensures Django apps are fully initialised before any
# app-level code that uvicorn may import during ASGI lifespan startup.
django.setup()

application = get_asgi_application()
