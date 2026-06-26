import os
import sys

# Apply gevent monkey-patching as early as possible for Celery worker processes
if any("celery" in arg for arg in sys.argv):
    try:
        from gevent import monkey
        monkey.patch_all()
    except ImportError:
        pass

from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

app = Celery("stacksniff_api")

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Default settings for concurrent worker pool execution
app.conf.update(
    worker_pool=os.environ.get("CELERY_POOL", "gevent"),
    worker_concurrency=int(os.environ.get("CELERY_CONCURRENCY", 10)),
    task_soft_time_limit=300,
    task_time_limit=360,
)

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()
