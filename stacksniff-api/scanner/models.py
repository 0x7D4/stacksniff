import uuid

from django.db import models


class ScanJob(models.Model):
    """Represents a scheduled, active, or finished scan request."""

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url = models.URLField(max_length=2048)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=255, null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)
    options = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"ScanJob({self.id}) - {self.url} [{self.status}]"


class ScanResult(models.Model):
    """Contains the final analysis data parsed and loaded from the scan."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.OneToOneField(ScanJob, on_delete=models.CASCADE, related_name="result")
    url = models.URLField(max_length=2048)
    scan_time = models.DateTimeField()
    duration_seconds = models.FloatField()
    technologies = models.JSONField(default=list)
    api_endpoints = models.JSONField(default=list)
    runtime_dependencies = models.JSONField(default=list)
    discovered_subdomains = models.JSONField(default=list)
    openapi_spec_found = models.BooleanField(default=False)
    phases_completed = models.JSONField(default=list)
    rules_count = models.IntegerField(default=0)

    def __str__(self) -> str:
        return f"ScanResult({self.id}) - {self.url}"
