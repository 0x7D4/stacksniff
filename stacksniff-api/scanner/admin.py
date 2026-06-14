from django.contrib import admin

from scanner.models import ScanJob, ScanResult


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ("id", "url", "status", "created_at", "started_at", "completed_at")
    list_filter = ("status", "created_at")
    search_fields = ("url", "id", "celery_task_id")


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ("id", "job", "url", "scan_time", "openapi_spec_found", "rules_count")
    list_filter = ("openapi_spec_found", "scan_time")
    search_fields = ("url", "id", "job__id")
