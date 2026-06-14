from rest_framework import serializers

from scanner.models import ScanJob, ScanResult


class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = [
            "id",
            "url",
            "scan_time",
            "duration_seconds",
            "technologies",
            "api_endpoints",
            "runtime_dependencies",
            "discovered_subdomains",
            "openapi_spec_found",
            "phases_completed",
            "rules_count",
        ]


class ScanJobSerializer(serializers.ModelSerializer):
    result = ScanResultSerializer(read_only=True)

    class Meta:
        model = ScanJob
        fields = [
            "id",
            "url",
            "status",
            "created_at",
            "started_at",
            "completed_at",
            "celery_task_id",
            "error_message",
            "options",
            "result",
        ]


class ScanJobCreateSerializer(serializers.Serializer):
    url = serializers.URLField(required=True)
    browser = serializers.BooleanField(default=True)
    timeout = serializers.FloatField(default=30.0, min_value=1.0)
    force_rescan = serializers.BooleanField(default=False)
