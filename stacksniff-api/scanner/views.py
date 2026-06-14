import logging

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from scanner.models import ScanJob, ScanResult
from scanner.serializers import (
    ScanJobCreateSerializer,
    ScanJobSerializer,
    ScanResultSerializer,
)

logger = logging.getLogger(__name__)


class ScanJobViewSet(viewsets.ModelViewSet):
    """API endpoint that allows scan jobs to be created, listed, and viewed."""

    queryset = ScanJob.objects.all()

    def get_serializer_class(self):
        if self.action == "create":
            return ScanJobCreateSerializer
        return ScanJobSerializer

    def get_queryset(self):
        queryset = ScanJob.objects.all()
        url = self.request.query_params.get("url")
        status_param = self.request.query_params.get("status")
        created_after = self.request.query_params.get("created_after")
        created_before = self.request.query_params.get("created_before")

        if url:
            queryset = queryset.filter(url__icontains=url)
        if status_param:
            queryset = queryset.filter(status=status_param)
        if created_after:
            queryset = queryset.filter(created_at__gte=created_after)
        if created_before:
            queryset = queryset.filter(created_at__lte=created_before)

        return queryset

    def create(self, request, *args, **kwargs):
        serializer = ScanJobCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data
        url = validated_data["url"]
        browser = validated_data.get("browser", True)
        timeout = validated_data.get("timeout", 30.0)
        force_rescan = validated_data.get("force_rescan", False)

        # Create the ScanJob model entry
        job = ScanJob.objects.create(
            url=url,
            status="pending",
            options={
                "browser": browser,
                "timeout": timeout,
            },
        )

        # Trigger the asynchronous Celery task
        from scanner.tasks import run_scan

        task_res = run_scan.delay(str(job.id), force_rescan=force_rescan)

        # Save the Celery task ID for potential cancellation
        job.celery_task_id = task_res.id
        job.save()

        # Serialize and return the created job
        job_serializer = ScanJobSerializer(job)
        return Response(job_serializer.data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        job = self.get_object()
        # Revoke the Celery task if present and active
        if job.celery_task_id:
            try:
                from celery.result import AsyncResult  # noqa: F401

                from config.celery import app as celery_app

                celery_app.control.revoke(job.celery_task_id, terminate=True)
                logger.info("Revoked Celery task %s for job %s", job.celery_task_id, job.id)
            except Exception as e:
                logger.error("Failed to revoke Celery task %s: %s", job.celery_task_id, e)

        # Delete from database
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["get"], url_path="result")
    def get_result(self, request, pk=None):
        """Return the full scan result if available."""
        job = self.get_object()
        try:
            result = job.result
            serializer = ScanResultSerializer(result)
            return Response(serializer.data)
        except ScanResult.DoesNotExist:
            return Response(
                {"error": f"Scan result is not available. Scan status: {job.status}"},
                status=status.HTTP_404_NOT_FOUND,
            )

    @action(detail=True, methods=["get"], url_path="technologies")
    def get_technologies(self, request, pk=None):
        """Return the list of matched technologies."""
        job = self.get_object()
        try:
            return Response(job.result.technologies)
        except ScanResult.DoesNotExist:
            return Response(
                {"error": f"Scan result is not available. Scan status: {job.status}"},
                status=status.HTTP_404_NOT_FOUND,
            )

    @action(detail=True, methods=["get"], url_path="endpoints")
    def get_endpoints(self, request, pk=None):
        """Return the list of detected API endpoints."""
        job = self.get_object()
        try:
            return Response(job.result.api_endpoints)
        except ScanResult.DoesNotExist:
            return Response(
                {"error": f"Scan result is not available. Scan status: {job.status}"},
                status=status.HTTP_404_NOT_FOUND,
            )

    @action(detail=True, methods=["get"], url_path="subdomains")
    def get_subdomains(self, request, pk=None):
        """Return the list of discovered subdomains."""
        job = self.get_object()
        try:
            return Response(job.result.discovered_subdomains)
        except ScanResult.DoesNotExist:
            return Response(
                {"error": f"Scan result is not available. Scan status: {job.status}"},
                status=status.HTTP_404_NOT_FOUND,
            )

    @action(detail=True, methods=["get"], url_path="dependencies")
    def get_dependencies(self, request, pk=None):
        """Return the list of runtime external dependencies."""
        job = self.get_object()
        try:
            return Response(job.result.runtime_dependencies)
        except ScanResult.DoesNotExist:
            return Response(
                {"error": f"Scan result is not available. Scan status: {job.status}"},
                status=status.HTTP_404_NOT_FOUND,
            )
