"""Scanner API views.

Concurrency model
-----------------
- ``ScanJobViewSet``    — **sync** (DRF ModelViewSet internals are sync; uvicorn
                          runs it via asgiref's SyncToAsync threadpool so it is
                          fully concurrent without any code changes).
- ``ShortcutScanView``  — **async** via ``adrf.views.AsyncAPIView``, which
                          provides an async-aware ``dispatch()`` that properly
                          awaits coroutine handlers.  Uses Django async ORM
                          via ``async_create_scan_job``.
- ``HealthCheckView``   — **async** ``AsyncAPIView``; probes DB and Celery with
                          an ``asyncio.wait_for`` hard timeout on the broker call.

Rate limiting
-------------
- 10 POSTs per IP per minute on all scan-creation endpoints.
- Sync ``ScanJobViewSet.create``: call ``is_ratelimited()`` directly — no wrapper,
  sync context.
- Async ``ShortcutScanView.post``: call via ``sync_to_async(is_ratelimited, ...)``
  — wrapper is required because ``is_ratelimited`` is sync and we are in an
  async context.  Do NOT add this wrapper in the sync ViewSet.
"""

import asyncio
import logging
from typing import Any

from adrf.views import APIView as AsyncAPIView
from asgiref.sync import sync_to_async
from django_ratelimit.core import is_ratelimited
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

# Shared rate: 10 scan-creation POSTs per IP per minute.
_RATE = "10/m"

# ---------------------------------------------------------------------------
# Job-creation helpers
# ---------------------------------------------------------------------------


def create_scan_job(validated_data):
    """Synchronous job creator — used by the sync ``ScanJobViewSet``."""
    url = validated_data["url"]
    browser = validated_data.get("browser", True)
    timeout = validated_data.get("timeout", 30.0)
    force_rescan = validated_data.get("force_rescan", False)
    scan_technologies = validated_data.get("scan_technologies", True)
    scan_subdomains = validated_data.get("scan_subdomains", True)
    scan_endpoints = validated_data.get("scan_endpoints", True)
    scan_dependencies = validated_data.get("scan_dependencies", True)

    # Create the ScanJob model entry
    job = ScanJob.objects.create(
        url=url,
        status="pending",
        options={
            "browser": browser,
            "timeout": timeout,
            "scan_technologies": scan_technologies,
            "scan_subdomains": scan_subdomains,
            "scan_endpoints": scan_endpoints,
            "scan_dependencies": scan_dependencies,
        },
    )

    # Trigger the asynchronous Celery task
    from scanner.tasks import run_scan

    task_res = run_scan.delay(str(job.id), force_rescan=force_rescan)

    # Save the Celery task ID for potential cancellation
    job.celery_task_id = task_res.id
    job.save(update_fields=["celery_task_id"])
    return job


async def async_create_scan_job(validated_data):
    """Async job creator — used by ``ShortcutScanView`` (async context).

    Uses Django's async ORM (``acreate``, ``asave``) so the event loop is
    never blocked by DB I/O.  Celery's ``.delay()`` is sync-only, so it
    runs via ``sync_to_async`` in a thread.
    """
    url = validated_data["url"]
    browser = validated_data.get("browser", True)
    timeout = validated_data.get("timeout", 30.0)
    force_rescan = validated_data.get("force_rescan", False)
    scan_technologies = validated_data.get("scan_technologies", True)
    scan_subdomains = validated_data.get("scan_subdomains", True)
    scan_endpoints = validated_data.get("scan_endpoints", True)
    scan_dependencies = validated_data.get("scan_dependencies", True)

    job = await ScanJob.objects.acreate(
        url=url,
        status="pending",
        options={
            "browser": browser,
            "timeout": timeout,
            "scan_technologies": scan_technologies,
            "scan_subdomains": scan_subdomains,
            "scan_endpoints": scan_endpoints,
            "scan_dependencies": scan_dependencies,
        },
    )

    from scanner.tasks import run_scan

    # Celery .delay() is sync — run it in a thread (thread_sensitive=False:
    # it doesn't need the same thread as the event loop).
    task_res = await sync_to_async(run_scan.delay, thread_sensitive=False)(
        str(job.id), force_rescan=force_rescan
    )

    job.celery_task_id = task_res.id
    await job.asave(update_fields=["celery_task_id"])
    return job


# ---------------------------------------------------------------------------
# ViewSet (sync — concurrent via uvicorn's SyncToAsync threadpool)
# ---------------------------------------------------------------------------


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
        # Rate limit: sync context — call is_ratelimited() directly, no wrapper.
        if is_ratelimited(
            request, fn=self.create, key="ip", rate=_RATE, method="POST", increment=True
        ):
            return Response(
                {"error": "Rate limit exceeded. You may submit 10 scans per minute."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": "60"},
            )

        # Merge query params into body data so scan-type flags can be toggled
        # as checkable URL params in Postman. Body values take precedence when
        # the same key appears in both places.
        _FLAG_PARAMS = {"scan_technologies", "scan_subdomains", "scan_endpoints", "scan_dependencies"}
        _ALL_BOOL_PARAMS = _FLAG_PARAMS | {"browser", "force_rescan"}
        data = dict(request.data)

        # Check if caller is using query parameters to control scan flags
        using_query_flags = any(k in request.query_params for k in _ALL_BOOL_PARAMS)

        for key in _ALL_BOOL_PARAMS:
            if key in data:
                # Body value explicitly provided
                continue
            if key in request.query_params:
                raw = request.query_params[key].lower()
                data[key] = raw not in {"false", "0", "no"}
            elif using_query_flags and key in _FLAG_PARAMS:
                # Key was omitted from query params (e.g. unchecked box in Postman)
                data[key] = False

        # If scan_dependencies is explicitly enabled, make sure browser, technologies, subdomains, and endpoints are on
        if data.get("scan_dependencies"):
            data["scan_technologies"] = True
            data["scan_subdomains"] = True
            data["scan_endpoints"] = True
            data["browser"] = True

        serializer = ScanJobCreateSerializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        job = create_scan_job(serializer.validated_data)
        job.refresh_from_db()

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
        """Return scan result, optionally filtered to specific fields.

        Query parameter
        ---------------
        ``fields`` — comma-separated list of result sections to include.
        When omitted the full result is returned (backward-compatible).

        Recognised aliases
        ------------------
        technologies  → technologies
        endpoints     → api_endpoints
        dependencies  → runtime_dependencies
        subdomains    → discovered_subdomains
        evidence      → raw_evidence

        Metadata fields (id, url, scan_time, duration_seconds,
        openapi_spec_found, phases_completed, rules_count,
        fingerprints_version) are always included.

        Example
        -------
        GET /api/scans/{id}/result/?fields=technologies,dependencies
        """
        # Map user-facing alias → serializer field name
        _FIELD_ALIASES: dict[str, str] = {
            "technologies": "technologies",
            "endpoints": "api_endpoints",
            "dependencies": "runtime_dependencies",
            "subdomains": "discovered_subdomains",
            "evidence": "raw_evidence",
        }
        # These are always present regardless of ?fields=
        _ALWAYS_INCLUDED: set[str] = {
            "id", "url", "scan_time", "duration_seconds",
            "openapi_spec_found", "phases_completed",
            "rules_count", "fingerprints_version",
        }

        job = self.get_object()
        try:
            result = job.result
        except ScanResult.DoesNotExist:
            return Response(
                {"error": f"Scan result is not available. Scan status: {job.status}"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = ScanResultSerializer(result)
        data = serializer.data

        # Apply field filtering when ?fields= is provided, or default to active job options
        raw_fields = request.query_params.get("fields", "").strip()
        if not raw_fields:
            opts = job.options or {}
            resolved = set()
            if opts.get("scan_technologies", True):
                resolved.add("technologies")
            if opts.get("scan_subdomains", True):
                resolved.add("discovered_subdomains")
            if opts.get("scan_endpoints", True):
                resolved.add("api_endpoints")
            if opts.get("scan_dependencies", True):
                resolved.add("runtime_dependencies")

            filtered = {
                key: value
                for key, value in data.items()
                if key in _ALWAYS_INCLUDED or key in resolved
            }
            return Response(filtered)

        requested_aliases = {f.strip().lower() for f in raw_fields.split(",") if f.strip()}
        unknown = requested_aliases - set(_FIELD_ALIASES.keys())
        if unknown:
            return Response(
                {
                    "error": f"Unknown field(s): {', '.join(sorted(unknown))}. "
                             f"Valid options: {', '.join(sorted(_FIELD_ALIASES.keys()))}"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Build the filtered response — metadata always included
        resolved = {_FIELD_ALIASES[alias] for alias in requested_aliases}
        filtered = {
            key: value
            for key, value in data.items()
            if key in _ALWAYS_INCLUDED or key in resolved
        }
        return Response(filtered)

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

    @action(detail=True, methods=["get"], url_path="evidence")
    def get_evidence(self, request, pk=None):
        """Return raw_evidence for client-side matching."""
        job = self.get_object()
        try:
            return Response({"raw_evidence": job.result.raw_evidence})
        except ScanResult.DoesNotExist:
            return Response(
                {"error": f"Scan result is not available. Scan status: {job.status}"},
                status=status.HTTP_404_NOT_FOUND,
            )


# ---------------------------------------------------------------------------
# Shortcut views (async — adrf.AsyncAPIView dispatch properly awaits handlers)
# ---------------------------------------------------------------------------


class ShortcutScanView(AsyncAPIView):
    """Base class for one-shot scan-preset endpoints.

    Inherits from ``adrf.views.AsyncAPIView`` which provides an async-aware
    ``dispatch()`` that properly awaits coroutine handler methods.

    Rate limiting uses ``sync_to_async(is_ratelimited, ...)`` here because
    ``is_ratelimited`` is sync and we are in an async context.  The sync
    ``ScanJobViewSet`` calls ``is_ratelimited()`` directly — no wrapper there.
    """

    PRESET: dict[str, Any] = {}

    async def post(self, request, *args, **kwargs):
        # Rate limit: async context — sync_to_async wrapper required.
        if await sync_to_async(is_ratelimited, thread_sensitive=True)(
            request, fn=self.post, key="ip", rate=_RATE, method="POST", increment=True
        ):
            return Response(
                {"error": "Rate limit exceeded. You may submit 10 scans per minute."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": "60"},
            )

        data = {**self.PRESET}
        if "url" in request.data:
            data["url"] = request.data["url"]
        if "timeout" in request.data:
            data["timeout"] = request.data["timeout"]
        if "force_rescan" in request.data:
            data["force_rescan"] = request.data["force_rescan"]

        serializer = ScanJobCreateSerializer(data=data)
        # ScanJobCreateSerializer has no DB validators — safe to call sync here.
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        job = await async_create_scan_job(serializer.validated_data)
        await job.arefresh_from_db()

        # Serialize in a thread: ScanJobSerializer accesses job.result (lazy
        # OneToOneField reverse relation), which triggers a sync DB lookup.
        # Running it via sync_to_async keeps the event loop unblocked.
        job_data = await sync_to_async(
            lambda: ScanJobSerializer(job).data, thread_sensitive=True
        )()
        return Response(job_data, status=status.HTTP_201_CREATED)


class ShortcutTechView(ShortcutScanView):
    PRESET = {
        "scan_technologies": True,
        "scan_subdomains": False,
        "scan_endpoints": False,
        "browser": True,
    }


class ShortcutFullView(ShortcutScanView):
    PRESET = {
        "scan_technologies": True,
        "scan_subdomains": True,
        "scan_endpoints": True,
        "browser": True,
    }


class ShortcutEndpointsView(ShortcutScanView):
    PRESET = {
        "scan_technologies": False,
        "scan_subdomains": False,
        "scan_endpoints": True,
        "browser": True,
    }


class ShortcutSubdomainsView(ShortcutScanView):
    PRESET = {
        "scan_technologies": False,
        "scan_subdomains": True,
        "scan_endpoints": False,
        "browser": False,
    }


class ShortcutDependenciesView(ShortcutScanView):
    """Run the browser collector + DomainMapper to harvest runtime external dependencies.

    scan_technologies and subdomains are both enabled so that:
    - browser=True + scan_technologies=True  → need_js=True → browser launches
    - subdomains=True                        → DomainMapper runs → runtime_dependencies populated

    Endpoint probing is skipped to keep the scan fast (~25s).
    """

    PRESET = {
        "scan_technologies": True,
        "scan_subdomains": True,
        "scan_endpoints": True,
        "browser": True,
    }


# ---------------------------------------------------------------------------
# Health check (async — concurrent DB + Celery probes)
# ---------------------------------------------------------------------------


class HealthCheckView(AsyncAPIView):
    """Lightweight health probe for load balancers and monitoring systems.

    ``GET /api/health/`` — no authentication required.

    Returns ``200`` when all checks pass, ``503`` when any check is degraded.
    The Celery probe is wrapped in ``asyncio.wait_for`` with a hard 3-second
    outer timeout so a slow or restarting Redis/worker never hangs this
    endpoint (the inspector's own ``timeout=2`` is a soft hint to the broker).
    """

    permission_classes = []
    authentication_classes = []

    async def get(self, request):
        checks: dict[str, str] = {}

        # --- DB check ---
        try:
            await ScanJob.objects.acount()
            checks["database"] = "ok"
        except Exception as e:  # noqa: BLE001
            logger.error("Health check DB probe failed: %s", e)
            checks["database"] = f"error: {e}"

        # --- Celery / Redis check ---
        # Hard outer timeout (asyncio.wait_for) guards against broker hangs.
        # The inspector's timeout=2 is a soft Celery-level hint.
        try:
            from config.celery import app as celery_app

            inspector = celery_app.control.inspect(timeout=2)
            workers = await asyncio.wait_for(
                sync_to_async(inspector.active, thread_sensitive=False)(),
                timeout=3.0,
            )
            checks["celery"] = "ok" if workers else "no workers"
        except TimeoutError:
            logger.warning("Health check Celery probe timed out")
            checks["celery"] = "error: timeout"
        except Exception as e:  # noqa: BLE001
            logger.error("Health check Celery probe failed: %s", e)
            checks["celery"] = f"error: {e}"

        all_ok = all(v == "ok" for v in checks.values())
        return Response(
            {"status": "ok" if all_ok else "degraded", "checks": checks},
            status=200 if all_ok else 503,
        )
