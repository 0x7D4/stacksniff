from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from stacksniff.models import DetectedEndpoint, ScanMeta, TechMatch
from stacksniff.models import ScanResult as StacksniffScanResult

from scanner.models import ScanJob, ScanResult
from scanner.tasks import run_scan


class ScanJobAPITests(APITestCase):
    def setUp(self):
        # Create some initial jobs for list and detail tests
        self.job1 = ScanJob.objects.create(
            url="https://example.com",
            status="pending",
            options={"browser": True, "timeout": 30.0},
        )
        self.job2 = ScanJob.objects.create(
            url="https://test.org",
            status="completed",
            options={"browser": False, "timeout": 15.0},
        )
        # Ensure distinct created_at values for ordering test
        ScanJob.objects.filter(id=self.job1.id).update(
            created_at=timezone.now() - timezone.timedelta(seconds=10)
        )
        self.job1.refresh_from_db()

        self.result2 = ScanResult.objects.create(
            job=self.job2,
            url="https://test.org",
            scan_time=timezone.now(),
            duration_seconds=2.5,
            technologies=[{"name": "Nginx", "category": "web-servers", "version": "1.24.0"}],
            api_endpoints=[{"url": "https://test.org/api", "method": "GET", "confidence": 0.9}],
            runtime_dependencies=[],
            discovered_subdomains=[],
            openapi_spec_found=False,
            phases_completed=["http"],
            rules_count=50,
        )

    @patch("scanner.tasks.run_scan.delay")
    def test_create_scan_job_success(self, mock_run_scan_delay):
        # Mock Celery delay return value
        mock_task = MagicMock()
        mock_task.id = "mock-task-uuid-123"
        mock_run_scan_delay.return_value = mock_task

        url = reverse("scan-list")
        data = {
            "url": "https://newsite.com",
            "browser": True,
            "timeout": 20.0,
            "force_rescan": True,
        }
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["url"], "https://newsite.com")
        self.assertEqual(response.data["status"], "pending")
        self.assertEqual(response.data["celery_task_id"], "mock-task-uuid-123")

        # Verify DB entry
        job = ScanJob.objects.get(id=response.data["id"])
        self.assertEqual(job.url, "https://newsite.com")
        self.assertEqual(job.options["browser"], True)
        self.assertEqual(job.options["timeout"], 20.0)
        self.assertEqual(job.options["scan_technologies"], True)
        self.assertEqual(job.options["scan_subdomains"], True)
        self.assertEqual(job.options["scan_endpoints"], True)

        # Verify task was called with correct arguments
        mock_run_scan_delay.assert_called_once_with(str(job.id), force_rescan=True)

    @patch("scanner.tasks.run_scan.delay")
    def test_create_scan_job_with_custom_options(self, mock_run_scan_delay):
        mock_task = MagicMock()
        mock_task.id = "mock-task-uuid-456"
        mock_run_scan_delay.return_value = mock_task

        url = reverse("scan-list")
        data = {
            "url": "https://customoptions.com",
            "browser": False,
            "timeout": 15.0,
            "scan_technologies": False,
            "scan_subdomains": False,
            "scan_endpoints": False,
            "force_rescan": False,
        }
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        job = ScanJob.objects.get(id=response.data["id"])
        self.assertEqual(job.url, "https://customoptions.com")
        self.assertEqual(job.options["browser"], False)
        self.assertEqual(job.options["timeout"], 15.0)
        self.assertEqual(job.options["scan_technologies"], False)
        self.assertEqual(job.options["scan_subdomains"], False)
        self.assertEqual(job.options["scan_endpoints"], False)

    def test_create_scan_job_invalid_url(self):
        url = reverse("scan-list")
        data = {"url": "not-a-valid-url"}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("url", response.data)

    def test_list_scan_jobs(self):
        url = reverse("scan-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)
        # Verify ordering (newest first)
        self.assertEqual(response.data["results"][0]["url"], "https://test.org")
        self.assertEqual(response.data["results"][1]["url"], "https://example.com")

    def test_list_scan_jobs_filtering(self):
        url = reverse("scan-list")

        # Filter by URL
        response = self.client.get(url, {"url": "test"})
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["url"], "https://test.org")

        # Filter by status
        response = self.client.get(url, {"status": "pending"})
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["url"], "https://example.com")

    def test_retrieve_scan_job_pending(self):
        url = reverse("scan-detail", kwargs={"pk": self.job1.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "pending")
        self.assertIsNone(response.data["result"])

    def test_retrieve_scan_job_completed(self):
        url = reverse("scan-detail", kwargs={"pk": self.job2.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "completed")
        self.assertIsNotNone(response.data["result"])
        self.assertEqual(response.data["result"]["technologies"][0]["name"], "Nginx")

    @patch("config.celery.app.control.revoke")
    def test_cancel_scan_job(self, mock_revoke):
        self.job1.celery_task_id = "test-task-id"
        self.job1.save()

        url = reverse("scan-detail", kwargs={"pk": self.job1.id})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        mock_revoke.assert_called_once_with("test-task-id", terminate=True)

        # Check job is deleted
        self.assertFalse(ScanJob.objects.filter(id=self.job1.id).exists())

    def test_get_subresources(self):
        # Technologies
        url = reverse("scan-get-technologies", kwargs={"pk": self.job2.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["name"], "Nginx")

        # Endpoints
        url = reverse("scan-get-endpoints", kwargs={"pk": self.job2.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["url"], "https://test.org/api")

        # Subdomains (empty but exists)
        url = reverse("scan-get-subdomains", kwargs={"pk": self.job2.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])

        # Dependencies (empty but exists)
        url = reverse("scan-get-dependencies", kwargs={"pk": self.job2.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])

    def test_get_subresources_not_available(self):
        url = reverse("scan-get-technologies", kwargs={"pk": self.job1.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @patch("scanner.tasks.run_scan.delay")
    def test_shortcut_tech_sets_correct_flags(self, mock_run_scan_delay):
        mock_task = MagicMock()
        mock_task.id = "mock-task-uuid-tech"
        mock_run_scan_delay.return_value = mock_task

        url = "/api/scan/tech/"
        data = {"url": "https://techonly.com"}
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        job = ScanJob.objects.get(id=response.data["id"])
        self.assertEqual(job.options["scan_technologies"], True)
        self.assertEqual(job.options["scan_subdomains"], False)
        self.assertEqual(job.options["scan_endpoints"], False)
        self.assertEqual(job.options["browser"], True)

    @patch("scanner.tasks.run_scan.delay")
    def test_shortcut_full_sets_all_flags_true(self, mock_run_scan_delay):
        mock_task = MagicMock()
        mock_task.id = "mock-task-uuid-full"
        mock_run_scan_delay.return_value = mock_task

        url = "/api/scan/full/"
        data = {"url": "https://fullscan.com"}
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        job = ScanJob.objects.get(id=response.data["id"])
        self.assertEqual(job.options["scan_technologies"], True)
        self.assertEqual(job.options["scan_subdomains"], True)
        self.assertEqual(job.options["scan_endpoints"], True)
        self.assertEqual(job.options["browser"], True)

    @patch("scanner.tasks.run_scan.delay")
    def test_shortcut_endpoints_disables_tech_and_subdomains(self, mock_run_scan_delay):
        mock_task = MagicMock()
        mock_task.id = "mock-task-uuid-endpoints"
        mock_run_scan_delay.return_value = mock_task

        url = "/api/scan/endpoints/"
        data = {"url": "https://endpoints-only.com"}
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        job = ScanJob.objects.get(id=response.data["id"])
        self.assertEqual(job.options["scan_technologies"], False)
        self.assertEqual(job.options["scan_subdomains"], False)
        self.assertEqual(job.options["scan_endpoints"], True)
        self.assertEqual(job.options["browser"], True)

    @patch("scanner.tasks.run_scan.delay")
    def test_shortcut_subdomains_disables_browser(self, mock_run_scan_delay):
        mock_task = MagicMock()
        mock_task.id = "mock-task-uuid-subs"
        mock_run_scan_delay.return_value = mock_task

        url = "/api/scan/subdomains/"
        data = {"url": "https://subdomains-only.com"}
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        job = ScanJob.objects.get(id=response.data["id"])
        self.assertEqual(job.options["scan_technologies"], False)
        self.assertEqual(job.options["scan_subdomains"], True)
        self.assertEqual(job.options["scan_endpoints"], False)
        self.assertEqual(job.options["browser"], False)

    @patch("scanner.tasks.run_scan.delay")
    def test_shortcut_respects_force_rescan_override(self, mock_run_scan_delay):
        mock_task = MagicMock()
        mock_task.id = "mock-task-uuid-rescan"
        mock_run_scan_delay.return_value = mock_task

        url = "/api/scan/tech/"
        data = {
            "url": "https://techoverride.com",
            "force_rescan": True,
            "timeout": 45.0,
        }
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        job = ScanJob.objects.get(id=response.data["id"])
        self.assertEqual(job.options["timeout"], 45.0)
        mock_run_scan_delay.assert_called_once_with(str(job.id), force_rescan=True)


class ScanJobCeleryTaskTests(APITestCase):
    def setUp(self):
        self.job = ScanJob.objects.create(
            url="https://celerytest.com",
            status="pending",
            options={"browser": True, "timeout": 30.0},
        )

        # Build mock stacksniff ScanResult
        self.mock_scan_result = StacksniffScanResult(
            url="https://celerytest.com",
            scan_time=datetime.now(UTC),
            technologies=[
                TechMatch(
                    name="React",
                    category="javascript-libraries",
                    version="18.2.0",
                    confidence=1.0,
                    evidence=[],
                )
            ],
            api_endpoints=[
                DetectedEndpoint(
                    url="https://celerytest.com/api",
                    method="GET",
                    content_type="application/json",
                    pattern_matched="REST",
                    confidence=0.8,
                )
            ],
            meta=ScanMeta(
                duration_seconds=1.8,
                phases_completed=["http", "browser"],
                fingerprints_version="1.0",
                rules_count=120,
            ),
            openapi_spec_found=True,
            runtime_dependencies=[{"domain": "external.com"}],
            discovered_subdomains=[{"domain": "api.celerytest.com"}],
        )

    @patch("stacksniff.scanner.Scanner.scan", new_callable=AsyncMock)
    def test_run_scan_task_success(self, mock_scan):
        mock_scan.return_value = self.mock_scan_result

        # Run task directly (synchronous call simulating Celery worker thread)
        result = run_scan(str(self.job.id))

        self.assertEqual(result, "completed")
        mock_scan.assert_called_once_with(
            "https://celerytest.com",
            browser=True,
            timeout=30.0,
            cache_bypass=False,
            subdomains=True,
            scan_technologies=True,
            scan_endpoints=True,
        )

        # Refresh from database
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "completed")
        self.assertIsNotNone(self.job.completed_at)

        # Verify ScanResult creation
        scan_res = self.job.result
        self.assertEqual(scan_res.url, "https://celerytest.com")
        self.assertEqual(scan_res.duration_seconds, 1.8)
        self.assertTrue(scan_res.openapi_spec_found)
        self.assertEqual(scan_res.technologies[0]["name"], "React")
        self.assertEqual(scan_res.api_endpoints[0]["url"], "https://celerytest.com/api")
        self.assertEqual(scan_res.runtime_dependencies[0]["domain"], "external.com")
        self.assertEqual(scan_res.discovered_subdomains[0]["domain"], "api.celerytest.com")
        self.assertEqual(scan_res.fingerprints_version, "1.0")

    @patch("stacksniff.scanner.Scanner.scan", new_callable=AsyncMock)
    def test_run_scan_task_failure(self, mock_scan):
        # Scanner raises an exception
        mock_scan.side_effect = RuntimeError("Browser connection lost")

        # Run task
        result = run_scan(str(self.job.id))

        self.assertEqual(result, "failed")

        # Refresh from database
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "failed")
        self.assertEqual(self.job.error_message, "Browser connection lost")
        self.assertIsNotNone(self.job.completed_at)

    @patch("stacksniff.scanner.Scanner.scan", new_callable=AsyncMock)
    def test_run_scan_task_custom_options(self, mock_scan):
        mock_scan.return_value = self.mock_scan_result
        custom_job = ScanJob.objects.create(
            url="https://customcelery.com",
            status="pending",
            options={
                "browser": False,
                "timeout": 15.0,
                "scan_technologies": False,
                "scan_subdomains": False,
                "scan_endpoints": False,
            },
        )
        result = run_scan(str(custom_job.id))
        self.assertEqual(result, "completed")
        mock_scan.assert_called_once_with(
            "https://customcelery.com",
            browser=False,
            timeout=15.0,
            cache_bypass=False,
            subdomains=False,
            scan_technologies=False,
            scan_endpoints=False,
        )


class HealthAndRateLimitTests(APITestCase):
    """Tests for the health check endpoint and per-IP rate limiting."""

    def setUp(self):
        # Clear the cache before EVERY individual test so rate limit counts
        # from other tests (or earlier runs of this test) cannot leak in.
        # Must be setUp (not setUpClass) to reset between each test method.
        cache.clear()

    def test_health_check_ok(self):
        """GET /api/health/ returns 200 and status=ok when DB is reachable
        and Celery workers are active."""
        mock_inspector = MagicMock()
        mock_inspector.active.return_value = {"worker1@host": []}

        with patch("config.celery.app.control.inspect", return_value=mock_inspector):
            response = self.client.get("/api/health/")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["checks"]["database"], "ok")
        self.assertEqual(data["checks"]["celery"], "ok")

    def test_health_check_db_error(self):
        """GET /api/health/ returns 503 and status=degraded when the DB query fails."""
        mock_inspector = MagicMock()
        mock_inspector.active.return_value = {"worker1@host": []}

        with patch("config.celery.app.control.inspect", return_value=mock_inspector), \
             patch("scanner.views.ScanJob") as mock_model:
            mock_model.objects.acount = AsyncMock(
                side_effect=Exception("DB connection refused")
            )
            response = self.client.get("/api/health/")

        self.assertEqual(response.status_code, 503)
        data = response.json()
        self.assertEqual(data["status"], "degraded")
        self.assertIn("error", data["checks"]["database"])
        self.assertIn("DB connection refused", data["checks"]["database"])

    @patch("scanner.tasks.run_scan.delay")
    def test_rate_limit_enforced(self, mock_delay):
        """The 11th POST to /api/scans/ from the same IP within 1 minute
        returns HTTP 429 with a Retry-After header.

        cache.clear() in setUp() ensures each test starts from zero requests.
        """
        mock_delay.return_value.id = "task-rate-test"
        url = reverse("scan-list")
        data = {"url": "https://ratelimit-test.com"}

        # First 10 requests must all succeed
        for i in range(10):
            response = self.client.post(url, data, format="json")
            self.assertEqual(
                response.status_code,
                status.HTTP_201_CREATED,
                msg=f"Request {i + 1} should succeed but got {response.status_code}",
            )

        # 11th request must be rejected
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn(
            "Retry-After",
            response.headers,
            msg="429 response must include Retry-After header",
        )
        self.assertEqual(response.headers["Retry-After"], "60")
