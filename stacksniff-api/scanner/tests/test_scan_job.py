from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

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

        # Verify task was called with correct arguments
        mock_run_scan_delay.assert_called_once_with(str(job.id), force_rescan=True)

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
