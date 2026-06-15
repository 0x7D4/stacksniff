import asyncio
import logging
import threading

from celery import shared_task
from celery.signals import worker_process_init
from django.utils import timezone

from scanner.models import ScanJob, ScanResult

logger = logging.getLogger(__name__)

# Persistent background event loop and thread
_background_loop = None
_loop_thread = None
_loop_lock = threading.Lock()


def get_background_loop() -> asyncio.AbstractEventLoop:
    """Return or create a thread-safe background event loop."""
    global _background_loop, _loop_thread
    with _loop_lock:
        if _background_loop is None:
            _background_loop = asyncio.new_event_loop()
            _loop_thread = threading.Thread(
                target=_background_loop.run_forever,
                name="StacksniffEventLoopThread",
                daemon=True,
            )
            _loop_thread.start()
            logger.info("Started persistent stacksniff background event loop thread.")
    return _background_loop


@worker_process_init.connect
def init_browser_pool(**kwargs) -> None:
    """Pre-initialize Playwright BrowserPool once per Celery worker process."""
    logger.info("Initializing BrowserPool for Celery worker process.")
    loop = get_background_loop()
    from stacksniff.browser_pool import initialize_pool

    future = asyncio.run_coroutine_threadsafe(initialize_pool(), loop)
    try:
        # Wait for the initialization to complete
        future.result(timeout=60.0)
        logger.info("BrowserPool initialized successfully in background event loop.")
    except Exception as e:
        logger.exception("Failed to initialize BrowserPool in worker process: %s", e)


@shared_task(bind=True)
def run_scan(self, job_id: str, force_rescan: bool = False) -> str:
    """Execute a scan job asynchronously using the background event loop."""
    try:
        job = ScanJob.objects.get(id=job_id)
    except ScanJob.DoesNotExist:
        logger.error("ScanJob with id %s does not exist.", job_id)
        return "ScanJob not found"

    # Update status to running
    job.status = "running"
    job.started_at = timezone.now()
    job.celery_task_id = self.request.id
    job.save()

    # Get scan options
    options = job.options
    browser = options.get("browser", True)
    timeout = float(options.get("timeout", 30.0))
    scan_technologies = options.get("scan_technologies", True)
    scan_subdomains = options.get("scan_subdomains", True)
    scan_endpoints = options.get("scan_endpoints", True)

    loop = get_background_loop()

    # Async wrapper to initialize and run the scan
    async def perform_scan():
        from stacksniff.scanner import Scanner

        scanner = Scanner()
        return await scanner.scan(
            job.url,
            browser=browser,
            timeout=timeout,
            cache_bypass=force_rescan,
            subdomains=scan_subdomains,
            scan_technologies=scan_technologies,
            scan_endpoints=scan_endpoints,
        )

    # Schedule the coroutine on the background event loop
    future = asyncio.run_coroutine_threadsafe(perform_scan(), loop)

    # Calculate a generous hard timeout to allow all sequential phases,
    # retries, and browser tasks to finish. The total scan can take
    # significantly longer than a single collector timeout.
    hard_timeout = max(timeout * 5, 300.0)

    try:
        scan_result = future.result(timeout=hard_timeout)

        # Convert to dictionary representation for database storage
        res_dict = scan_result.to_dict()

        # Update ScanJob to completed
        job.status = "completed"
        job.completed_at = timezone.now()
        job.save()

        # Create linked ScanResult
        ScanResult.objects.create(
            job=job,
            url=scan_result.url,
            scan_time=scan_result.scan_time,
            duration_seconds=scan_result.meta.duration_seconds,
            technologies=res_dict.get("technologies", []),
            api_endpoints=res_dict.get("api_endpoints", []),
            runtime_dependencies=res_dict.get("runtime_dependencies", []),
            discovered_subdomains=res_dict.get("discovered_subdomains", []),
            openapi_spec_found=scan_result.openapi_spec_found,
            phases_completed=scan_result.meta.phases_completed,
            rules_count=scan_result.meta.rules_count,
            fingerprints_version=scan_result.meta.fingerprints_version,
        )

        return "completed"

    except Exception as e:
        logger.exception("Error scanning URL %s for job %s: %s", job.url, job.id, e)
        # Update ScanJob to failed
        job.status = "failed"
        job.completed_at = timezone.now()
        job.error_message = str(e) or e.__class__.__name__
        job.save()
        return "failed"
