import asyncio
import dataclasses
import logging
import threading
import time

from celery import shared_task
from celery.signals import worker_process_init
from django.utils import timezone

from scanner.models import ScanJob, ScanResult

logger = logging.getLogger(__name__)

# Use gevent's unpatched Thread to ensure the asyncio background event loop
# runs in a real native OS thread on Windows, preventing deadlocks with ProactorEventLoop.
try:
    from gevent.monkey import get_original
    NativeThread = get_original("threading", "Thread")
except (ImportError, KeyError):
    NativeThread = threading.Thread

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
            _loop_thread = NativeThread(
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
    """Execute a scan job asynchronously.
    
    If running under gevent monkey patching, uses a clean Python subprocess to
    avoid the Windows ProactorEventLoop deadlock. Otherwise, runs in-process on the
    persistent background event loop thread (ensuring unit tests and mocks work).
    """
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

    # Calculate timeout
    hard_timeout = max(timeout * 5, 300.0)

    # Check if gevent monkey patching is active
    is_gevent = False
    try:
        from gevent.monkey import is_module_patched
        is_gevent = is_module_patched("socket")
    except ImportError:
        pass

    if not is_gevent:
        # Run in-process using the persistent background event loop
        loop = get_background_loop()

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

        try:
            scan_result = future.result(timeout=hard_timeout)
            res_dict = scan_result.to_dict()

            # Update ScanJob to completed
            job.status = "completed"
            job.completed_at = timezone.now()
            job.save()

            # Create linked ScanResult
            raw_evidence = dataclasses.asdict(scan_result.collected_evidence) if scan_result.collected_evidence else {}
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
                raw_evidence=raw_evidence,
            )
            return "completed"
        except Exception as e:
            logger.exception("Error scanning URL %s for job %s: %s", job.url, job.id, e)
            job.status = "failed"
            job.completed_at = timezone.now()
            job.error_message = str(e) or e.__class__.__name__
            job.save()
            return "failed"

    else:
        # Subprocess script that executes the scan and prints the result JSON
        script = f"""
import asyncio
import dataclasses
import json
import sys
from stacksniff.scanner import Scanner

async def main():
    try:
        scanner = Scanner()
        res = await scanner.scan(
            {repr(job.url)},
            browser={browser},
            timeout={timeout},
            cache_bypass={force_rescan},
            subdomains={scan_subdomains},
            scan_technologies={scan_technologies},
            scan_endpoints={scan_endpoints}
        )
        evidence = {{}}
        if res.collected_evidence is not None:
            evidence = dataclasses.asdict(res.collected_evidence)
        print(json.dumps({{"result": res.to_dict(), "evidence": evidence}}))
    except Exception as e:
        print(json.dumps({{"error": str(e)}}), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
"""

        try:
            # Import Popen cooperatively if gevent is running
            try:
                from gevent.subprocess import Popen, PIPE
            except ImportError:
                from subprocess import Popen, PIPE
            import sys
            import json

            proc = Popen([sys.executable, "-c", script], stdout=PIPE, stderr=PIPE, text=True)
            try:
                stdout, stderr = proc.communicate(timeout=hard_timeout)
            except Exception:
                proc.kill()
                stdout, stderr = proc.communicate()
                raise TimeoutError("Scan process timed out")

            if proc.returncode != 0:
                error_msg = stderr.strip() or stdout.strip() or f"Exit code {proc.returncode}"
                try:
                    err_data = json.loads(error_msg)
                    if "error" in err_data:
                        error_msg = err_data["error"]
                except Exception:
                    pass
                raise RuntimeError(error_msg)

            envelope = json.loads(stdout)
            if "error" in envelope:
                raise RuntimeError(envelope["error"])
            res_dict = envelope["result"]
            raw_evidence = envelope.get("evidence", {})

            # Update ScanJob to completed
            job.status = "completed"
            job.completed_at = timezone.now()
            job.save()

            # Create linked ScanResult (gevent/production path)
            meta = res_dict.get("meta", {})
            ScanResult.objects.create(
                job=job,
                url=res_dict.get("url", job.url),
                scan_time=res_dict.get("scan_time", timezone.now().isoformat()),
                duration_seconds=meta.get("duration_seconds", 0.0),
                technologies=res_dict.get("technologies", []),
                api_endpoints=res_dict.get("api_endpoints", []),
                runtime_dependencies=res_dict.get("runtime_dependencies", []),
                discovered_subdomains=res_dict.get("discovered_subdomains", []),
                openapi_spec_found=res_dict.get("openapi_spec_found", False),
                phases_completed=meta.get("phases_completed", []),
                rules_count=meta.get("rules_count", 0),
                fingerprints_version=meta.get("fingerprints_version", ""),
                raw_evidence=raw_evidence,
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
