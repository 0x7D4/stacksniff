"""Scanner orchestrator that coordinates the web tech detection pipeline."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable  # noqa: TC003
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003
from typing import Any

from stacksniff.analyzers.api_detector import ApiDetector
from stacksniff.analyzers.fingerprint_matcher import FingerprintMatcher
from stacksniff.collectors.base import CollectorResult, NetworkRequest
from stacksniff.collectors.cookie_collector import CookieCollector
from stacksniff.collectors.domain_mapper import DomainMapper
from stacksniff.collectors.framework_prober import FrameworkProber
from stacksniff.collectors.header_collector import HeaderCollector
from stacksniff.collectors.html_collector import HtmlCollector
from stacksniff.collectors.js_collector import JsCollector
from stacksniff.collectors.js_static_collector import JsStaticCollector
from stacksniff.collectors.network_collector import NetworkCollector
from stacksniff.fingerprints import FingerprintStore
from stacksniff.models import CollectedEvidence, ScanMeta, ScanResult

logger = logging.getLogger(__name__)


class Scanner:
    """Orchestrates Phase 1 (HTTP), Phase 2 (Browser), and Phase 3 (Analysis)."""

    def __init__(self, fingerprints_path: Path | None = None) -> None:
        self.default_store: FingerprintStore | None = None
        self.fingerprints_path = fingerprints_path

    def _get_store(self, path: Path | None = None) -> FingerprintStore:
        """Resolve and load the FingerprintStore."""
        if path is not None:
            return FingerprintStore.from_yaml(path)
        if self.default_store is not None:
            return self.default_store

        if self.fingerprints_path is not None:
            self.default_store = FingerprintStore.from_yaml(self.fingerprints_path)
        else:
            self.default_store = FingerprintStore.default()
        return self.default_store

    async def scan(
        self,
        url: str,
        *,
        browser: bool = True,
        timeout: float = 30.0,
        fingerprints_path: Path | None = None,
        progress_callback: Callable[[str, str], None] | None = None,
        crawl_depth: int = 1,
    ) -> ScanResult:
        """Scan a URL and return a structured ScanResult."""
        start_time = time.monotonic()
        phases_completed: list[str] = []

        store = self._get_store(fingerprints_path)

        # -------------------------------------------------------------------
        # Phase 1: HTTP-only collectors
        # -------------------------------------------------------------------
        if progress_callback:
            progress_callback("http", "started")

        header_collector = HeaderCollector(timeout=timeout)
        cookie_collector = CookieCollector(timeout=timeout)
        html_collector = HtmlCollector(timeout=timeout)

        # Run concurrently
        header_task = header_collector.collect(url)
        cookie_task = cookie_collector.collect(url)
        html_task = html_collector.collect(url)

        header_res, cookie_res, html_res = await asyncio.gather(
            header_task, cookie_task, html_task, return_exceptions=True
        )

        def _safe_res(res: Any) -> CollectorResult:
            if isinstance(res, Exception):
                logger.error("Collector raised an exception: %s", res, exc_info=res)
                return CollectorResult()
            return res

        header_ok = _safe_res(header_res)
        cookie_ok = _safe_res(cookie_res)
        html_ok = _safe_res(html_res)

        headers = header_ok.data.get("headers", {})
        cookies = cookie_ok.data.get("cookies", {})
        html = html_ok.data.get("raw_html", "")
        meta_tags = html_ok.data.get("meta_tags", {})
        script_srcs = html_ok.data.get("script_srcs", [])
        link_hrefs = html_ok.data.get("link_hrefs", [])
        manifest_url = html_ok.data.get("manifest_url")

        # Collect static DOM evidence
        dom_evidence = html_ok.data.get("dom", {}).copy()

        # Run JsStaticCollector in a second gather - chained after HtmlCollector
        js_static_collector = JsStaticCollector(script_srcs, base_url=url, timeout=timeout)
        js_static_res_list = await asyncio.gather(
            js_static_collector.collect(url), return_exceptions=True
        )
        js_static_ok = _safe_res(js_static_res_list[0])
        static_endpoints = js_static_ok.data.get("static_endpoints", [])

        phases_completed.append("http")
        if progress_callback:
            progress_callback("http", "completed")

        # -------------------------------------------------------------------
        # Phase 2: Headless browser collectors
        # -------------------------------------------------------------------
        js_globals: dict[str, str] = {}
        network_requests: list[NetworkRequest] = []
        probed_paths: list[NetworkRequest] = []

        # Check if browser is requested and Playwright is installed
        playwright_installed = False
        if browser:
            try:
                import playwright  # noqa: F401

                playwright_installed = True
            except ImportError:
                playwright_installed = False

        if browser and playwright_installed:
            if progress_callback:
                progress_callback("browser", "started")

            js_collector = JsCollector(timeout=timeout)
            network_collector = NetworkCollector(timeout=timeout, max_crawl_depth=crawl_depth)

            js_task = js_collector.collect(url)
            net_task = network_collector.collect(url)

            js_res, net_res = await asyncio.gather(js_task, net_task, return_exceptions=True)

            js_ok = _safe_res(js_res)
            net_ok = _safe_res(net_res)

            logger.debug("net_ok har_entries count: %d", len(net_ok.data.get("har_entries", [])))

            js_globals = js_ok.data.get("js_globals", {})

            # Merge browser DOM findings
            for sel, findings in js_ok.data.get("dom", {}).items():
                if sel not in dom_evidence:
                    dom_evidence[sel] = findings
                else:
                    existing_texts = {f["text"] for f in dom_evidence[sel]}
                    for f in findings:
                        if f["text"] not in existing_texts:
                            dom_evidence[sel].append(f)

            # Deserialise browser network requests
            for req_dict in net_ok.data.get("network_requests", []):
                network_requests.append(
                    NetworkRequest(
                        url=req_dict.get("url", ""),
                        method=req_dict.get("method", "GET"),
                        resource_type=req_dict.get("resource_type", "xhr"),
                        status=req_dict.get("status"),
                        content_type=req_dict.get("content_type"),
                        request_headers=req_dict.get("request_headers", {}),
                        response_headers=req_dict.get("response_headers", {}),
                    )
                )

            # Deserialise probed paths
            for probe_dict in net_ok.data.get("probed_paths", []):
                nr = NetworkRequest(
                    url=probe_dict.get("url", ""),
                    method=probe_dict.get("method", "GET"),
                    resource_type=probe_dict.get("resource_type", "probe"),
                    status=probe_dict.get("status"),
                    content_type=probe_dict.get("content_type"),
                    request_headers=probe_dict.get("request_headers", {}),
                    response_headers=probe_dict.get("response_headers", {}),
                )
                probed_paths.append(nr)
                # Keep them in network_requests too, so ApiDetector can process them
                # if it is called directly on evidence.network_requests.
                network_requests.append(nr)

            phases_completed.append("browser")
            if progress_callback:
                progress_callback("browser", "completed")

        # Extract OpenAPI Spec details if available
        parsed_spec_data = None
        s_endpoints = []
        s_title = None
        s_version = None
        s_methods = {}
        if browser and playwright_installed:
            parsed_spec_data = net_ok.data.get("parsed_spec")
            s_endpoints = net_ok.data.get("spec_endpoints", [])
            if parsed_spec_data:
                info_data = parsed_spec_data.get("info", {})
                s_title = info_data.get("title")
                s_version = info_data.get("version")
                s_methods = parsed_spec_data.get("paths", {})

        # -------------------------------------------------------------------
        # Build CollectedEvidence
        # -------------------------------------------------------------------
        evidence = CollectedEvidence(
            headers=headers,
            cookies=cookies,
            html=html,
            meta_tags=meta_tags,
            script_srcs=script_srcs,
            link_hrefs=link_hrefs,
            js_globals=js_globals,
            dom=dom_evidence,
            network_requests=network_requests,
            probed_paths=probed_paths,
            static_endpoints=static_endpoints,
            spec_endpoints=s_endpoints,
            spec_title=s_title,
            spec_version=s_version,
            spec_methods=s_methods,
            manifest_url=manifest_url,
        )

        # -------------------------------------------------------------------
        # Phase 3: Match fingerprints & detect APIs  +  Domain mapping
        # (run concurrently — domain mapper is pure I/O, independent of
        #  fingerprint matching)
        # -------------------------------------------------------------------
        evidence_dict = {
            "headers": evidence.headers,
            "cookies": evidence.cookies,
            "html": evidence.html,
            "meta_tags": evidence.meta_tags,
            "script_srcs": evidence.script_srcs,
            "link_hrefs": evidence.link_hrefs,
            "js_globals": evidence.js_globals,
            "dom": evidence.dom,
            "manifest_url": evidence.manifest_url,
            "network_requests": [req.url for req in evidence.network_requests],
        }

        matcher = FingerprintMatcher(store)
        tech_matches = matcher.match(evidence_dict)

        # -------------------------------------------------------------------
        # Phase 3.5: SecLists-based framework path probing  +  Domain mapping
        # Run both concurrently.
        # -------------------------------------------------------------------
        if progress_callback:
            progress_callback("framework_probe", "started")

        # Collect HAR entries produced during browser phase
        har_entries: list[dict] = []
        if browser and playwright_installed:
            har_entries = net_ok.data.get("har_entries", [])

        logger.debug("domain_mapper har_entries received: %d", len(har_entries))

        prober = FrameworkProber(tech_matches, url, timeout=timeout)
        domain_mapper = DomainMapper(
            base_url=url,
            har_entries=har_entries,
            fingerprint_store=store,
            timeout=timeout,
        )

        probe_result_raw, domain_result_raw = await asyncio.gather(
            prober.collect(),
            domain_mapper.collect(),
            return_exceptions=True,
        )

        if isinstance(probe_result_raw, Exception):
            logger.error("FrameworkProber raised: %s", probe_result_raw)
            probe_result: CollectorResult = CollectorResult()
        else:
            probe_result = probe_result_raw

        if isinstance(domain_result_raw, Exception):
            logger.error("DomainMapper raised: %s", domain_result_raw)
            domain_result: CollectorResult = CollectorResult()
        else:
            domain_result = domain_result_raw

        framework_endpoints = probe_result.data.get("framework_endpoints", [])
        evidence.framework_endpoints = framework_endpoints
        evidence.runtime_dependencies = domain_result.data.get("external_dependencies", [])
        evidence.discovered_subdomains = domain_result.data.get("internal_subdomains", [])

        if progress_callback:
            progress_callback("framework_probe", "completed")

        detector = ApiDetector()
        detected_endpoints = detector.detect(evidence)

        # -------------------------------------------------------------------
        # Phase 4: Report assembly
        # -------------------------------------------------------------------
        duration = time.monotonic() - start_time
        meta = ScanMeta(
            duration_seconds=duration,
            phases_completed=phases_completed,
            fingerprints_version=store.version,
            rules_count=len(store.get_all()),
        )

        return ScanResult(
            url=url,
            scan_time=datetime.now(UTC),
            technologies=tech_matches,
            api_endpoints=detected_endpoints,
            meta=meta,
            openapi_spec_found=bool(evidence.spec_endpoints),
            runtime_dependencies=evidence.runtime_dependencies,
            discovered_subdomains=evidence.discovered_subdomains,
        )


def scan_sync(
    url: str,
    *,
    browser: bool = True,
    timeout: float = 30.0,
    fingerprints_path: Path | None = None,
) -> ScanResult:
    """Synchronously scan a URL using asyncio.run."""
    scanner = Scanner()
    return asyncio.run(
        scanner.scan(
            url,
            browser=browser,
            timeout=timeout,
            fingerprints_path=fingerprints_path,
        )
    )
