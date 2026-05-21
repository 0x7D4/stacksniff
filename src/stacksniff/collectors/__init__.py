"""stacksniff.collectors -- Evidence collection from HTTP responses, HTML, cookies, and browsers."""

from stacksniff.collectors.base import Collector, CollectorResult, NetworkRequest
from stacksniff.collectors.cookie_collector import CookieCollector
from stacksniff.collectors.header_collector import HeaderCollector
from stacksniff.collectors.html_collector import HtmlCollector
from stacksniff.collectors.js_collector import JsCollector
from stacksniff.collectors.js_static_collector import JsStaticCollector
from stacksniff.collectors.network_collector import NetworkCollector

__all__ = [
    "Collector",
    "CollectorResult",
    "CookieCollector",
    "HeaderCollector",
    "HtmlCollector",
    "JsCollector",
    "NetworkCollector",
    "JsStaticCollector",
    "NetworkRequest",
]
