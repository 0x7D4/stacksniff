"""Collect JavaScript global variables from a target URL via Playwright.

Launches a headless Chromium browser, navigates to the target, waits for
``networkidle``, then evaluates a curated list of JS expressions to detect
frameworks, libraries, and runtime globals.

Returned ``data`` dict shape::

    {
        "js_globals": {
            "window.jQuery":            "function",
            "window.jQuery?.fn?.jquery": "3.7.1",
            "window.__NEXT_DATA__":     "{\"props\":{...}}",
            "window.ga":               "function",
        },
        "final_url": "https://www.example.com/",
    }

Only globals that exist (not ``undefined``) and don't throw on access
are included.  Values are JSON-stringified where possible, otherwise
the ``typeof`` result is stored.

If Playwright is not installed the collector returns an empty result
with a warning — it never raises ``ImportError``.
"""

from __future__ import annotations

import logging

from stacksniff.collectors.base import CollectorResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# JS expressions to probe — order doesn't matter, dict preserves insertion.
# ---------------------------------------------------------------------------

_JS_GLOBALS: tuple[str, ...] = (
    "window.React",
    "window.React?.version",
    "window.__NEXT_DATA__",
    "window.__nuxt",
    "window.angular",
    "window.Vue",
    "window.Backbone",
    "window.jQuery",
    "window.jQuery?.fn?.jquery",
    "window.wp",
    "window.Drupal",
    "window.Shopify",
    "window.ga",
    "window.gtag",
    "window.dataLayer",
    "window.__REDUX_STORE__",
    "window.supabase",
    "window.__FIREBASE_DEFAULTS__",
    # Closure Library
    "window.goog",
    "window.goog?.CLOSURE_NO_DEPS",
    "window.CLOSURE_BASE_PATH",
    "window.goog?.require",
    "window.WebFonts",
)

# JS snippet template injected into the page.  For each expression we
# return an object ``{type, value}`` or ``null`` if undefined/throws.
# The ``_MAX_VALUE_LEN`` cap prevents multi-MB __NEXT_DATA__ payloads
# from ballooning memory.
_MAX_VALUE_LEN: int = 1_024

_EVALUATE_TEMPLATE = """
() => {{
    const expressions = {expressions_json};
    const maxLen = {max_len};
    const results = {{}};

    function getGlobalValue(path) {{
        if (typeof window === 'undefined') return undefined;
        if (path in window) {{
            return window[path];
        }}
        let normalizedPath = path.replace(/\\?\\./g, '.');
        if (normalizedPath.startsWith('window.')) {{
            normalizedPath = normalizedPath.substring(7);
            if (normalizedPath in window) {{
                return window[normalizedPath];
            }}
        }}
        const parts = normalizedPath.split('.');
        let curr = window;
        for (const part of parts) {{
            if (curr === null || (typeof curr !== 'object' && typeof curr !== 'function')) {{
                return undefined;
            }}
            curr = curr[part];
        }}
        return curr;
    }}

    for (const expr of expressions) {{
        try {{
            const val = getGlobalValue(expr);
            if (typeof val === 'undefined') continue;
            let serialised;
            if (typeof val === 'function') {{
                serialised = 'function';
            }} else if (typeof val === 'object' && val !== null) {{
                try {{
                    const s = JSON.stringify(val);
                    serialised = s.length > maxLen ? s.slice(0, maxLen) + '...' : s;
                }} catch (_) {{
                    serialised = typeof val;
                }}
            }} else {{
                serialised = String(val);
            }}
            results[expr] = serialised;
        }} catch (_) {{
            // expression threw — skip it
        }}
    }}
    return results;
}}
"""

_DEFAULT_TIMEOUT: float = 30.0


class JsCollector:
    """Async collector that detects JS globals via Playwright.

    Parameters
    ----------
    timeout:
        Total timeout in seconds for browser launch + navigation + eval.
    """

    def __init__(self, *, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Collector protocol
    # ------------------------------------------------------------------

    async def collect(self, url: str) -> CollectorResult:
        """Navigate to *url* in headless Chromium and probe JS globals.

        Returns partial results on timeout or navigation errors.
        Returns an empty result (with warning) if Playwright is
        not installed.
        """
        result = CollectorResult()

        # ---- guard: Playwright optional dependency --------------------
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            result.add_error(
                "Playwright is not installed. Install with: "
                "pip install playwright && python -m playwright install chromium"
            )
            return result

        # ---- build the evaluation script ------------------------------
        import json as _json

        # Dynamically load unique js_globals from tech.yaml database
        expressions = list(_JS_GLOBALS)
        try:
            from stacksniff.fingerprints import FingerprintStore
            store = FingerprintStore.default()
            for fp in store.get_all():
                for gk in fp.js_globals.keys():
                    # Deduplicate and add
                    if gk not in expressions:
                        expressions.append(gk)
        except Exception as e:
            logger.warning("Could not load dynamic js_globals from FingerprintStore: %s", e)

        expressions_json = _json.dumps(expressions)
        evaluate_script = _EVALUATE_TEMPLATE.format(
            expressions_json=expressions_json,
            max_len=_MAX_VALUE_LEN,
        )

        timeout_ms = int(self._timeout * 1_000)

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    context = await browser.new_context(
                        java_script_enabled=True,
                        ignore_https_errors=True,
                    )
                    page = await context.new_page()
                    page.set_default_timeout(timeout_ms)

                    # Navigate and wait for network to settle
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                    except Exception as nav_exc:
                        # Page may still be usable (partial load, timeout)
                        result.add_error(f"Navigation issue: {nav_exc}")

                    # Evaluate JS globals
                    final_url = page.url
                    try:
                        js_results: dict[str, str] = await page.evaluate(evaluate_script)
                    except Exception as eval_exc:
                        logger.warning("JS evaluation failed on %s: %s", url, eval_exc)
                        result.add_error(f"JS evaluation error: {eval_exc}")
                        js_results = {}

                    # Evaluate DOM selectors
                    dom_results = {}
                    try:
                        from stacksniff.fingerprints import FingerprintStore
                        store = FingerprintStore.default()
                        dom_selectors = list(store.get_all_dom_selectors())
                    except Exception as e:
                        logger.warning("Could not load dynamic dom selectors from FingerprintStore: %s", e)
                        dom_selectors = []

                    if dom_selectors:
                        try:
                            dom_js = """
                            (selectors) => {
                                const results = {};
                                for (const sel of selectors) {
                                    try {
                                        const elements = document.querySelectorAll(sel);
                                        if (elements.length > 0) {
                                            const findings = [];
                                            for (const el of elements) {
                                                const attrs = {};
                                                for (let i = 0; i < el.attributes.length; i++) {
                                                    const attr = el.attributes[i];
                                                    attrs[attr.name] = attr.value;
                                                }
                                                const props = {};
                                                for (const key of ['src', 'href', 'type', 'value', 'name', 'id']) {
                                                    if (el[key] !== undefined && typeof el[key] === 'string') {
                                                        props[key] = el[key];
                                                    }
                                                }
                                                findings.push({
                                                    text: el.textContent ? el.textContent.trim() : "",
                                                    attributes: attrs,
                                                    properties: props
                                                });
                                            }
                                            results[sel] = findings;
                                        }
                                    } catch (_) {}
                                }
                                return results;
                            }
                            """
                            dom_results = await page.evaluate(dom_js, dom_selectors)
                        except Exception as dom_exc:
                            logger.warning("DOM evaluation failed on %s: %s", url, dom_exc)

                    # Check for service worker registration
                    sw_registered = False
                    try:
                        sw_registered = await page.evaluate(
                            "async () => { "
                            "  try { "
                            "    if (navigator.serviceWorker) { "
                            "      const regs = await navigator.serviceWorker.getRegistrations(); "
                            "      return regs && regs.length > 0; "
                            "    } "
                            "  } catch (_) {} "
                            "  return false; "
                            "}"
                        )
                    except Exception as sw_exc:
                        logger.debug("Failed to query service workers: %s", sw_exc)

                    if sw_registered:
                        pwa_sel = "link[rel='manifest']"
                        if pwa_sel not in dom_results:
                            dom_results[pwa_sel] = [
                                {
                                    "text": "",
                                    "attributes": {"rel": "manifest", "href": "/manifest.json"},
                                    "properties": {"rel": "manifest", "href": "/manifest.json"},
                                }
                            ]

                    result.data = {
                        "js_globals": js_results,
                        "dom": dom_results,
                        "final_url": final_url,
                    }

                finally:
                    await browser.close()

        except Exception as exc:  # noqa: BLE001
            logger.exception("Playwright error collecting JS globals from %s", url)
            result.add_error(f"Browser error: {exc}")

        return result
