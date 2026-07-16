// src/matchers/FingerprintMatcher.test.ts

import { describe, it, expect, beforeEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { FingerprintStore, FingerprintMatcher } from "./FingerprintMatcher";

describe("FingerprintMatcher Tests", () => {
  let store: FingerprintStore;

  beforeEach(() => {
    // Load default fingerprints.json from stacksniff-api static files
    const jsonPath = path.resolve(
      __dirname,
      "../../../stacksniff-api/scanner/static/scanner/fingerprints.json"
    );
    const rawData = JSON.parse(fs.readFileSync(jsonPath, "utf-8"));
    store = new FingerprintStore(rawData);
  });

  it("should match basic headers, extract version and calculate confidence", () => {
    const matcher = new FingerprintMatcher(store);
    const evidence = {
      headers: {
        Server: "nginx/1.25.3",
      },
    };

    const results = matcher.match(evidence);
    const nginxMatch = results.find((m) => m.name === "Nginx");

    expect(nginxMatch).toBeDefined();
    expect(nginxMatch!.version).toBe("1.25.3");
    // Base confidence = 0.9, version boost = +0.1, capped at 1.0
    expect(nginxMatch!.confidence).toBe(1.0);
    expect(nginxMatch!.evidence.length).toBe(1);
    expect(nginxMatch!.evidence[0].source).toBe("header");
    expect(nginxMatch!.evidence[0].matched).toBe("nginx/1.25.3");
  });

  it("should boost confidence from multiple corroborating sources", () => {
    const matcher = new FingerprintMatcher(store);
    // WordPress base = 0.85. 2 sources (meta generator + wp-content html) -> +0.1 -> 0.95.
    // Version matched in meta generator (+0.1) -> 1.05 -> capped at 1.0.
    const evidence = {
      meta_tags: {
        generator: "WordPress 6.4.2",
      },
      html: "<html><body><div class='wp-content'>Hello</div></body></html>",
    };

    const results = matcher.match(evidence);
    const wpMatch = results.find((m) => m.name === "WordPress");

    expect(wpMatch).toBeDefined();
    expect(wpMatch!.version).toBe("6.4.2");
    expect(wpMatch!.confidence).toBe(1.0);

    // Verify implies triggers: WordPress implies PHP and MySQL
    const phpMatch = results.find((m) => m.name === "PHP");
    const mysqlMatch = results.find((m) => m.name === "MySQL");

    expect(phpMatch).toBeDefined();
    expect(phpMatch!.confidence).toBe(0.6);
    expect(mysqlMatch).toBeDefined();
    expect(mysqlMatch!.confidence).toBe(0.6);
  });

  it("should normalize JS globals and match them", () => {
    const matcher = new FingerprintMatcher(store);
    const evidence = {
      js_globals: {
        "window.React": "function",
        "window.React?.version": "18.2.0",
      },
    };

    const results = matcher.match(evidence);
    const reactMatch = results.find((m) => m.name === "React");

    expect(reactMatch).toBeDefined();
    expect(reactMatch!.version).toBe("18.2.0");
    // Base confidence = 0.8. Version capture = 18.2.0 -> +0.1 -> 0.9.
    expect(reactMatch!.confidence).toBe(0.9);
  });

  it("should match custom DOM rules and selectors", () => {
    const categories = { "1": { name: "CMS" } };
    const fp1 = {
      name: "LottieFiles",
      category: "CMS",
      dom: ["lottie-player", "a[href*='lottie']"],
      confidence: 0.8,
      headers: {},
      cookies: {},
      meta: {},
      scripts: [],
      html: [],
      js_globals: {},
      implies: [],
    };

    const fp2 = {
      name: "Google Font API",
      category: "CMS",
      dom: {
        "link[href*='fonts.googleapis.com']": {
          exists: "",
        },
        "link[rel='stylesheet']": {
          attributes: {
            href: "fonts\\.googleapis\\.com/css\\?family=(.+)",
          },
        },
      },
      confidence: 0.7,
      headers: {},
      cookies: {},
      meta: {},
      scripts: [],
      html: [],
      js_globals: {},
      implies: [],
    };

    const customStore = new FingerprintStore({
      version: "1.0.0",
      categories,
      technologies: {
        lottiefiles: fp1,
        "google font api": fp2,
      },
    });

    const matcher = new FingerprintMatcher(customStore);

    // Test list-based selector matching
    const evidence1 = {
      dom: {
        "lottie-player": [
          {
            text: "",
            attributes: { src: "animation.json" },
            properties: {},
          },
        ],
      },
    };

    const results1 = matcher.match(evidence1);
    const lottieMatch = results1.find((m) => m.name === "LottieFiles");
    expect(lottieMatch).toBeDefined();
    expect(lottieMatch!.confidence).toBe(0.8);
    expect(lottieMatch!.evidence[0].source).toBe("dom");
    expect(lottieMatch!.evidence[0].pattern).toBe("lottie-player");

    // Test dict-based attributes regex match and version extraction
    const evidence2 = {
      dom: {
        "link[rel='stylesheet']": [
          {
            text: "",
            attributes: {
              rel: "stylesheet",
              href: "https://fonts.googleapis.com/css?family=Roboto:400,700",
            },
            properties: {},
          },
        ],
      },
    };

    const results2 = matcher.match(evidence2);
    const fontMatch = results2.find((m) => m.name === "Google Font API");
    expect(fontMatch).toBeDefined();
    // confidence = base (0.7) + version matched (+0.1) = 0.8
    expect(fontMatch!.confidence).toBe(0.8);
    expect(fontMatch!.version).toBe("Roboto:400,700");
  });

  it("should detect PWA when manifest_url is present", () => {
    const matcher = new FingerprintMatcher(store);
    const evidence = {
      manifest_url: "/manifest.json",
    };

    const results = matcher.match(evidence);
    const pwaMatch = results.find((m) => m.name === "PWA");

    expect(pwaMatch).toBeDefined();
    expect(pwaMatch!.confidence).toBeGreaterThanOrEqual(0.75);
    expect(pwaMatch!.evidence.some((e) => e.source === "dom")).toBe(true);
  });

  it("should NOT detect PWA when manifest_url is absent", () => {
    const matcher = new FingerprintMatcher(store);
    const evidence = {
      headers: {
        Server: "nginx",
      },
    };

    const results = matcher.match(evidence);
    const pwaMatch = results.find((m) => m.name === "PWA");

    expect(pwaMatch).toBeUndefined();
  });

  it("should detect Google Font API via network_requests", () => {
    const matcher = new FingerprintMatcher(store);
    const evidence = {
      network_requests: [
        "https://fonts.googleapis.com/css?family=Roboto:400,700",
        "https://fonts.gstatic.com/s/roboto/v30/KFOmCnqEu92Fr1Mu4mxK.woff2",
      ],
    };

    const results = matcher.match(evidence);
    const fontMatch = results.find((m) => m.name === "Google Font API");

    expect(fontMatch).toBeDefined();
    expect(fontMatch!.confidence).toBe(0.75);
    expect(fontMatch!.version).toBeNull();
    expect(fontMatch!.evidence.some((e) => e.source === "dom")).toBe(true);
  });
});
