// src/matchers/FingerprintMatcher.ts — ported from src/stacksniff/analyzers/fingerprint_matcher.py

import { CollectedEvidence, TechMatch, Evidence } from "../types/evidence";

export interface Fingerprint {
  name: string;
  category: string;
  website?: string | null;
  headers: Record<string, string>;
  cookies: Record<string, string>;
  meta: Record<string, string>;
  scripts: string[];
  html: string[];
  js_globals: Record<string, string>;
  dom: Record<string, any> | string[];
  implies: string[];
  confidence: number;
}

export class FingerprintStore {
  version: string;
  categories: Record<string, Record<string, string>>;
  technologies: Map<string, Fingerprint>;

  constructor(rawData: any) {
    this.version = String(rawData.version || "1.0.0");
    this.categories = rawData.categories || {};
    this.technologies = new Map<string, Fingerprint>();

    const rawTechs = rawData.technologies || {};
    for (const [key, data] of Object.entries(rawTechs)) {
      if (!data || typeof data !== "object") continue;
      const t = data as any;
      const name = String(t.name || key);
      const catSlug = String(t.category || "other");
      const catInfo = this.categories[catSlug];
      const categoryName = catInfo ? String(catInfo.name || catSlug) : catSlug;

      const fingerprint: Fingerprint = {
        name,
        category: categoryName,
        website: t.website ? String(t.website) : null,
        headers: t.headers || {},
        cookies: t.cookies || {},
        meta: t.meta || {},
        scripts: Array.isArray(t.scripts) ? t.scripts.map(String) : [],
        html: Array.isArray(t.html) ? t.html.map(String) : [],
        js_globals: t.js_globals || {},
        dom: Array.isArray(t.dom) ? t.dom.map(String) : (t.dom || {}),
        implies: Array.isArray(t.implies) ? t.implies.map(String) : [],
        confidence: typeof t.confidence === "number" ? t.confidence : 0.5,
      };

      this.technologies.set(key.toLowerCase(), fingerprint);
    }
  }

  get_all(): Fingerprint[] {
    return Array.from(this.technologies.values());
  }

  get_all_dom_selectors(): Set<string> {
    const selectors = new Set<string>();
    for (const f of this.technologies.values()) {
      if (Array.isArray(f.dom)) {
        for (const sel of f.dom) selectors.add(sel);
      } else if (f.dom && typeof f.dom === "object") {
        for (const sel of Object.keys(f.dom)) selectors.add(sel);
      }
    }
    return selectors;
  }

  resolve_implies(matches: TechMatch[]): TechMatch[] {
    const matchMap = new Map<string, TechMatch>();
    for (const m of matches) {
      matchMap.set(m.name.toLowerCase(), m);
    }

    const queue = Array.from(matchMap.keys());
    const visited = new Set<string>(queue);

    while (queue.length > 0) {
      const currentTech = queue.shift()!;
      const rule = this.technologies.get(currentTech);
      if (!rule || !rule.implies) {
        continue;
      }

      for (const implied of rule.implies) {
        const impliedKey = implied.toLowerCase();
        const impliedRule = this.technologies.get(impliedKey);
        const impliedName = impliedRule ? impliedRule.name : implied;
        const impliedCategory = impliedRule ? impliedRule.category : "";

        const existing = matchMap.get(impliedKey);
        if (existing) {
          if (existing.confidence < 0.6) {
            matchMap.set(impliedKey, {
              name: existing.name,
              category: existing.category,
              version: existing.version,
              confidence: 0.6,
              evidence: [
                ...existing.evidence,
                {
                  source: "implies",
                  key: "implies",
                  matched: `Implied by ${rule.name}`,
                  pattern: "",
                },
              ],
            });
          }
        } else {
          matchMap.set(impliedKey, {
            name: impliedName,
            category: impliedCategory,
            version: null,
            confidence: 0.6,
            evidence: [
              {
                source: "implies",
                key: "implies",
                matched: `Implied by ${rule.name}`,
                pattern: "",
              },
            ],
          });
        }

        if (!visited.has(impliedKey)) {
          visited.add(impliedKey);
          queue.push(impliedKey);
        }
      }
    }

    return Array.from(matchMap.values());
  }
}

export function _normalize_js_key(k: string): string {
  let key = k.trim();
  if (key.startsWith("window.")) {
    key = key.slice(7);
  }
  key = key.replace(/\?\./g, ".");
  if (key.endsWith("()")) {
    key = key.slice(0, -2);
  }
  return key.toLowerCase().trim();
}

const SELECTOR_PATTERN = /^(?<tag>[a-zA-Z0-9_-]*)\[(?<attr>[a-zA-Z0-9_-]+)(?<op>[~|^$*]?=)['"]?(?<val>[^'"\]]+)['"]?\]$/;

export function _match_network_request_to_selector(url: string, sel: string): any | null {
  const match = SELECTOR_PATTERN.exec(sel);
  if (!match || !match.groups) {
    return null;
  }

  const { attr, op, val } = match.groups;

  if (attr !== "href" && attr !== "src" && attr !== "data-href") {
    return null;
  }

  let matched = false;
  if (op === "=") {
    matched = url === val || (
      !val.startsWith("http:") && !val.startsWith("https:") && !val.startsWith("//") && url.endsWith(val)
    );
  } else if (op === "*=") {
    matched = url.includes(val);
  } else if (op === "^=") {
    matched = url.startsWith(val);
  } else if (op === "$=") {
    matched = url.endsWith(val);
  } else if (op === "~=") {
    matched = url.split(/\s+/).includes(val);
  } else {
    matched = url.includes(val);
  }

  if (matched) {
    return {
      text: "",
      attributes: { [attr]: url },
      properties: { [attr]: url },
    };
  }
  return null;
}

export class FingerprintMatcher {
  store: FingerprintStore;

  constructor(store: FingerprintStore) {
    this.store = store;
  }

  match(evidenceData: Partial<CollectedEvidence>): TechMatch[] {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(evidenceData.headers || {})) {
      headers[k.toLowerCase()] = String(v);
    }

    const cookies: Record<string, string> = {};
    for (const [k, v] of Object.entries(evidenceData.cookies || {})) {
      cookies[k.toLowerCase()] = String(v);
    }

    const meta_tags: Record<string, string> = {};
    for (const [k, v] of Object.entries(evidenceData.meta_tags || {})) {
      meta_tags[k.toLowerCase()] = String(v);
    }

    const script_srcs = Array.isArray(evidenceData.script_srcs) ? evidenceData.script_srcs.map(String) : [];
    const link_hrefs = Array.isArray(evidenceData.link_hrefs) ? evidenceData.link_hrefs.map(String) : [];
    const network_requests = Array.isArray(evidenceData.network_requests)
      ? evidenceData.network_requests.map(req => typeof req === "string" ? req : req.url)
      : [];

    const html_val = (evidenceData as any).html || (evidenceData as any).raw_html || "";
    const rawHtml = String(html_val);

    const js_globals: Record<string, string> = {};
    for (const [k, v] of Object.entries(evidenceData.js_globals || {})) {
      js_globals[_normalize_js_key(k)] = String(v);
    }

    const manifest_url = evidenceData.manifest_url || null;

    const allScripts = [...script_srcs, ...link_hrefs, ...network_requests];

    const domData: Record<string, any[]> = {};
    for (const [k, v] of Object.entries(evidenceData.dom || {})) {
      if (Array.isArray(v)) {
        domData[k] = [...v];
      }
    }

    if (manifest_url) {
      const pwaSel = "link[rel='manifest']";
      if (!domData[pwaSel]) {
        domData[pwaSel] = [
          {
            text: "",
            attributes: { rel: "manifest", href: manifest_url },
            properties: { rel: "manifest", href: manifest_url },
          }
        ];
      }
    }

    const allDomSelectors = this.store.get_all_dom_selectors();
    for (const sel of allDomSelectors) {
      if (!domData[sel]) {
        const findings: any[] = [];
        const subSelectors = sel.split(",").map(s => s.trim());
        for (const subSel of subSelectors) {
          for (const url of network_requests) {
            const finding = _match_network_request_to_selector(url, subSel);
            if (finding) {
              findings.push(finding);
            }
          }
        }
        if (findings.length > 0) {
          domData[sel] = findings;
        }
      }
    }

    const matches: TechMatch[] = [];

    for (const fp of this.store.get_all()) {
      const matched_sources = new Set<string>();
      const evidences: Evidence[] = [];
      const versions: string[] = [];

      // 1. Match Headers
      for (const [headerKey, pattern] of Object.entries(fp.headers)) {
        const headerVal = headers[headerKey.toLowerCase()];
        if (headerVal !== undefined && headerVal !== null) {
          try {
            const rx = new RegExp(pattern, "i");
            const match = rx.exec(headerVal);
            if (match) {
              matched_sources.add("header");
              evidences.push({
                source: "header",
                key: headerKey,
                matched: headerVal,
                pattern: pattern,
              });
              if (match[1]) {
                versions.push(match[1]);
              }
            }
          } catch (e) {
            // Ignored, warning logged in server version
          }
        }
      }

      // 2. Match Cookies
      for (const [cookieKey, pattern] of Object.entries(fp.cookies)) {
        const cookieVal = cookies[cookieKey.toLowerCase()];
        if (cookieVal !== undefined && cookieVal !== null) {
          try {
            const rx = new RegExp(pattern, "i");
            const match = rx.exec(cookieVal);
            if (match) {
              matched_sources.add("cookie");
              evidences.push({
                source: "cookie",
                key: cookieKey,
                matched: cookieVal,
                pattern: pattern,
              });
              if (match[1]) {
                versions.push(match[1]);
              }
            }
          } catch (e) {
            // Ignored
          }
        }
      }

      // 3. Match Meta Tags
      for (const [metaKey, pattern] of Object.entries(fp.meta)) {
        const metaVal = meta_tags[metaKey.toLowerCase()];
        if (metaVal !== undefined && metaVal !== null) {
          try {
            const rx = new RegExp(pattern, "i");
            const match = rx.exec(metaVal);
            if (match) {
              matched_sources.add("meta");
              evidences.push({
                source: "meta",
                key: metaKey,
                matched: metaVal,
                pattern: pattern,
              });
              if (match[1]) {
                versions.push(match[1]);
              }
            }
          } catch (e) {
            // Ignored
          }
        }
      }

      // 4. Match Script Src / Link Hrefs
      for (const pattern of fp.scripts) {
        let matchedScript: string | null = null;
        let matchedVal = "";

        for (const script of allScripts) {
          if (script.includes(pattern)) {
            matchedScript = script;
            matchedVal = script;
            break;
          }
        }

        if (!matchedScript) {
          try {
            const rx = new RegExp(pattern, "i");
            for (const script of allScripts) {
              const match = rx.exec(script);
              if (match) {
                matchedScript = script;
                matchedVal = script;
                if (match[1]) {
                  versions.push(match[1]);
                }
                break;
              }
            }
          } catch (e) {
            // Ignored
          }
        }

        if (matchedScript) {
          matched_sources.add("script");
          evidences.push({
            source: "script",
            key: "script_src",
            matched: matchedVal,
            pattern: pattern,
          });
        }
      }

      // 5. Match HTML
      for (const pattern of fp.html) {
        try {
          const rx = new RegExp(pattern, "i");
          const match = rx.exec(rawHtml);
          if (match) {
            matched_sources.add("html");
            evidences.push({
              source: "html",
              key: "raw_html",
              matched: match[0].slice(0, 100) + "...",
              pattern: pattern,
            });
            if (match[1]) {
              versions.push(match[1]);
            }
          }
        } catch (e) {
          // Ignored
        }
      }

      // 6. Match JS Globals
      for (const [globalKey, pattern] of Object.entries(fp.js_globals)) {
        const normalizedRuleKey = _normalize_js_key(globalKey);
        if (normalizedRuleKey in js_globals) {
          const globalVal = js_globals[normalizedRuleKey];
          let matchedJs = false;

          if (pattern === ".") {
            matchedJs = true;
          } else {
            try {
              const rx = new RegExp(pattern, "i");
              const match = rx.exec(globalVal);
              if (match) {
                matchedJs = true;
                if (match[1]) {
                  versions.push(match[1]);
                }
              }
            } catch (e) {
              // Ignored
            }
          }

          if (matchedJs) {
            matched_sources.add("js_global");
            const truncatedVal = globalVal.length > 100 ? globalVal.slice(0, 100) + "..." : globalVal;
            evidences.push({
              source: "js_global",
              key: globalKey,
              matched: truncatedVal,
              pattern: pattern,
            });
          }
        }
      }

      // 7. Match DOM selectors
      if (fp.dom) {
        if (Array.isArray(fp.dom)) {
          for (const sel of fp.dom) {
            if (sel in domData) {
              matched_sources.add("dom");
              const matchedEl = domData[sel][0];
              let matchedText = `Found element: ${sel}`;
              if (matchedEl && matchedEl.text) {
                matchedText += ` (text: ${matchedEl.text})`;
              }
              evidences.push({
                source: "dom",
                key: "selector",
                matched: matchedText.slice(0, 100),
                pattern: sel,
              });
            }
          }
        } else if (typeof fp.dom === "object") {
          for (const [sel, subRule] of Object.entries(fp.dom)) {
            if (sel in domData) {
              const elements = domData[sel];
              const ruleDict = (subRule && typeof subRule === "object") ? subRule : {};
              if (!subRule || "exists" in ruleDict) {
                matched_sources.add("dom");
                evidences.push({
                  source: "dom",
                  key: sel,
                  matched: `Element exists: ${sel}`,
                  pattern: "",
                });
                continue;
              }

              let matchedAnyEl = false;
              for (const el of elements) {
                let matchedElCriteria = true;

                // Check text regex
                if ("text" in ruleDict) {
                  const pat = ruleDict.text;
                  if (typeof pat === "string") {
                    try {
                      const rx = new RegExp(pat, "i");
                      const match = rx.exec(String(el.text || ""));
                      if (!match) {
                        matchedElCriteria = false;
                      } else {
                        if (match[1]) {
                          versions.push(match[1]);
                        }
                      }
                    } catch (e) {
                      matchedElCriteria = false;
                    }
                  }
                }

                // Check attributes
                if (matchedElCriteria && "attributes" in ruleDict) {
                  const elAttrs = (el.attributes || {}) as Record<string, string>;
                  const attrsRule = ruleDict.attributes;
                  if (attrsRule && typeof attrsRule === "object") {
                    for (const [attrName, pat] of Object.entries(attrsRule)) {
                      const attrVal = elAttrs[attrName];
                      if (attrVal === undefined || attrVal === null) {
                        matchedElCriteria = false;
                        break;
                      }
                      if (typeof pat === "string") {
                        try {
                          const rx = new RegExp(pat, "i");
                          const match = rx.exec(String(attrVal));
                          if (!match) {
                            matchedElCriteria = false;
                            break;
                          } else {
                            if (match[1]) {
                              versions.push(match[1]);
                            }
                          }
                        } catch (e) {
                          matchedElCriteria = false;
                          break;
                        }
                      }
                    }
                  }
                }

                // Check properties
                if (matchedElCriteria && "properties" in ruleDict) {
                  const elProps = (el.properties || {}) as Record<string, string>;
                  const propsRule = ruleDict.properties;
                  if (propsRule && typeof propsRule === "object") {
                    for (const [propName, pat] of Object.entries(propsRule)) {
                      const propVal = elProps[propName];
                      if (propVal === undefined || propVal === null) {
                        matchedElCriteria = false;
                        break;
                      }
                      if (typeof pat === "string") {
                        try {
                          const rx = new RegExp(pat, "i");
                          const match = rx.exec(String(propVal));
                          if (!match) {
                            matchedElCriteria = false;
                            break;
                          } else {
                            if (match[1]) {
                              versions.push(match[1]);
                            }
                          }
                        } catch (e) {
                          matchedElCriteria = false;
                          break;
                        }
                      }
                    }
                  }
                }

                if (matchedElCriteria) {
                  matchedAnyEl = true;
                  const matchedDetails: string[] = [];
                  if ("text" in ruleDict) {
                    matchedDetails.push(`text: ${el.text}`);
                  }
                  if ("attributes" in ruleDict) {
                    const attrsRule = ruleDict.attributes;
                    const attrsDict: Record<string, any> = {};
                    if (attrsRule && typeof attrsRule === "object") {
                      for (const k of Object.keys(attrsRule)) {
                        attrsDict[k] = (el.attributes as any)?.[k];
                      }
                    }
                    matchedDetails.push(`attributes: ${JSON.stringify(attrsDict)}`);
                  }
                  const matchedStr = matchedDetails.length > 0
                    ? `Found: ${sel} (${matchedDetails.join(", ")})`
                    : `Found: ${sel}`;
                  evidences.push({
                    source: "dom",
                    key: sel,
                    matched: matchedStr.slice(0, 120),
                    pattern: JSON.stringify(subRule),
                  });
                  break;
                }
              }

              if (matchedAnyEl) {
                matched_sources.add("dom");
              }
            }
          }
        }
      }

      // Calculate final confidence and build match
      if (evidences.length > 0) {
        const numSources = matched_sources.size;
        let confidence = fp.confidence;

        // +0.1 per additional corroborating source type
        if (numSources > 1) {
          confidence += 0.1 * (numSources - 1);
        }

        // +0.1 if version capture group matched
        const version = versions[0] || null;
        if (version) {
          confidence += 0.1;
        }

        confidence = Math.min(confidence, 1.0);

        matches.push({
          name: fp.name,
          category: fp.category,
          version: version,
          confidence: Number(confidence.toFixed(2)),
          evidence: evidences,
        });
      }
    }

    // Resolve implies chains
    const resolved = this.store.resolve_implies(matches);

    // Sort matches by confidence descending
    resolved.sort((a, b) => b.confidence - a.confidence);

    return resolved;
  }
}
