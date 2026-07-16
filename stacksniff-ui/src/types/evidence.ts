// src/types/evidence.ts — TypeScript type definitions matching python models

export interface CollectedEvidence {
  headers: Record<string, string>;
  cookies: Record<string, string>;
  html: string;
  meta_tags: Record<string, string>;
  script_srcs: string[];
  link_hrefs: string[];
  js_globals: Record<string, string>;
  dom: Record<string, Array<Record<string, unknown>>>;
  network_requests: NetworkRequest[];
  probed_paths: NetworkRequest[];
  static_endpoints: string[];
  spec_endpoints: string[];
  framework_endpoints: FrameworkEndpoint[];
  runtime_dependencies: Array<Record<string, unknown>>;
  discovered_subdomains: Array<Record<string, unknown>>;
  spec_title?: string | null;
  spec_version?: string | null;
  spec_methods?: Record<string, string[]>;
  manifest_url?: string | null;
}

export interface NetworkRequest {
  url: string;
  method: string;
  resource_type: string;
  response_status?: number;
  response_headers?: Record<string, string>;
}

export interface FrameworkEndpoint {
  url: string;
  status_code: number;
  status_label: string; // e.g. "exposed", "forbidden", "redirect"
  content_type: string | null;
  confidence: number;
  source_wordlist: string; // e.g. "wordpress.txt"
  top_level_keys?: string[]; // keys present in JSON response body
  redirect_location?: string; // present for 3xx responses
  implied_techs: string[]; // techs implied by the wordlist
}

export interface TechMatch {
  name: string;
  category: string;
  version: string | null;
  confidence: number; // 0.0–1.0
  evidence: Evidence[];
}

export interface Evidence {
  source: string; // "header" | "cookie" | "meta" | "script" | "html" | "js_global" | "dom"
  key: string;
  matched: string;
  pattern: string;
}
