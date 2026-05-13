"""Ars0n-style 3-round recon pipeline.

   PASSIVE → consolidate → httpx (round 1)
   ACTIVE  → consolidate → httpx (round 2)        [optional, requires brute-force tools]
   JS      → consolidate → httpx (round 3)
   ENRICH  → screenshots, port scan, nuclei
   ROI     → per-URL score
   TAKE    → takeover check
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from ...core.config import PATHS
from ...core.finding import Finding
from ...core.logging import info, ok, step, warn
from ...core.roi import calculate_from_dict
from ...core.scope import Scope
from ...core.store import (add_target, get_or_create_engagement, insert_finding,
                            store, upsert_asset, upsert_url_fact)
from . import crawl, http_probe, js_analysis, screenshots, subdomains, takeover


@dataclass
class ReconResult:
    target: str
    subdomains: list[str] = field(default_factory=list)
    url_facts: list[dict] = field(default_factory=list)
    js_findings: dict[str, dict] = field(default_factory=dict)
    takeover_findings: list[Finding] = field(default_factory=list)
    paused: bool = False
    pause_reason: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "subdomains": len(self.subdomains),
            "live": len(self.url_facts),
            "js_files": len(self.js_findings),
            "takeover_findings": len(self.takeover_findings),
            "paused": self.paused, "pause_reason": self.pause_reason,
        }


async def run(target: str, *, scope: Scope,
              mode: str = "passive",
              max_subdomains: int = 2500,
              max_live: int = 500,
              do_screenshots: bool = True,
              do_takeover: bool = True) -> ReconResult:
    """Run the recon pipeline.

    Modes:
    - ``osint``    OSINT-only: subfinder/amass-passive/crt.sh/assetfinder/gau/waybackurls.
                   **Never sends a request to the target** — every source is a third party
                   (CT logs, archives, passive DNS providers). Safe for any program that
                   allows OSINT reconnaissance.
    - ``passive``  OSINT sources + httpx HTTP probe + crawl + screenshots + takeover check.
                   First mode that actually touches the target.
    - ``active``   passive + DNS brute force (shuffledns + cewl wordlist). Requires
                   massdns + shuffledns installed. Currently a hook point — no-op without
                   those binaries.
    - ``all``      active + every enrichment step.
    """
    result = ReconResult(target=target)
    scope.check_host(target.lstrip("*."), action="recon.pipeline")

    with store() as conn:
        eng_id = get_or_create_engagement(conn, scope.engagement.name or "default",
                                          type_=scope.engagement.type or "lab",
                                          authorized_by=scope.engagement.authorized_by,
                                          start=scope.engagement.start,
                                          end=scope.engagement.end,
                                          scope_path=str(scope.source_path or ""))
        tgt_id = add_target(conn, eng_id, target, kind="wildcard" if target.startswith("*.") else "domain")

    # -------- Round 1: passive --------
    step("recon: passive subdomain enumeration")
    per_tool = await subdomains.enumerate_passive(target, scope=scope)
    subs = subdomains.consolidate(per_tool, target)
    ok(f"  consolidated: {len(subs)} unique subdomains")
    if len(subs) > max_subdomains:
        result.paused = True
        result.pause_reason = f"subdomains {len(subs)} > max {max_subdomains}"
        warn(f"PAUSE: {result.pause_reason}")
        return result

    if mode == "osint":
        # OSINT-only: persist the subdomains as assets and stop here.
        with store() as conn:
            for sd in subs:
                upsert_asset(conn, eng_id, "fqdn", sd, parent_id=None)
        result.subdomains = subs
        ok(f"  OSINT-only mode: {len(subs)} subdomains persisted, no probing performed")
        return result

    step("recon: httpx round 1 (probing passive set)")
    facts = await http_probe.probe(subs, scope=scope)
    ok(f"  {len(facts)} live web hosts")
    if len(facts) > max_live:
        result.paused = True
        result.pause_reason = f"live web {len(facts)} > max {max_live}"
        warn(f"PAUSE: {result.pause_reason}")
        return result

    # -------- Round 2: active (placeholder for shuffledns brute) ------------
    if mode in ("active", "all"):
        step("recon: active brute-force (placeholder — install shuffledns+massdns to enable)")
        # Hook point: call recon.dns.brute_force(target, scope=scope) then re-probe.
        # Intentionally left as a no-op when those tools are missing — see recon/dns.py.

    # -------- Round 3: JS / crawler ------------
    step("recon: crawl + JS discovery")
    live_urls = [f.get("url") for f in facts if f.get("url")]
    crawled = await crawl.crawl_many(live_urls[:20], scope=scope, depth=2)
    js_urls = set()
    for url_map in crawled.values():
        for tool_urls in url_map.values():
            for u in tool_urls:
                if ".js" in u and u.endswith(".js"):
                    js_urls.add(u)
    if js_urls:
        result.js_findings = await js_analysis.analyse(list(js_urls)[:30], scope=scope)
        for js_url, payload in result.js_findings.items():
            for label, snippet in payload.get("secrets", []):
                fnd = Finding(
                    code="INFO-LEAK-JS",
                    title=f"Secret-shaped string in JS: {label}",
                    severity="medium" if "AWS" in label or "private key" in label else "low",
                    confidence="low",  # heuristic
                    asset=js_url,
                    description=f"Pattern matching {label!r} fired against {js_url}. Manual review required.",
                    evidence={"snippet": snippet, "regex": label},
                    wstg_id="WSTG-INFO-05",
                    cwe="CWE-200",
                    bbb_chapter="ch05_recon",
                    references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"],
                )
                with store() as conn:
                    insert_finding(conn, eng_id, fnd)

    # -------- Enrich: persist URL facts + ROI score ------------
    step("recon: persist URL facts and ROI score")
    url_facts_out: list[dict] = []
    with store() as conn:
        for fact in facts:
            url = fact.get("url") or ""
            host = fact.get("host") or fact.get("input") or url
            asset_id = upsert_asset(conn, eng_id, "fqdn", host)
            url_asset_id = upsert_asset(conn, eng_id, "url", url, parent_id=asset_id)
            ssl_flags = fact.get("ssl") or {}
            body = ""  # body is not in default httpx output; we skip without `-include-response`
            breakdown = calculate_from_dict({"status_code": fact.get("status_code"),
                                              "body": body,
                                              "headers": fact.get("response_headers") or {},
                                              "path": url,
                                              "ssl_flags": ssl_flags})
            upsert_url_fact(conn, url_asset_id,
                            status_code=fact.get("status_code"),
                            title=fact.get("title"),
                            server=fact.get("webserver"),
                            technologies=fact.get("tech") or fact.get("technologies") or [],
                            content_length=fact.get("content_length") or 0,
                            ssl_flags_json=ssl_flags,
                            response_headers_json=fact.get("response_headers") or {},
                            roi_score=breakdown.score,
                            roi_breakdown_json={"notes": breakdown.notes, "score": breakdown.score})
            fact["_roi_score"] = breakdown.score
            fact["_roi_notes"] = breakdown.notes
            url_facts_out.append(fact)
    result.url_facts = url_facts_out
    result.subdomains = subs

    # -------- Screenshots ------------
    if do_screenshots and live_urls:
        try:
            step("recon: screenshots")
            await screenshots.screenshot(live_urls, scope=scope, out_dir=PATHS.data / "screenshots")
        except Exception as e:  # pragma: no cover
            warn(f"screenshots failed: {e}")

    # -------- Takeover ------------
    if do_takeover and subs:
        step("recon: takeover check")
        try:
            tf = await takeover.check(subs, scope=scope)
            result.takeover_findings = tf
            if tf:
                with store() as conn:
                    for f in tf:
                        insert_finding(conn, eng_id, f)
        except Exception as e:  # pragma: no cover
            warn(f"takeover scan failed: {e}")

    return result
