"""Enrich KEV CVEs with NVD JSON 2.0 API data (cached)."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import requests

from src.models.document import CitationMetadata, ThreatDocument

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"


def _load_cache(cache_path: Path) -> dict[str, dict[str, Any]]:
    if not cache_path.exists():
        return {}
    return json.loads(cache_path.read_text(encoding="utf-8"))


def _save_cache(cache_path: Path, cache: dict[str, dict[str, Any]]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _fetch_cve(cve_id: str, session: requests.Session, sleep_seconds: float) -> dict[str, Any] | None:
    response = session.get(NVD_API_URL, params={"cveId": cve_id}, timeout=30)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    time.sleep(sleep_seconds)
    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    return vulnerabilities[0].get("cve")


def _build_nvd_document(cve_id: str, cve_data: dict[str, Any]) -> ThreatDocument:
    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        "",
    )
    metrics = cve_data.get("metrics", {})
    cvss = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key, [])
        if items:
            cvss_data = items[0].get("cvssData", {})
            cvss = (
                f"{cvss_data.get('baseScore', 'N/A')} "
                f"({cvss_data.get('baseSeverity', 'UNKNOWN')})"
            )
            break

    weaknesses = cve_data.get("weaknesses", [])
    cwes: list[str] = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                cwes.append(desc.get("value", ""))

    title = f"{cve_id}: {description[:120].strip()}" if description else cve_id
    content = "\n".join(
        [
            f"CVE ID: {cve_id}",
            f"CVSS: {cvss or 'Not available'}",
            f"CWEs: {', '.join(cwes) if cwes else 'Not listed'}",
            "",
            f"Description: {description or 'No description available.'}",
        ]
    )

    return ThreatDocument(
        source_id=cve_id,
        source_type="nvd_cve",
        title=title,
        content=content,
        citation=CitationMetadata(
            source_id=cve_id,
            source_type="nvd_cve",
            title=title,
            url=NVD_CVE_URL.format(cve_id=cve_id),
            extra={"cvss": cvss, "cwes": cwes},
        ),
    )


def load_nvd_for_cve_ids(
    cve_ids: list[str],
    cache_path: Path,
    *,
    limit: int | None = None,
    sleep_seconds: float = 0.6,
) -> list[ThreatDocument]:
    """
    Load or fetch NVD records for a list of CVE IDs.

    Uses a local JSON cache to avoid repeat API calls. Respects NVD rate limits.
    """
    cache = _load_cache(cache_path)
    documents: list[ThreatDocument] = []
    to_fetch = [cid for cid in cve_ids if cid not in cache]
    if limit is not None:
        to_fetch = to_fetch[:limit]

    session = requests.Session()
    session.headers.update({"User-Agent": "Threat-Intel-Rag/1.0"})

    for cve_id in to_fetch:
        try:
            logger.info("Fetching NVD record for %s", cve_id)
            record = _fetch_cve(cve_id, session, sleep_seconds)
            if record:
                cache[cve_id] = record
        except requests.RequestException as exc:
            logger.warning("NVD fetch failed for %s: %s", cve_id, exc)

    _save_cache(cache_path, cache)

    for cve_id in cve_ids:
        record = cache.get(cve_id)
        if record:
            documents.append(_build_nvd_document(cve_id, record))

    logger.info("NVD loader: %d documents (%d cached)", len(documents), len(cache))
    return documents
