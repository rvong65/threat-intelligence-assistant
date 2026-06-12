"""Load CISA Known Exploited Vulnerabilities (KEV) catalog from CSV."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from src.models.document import CitationMetadata, ThreatDocument

logger = logging.getLogger(__name__)

NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
CISA_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _build_kev_content(row: dict[str, str]) -> str:
    """Flatten KEV row fields into embeddable text."""
    lines = [
        f"CVE ID: {row.get('cveID', '').strip()}",
        f"Vendor / Project: {row.get('vendorProject', '').strip()}",
        f"Product: {row.get('product', '').strip()}",
        f"Vulnerability: {row.get('vulnerabilityName', '').strip()}",
        f"Date added to KEV: {row.get('dateAdded', '').strip()}",
        f"Remediation due date: {row.get('dueDate', '').strip()}",
        f"Known ransomware campaign use: {row.get('knownRansomwareCampaignUse', '').strip()}",
        f"CWEs: {row.get('cwes', '').strip()}",
        "",
        f"Description: {row.get('shortDescription', '').strip()}",
        "",
        f"Required action: {row.get('requiredAction', '').strip()}",
    ]
    notes = row.get("notes", "").strip()
    if notes:
        lines.extend(["", f"Notes: {notes}"])
    return "\n".join(lines)


def load_cisa_kev(path: Path) -> list[ThreatDocument]:
    """Parse KEV CSV and return one ThreatDocument per CVE entry."""
    if not path.exists():
        raise FileNotFoundError(f"CISA KEV file not found: {path}")

    logger.info("Loading CISA KEV from %s", path)
    documents: list[ThreatDocument] = []
    skipped = 0

    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            cve_id = (row.get("cveID") or "").strip()
            if not cve_id or not cve_id.startswith("CVE-"):
                skipped += 1
                continue

            vendor = (row.get("vendorProject") or "").strip()
            product = (row.get("product") or "").strip()
            vuln_name = (row.get("vulnerabilityName") or cve_id).strip()
            title = f"{cve_id}: {vuln_name}"

            citation = CitationMetadata(
                source_id=cve_id,
                source_type="cisa_kev",
                title=title,
                url=NVD_URL.format(cve_id=cve_id),
                vendor=vendor or None,
                product=product or None,
                date_added=(row.get("dateAdded") or "").strip() or None,
                extra={
                    "due_date": (row.get("dueDate") or "").strip(),
                    "required_action": (row.get("requiredAction") or "").strip(),
                    "ransomware_use": (row.get("knownRansomwareCampaignUse") or "").strip(),
                    "cwes": (row.get("cwes") or "").strip(),
                    "catalog_url": CISA_KEV_URL,
                },
            )

            documents.append(
                ThreatDocument(
                    source_id=cve_id,
                    source_type="cisa_kev",
                    title=title,
                    content=_build_kev_content(row),
                    citation=citation,
                )
            )

    logger.info("KEV loader: %d entries loaded, %d skipped", len(documents), skipped)
    return documents
