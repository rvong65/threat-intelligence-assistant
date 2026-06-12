"""Load MITRE ATT&CK Enterprise techniques from STIX 2.1 bundle JSON."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from src.models.document import CitationMetadata, ThreatDocument

logger = logging.getLogger(__name__)

MITRE_TECHNIQUE_URL = "https://attack.mitre.org/techniques/{technique_id}"


def _extract_technique_id(external_references: list[dict[str, Any]]) -> str | None:
    for ref in external_references:
        if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id")
            if external_id and re.match(r"^T\d{4}(?:\.\d{3})?$", external_id):
                return external_id
    return None


def _extract_tactics(kill_chain_phases: list[dict[str, Any]] | None) -> list[str]:
    if not kill_chain_phases:
        return []
    return sorted(
        {
            phase.get("phase_name", "").replace("-", " ").title()
            for phase in kill_chain_phases
            if phase.get("phase_name")
        }
    )


def _build_technique_content(
    technique_id: str,
    name: str,
    description: str,
    tactics: list[str],
    platforms: list[str],
    is_subtechnique: bool,
    parent_id: str | None,
) -> str:
    """Assemble readable body text; chunking adds the context prefix."""
    lines = [
        f"Name: {name}",
        f"Type: {'Sub-technique' if is_subtechnique else 'Technique'}",
    ]
    if parent_id:
        lines.append(f"Parent technique: {parent_id}")
    if tactics:
        lines.append(f"Tactics: {', '.join(tactics)}")
    if platforms:
        lines.append(f"Platforms: {', '.join(platforms)}")
    lines.append("")
    lines.append(description.strip())
    return "\n".join(lines)


def load_mitre_attack(path: Path) -> list[ThreatDocument]:
    """
    Parse enterprise-attack.json and return one ThreatDocument per technique.

    Skips revoked or deprecated entries. Focuses on attack-pattern objects.
    """
    if not path.exists():
        raise FileNotFoundError(f"MITRE ATT&CK file not found: {path}")

    logger.info("Loading MITRE ATT&CK from %s", path)
    with path.open(encoding="utf-8") as handle:
        bundle = json.load(handle)

    objects: list[dict[str, Any]] = bundle.get("objects", [])
    documents: list[ThreatDocument] = []
    skipped = 0

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            skipped += 1
            continue

        technique_id = _extract_technique_id(obj.get("external_references", []))
        if not technique_id:
            skipped += 1
            continue

        name = obj.get("name", "").strip()
        description = obj.get("description", "").strip()
        if not name or not description:
            skipped += 1
            continue

        tactics = _extract_tactics(obj.get("kill_chain_phases"))
        platforms = sorted(obj.get("x_mitre_platforms", []))
        is_subtechnique = bool(obj.get("x_mitre_is_subtechnique", False))

        # Parent technique ID derived from sub-technique ID (e.g. T1059.001 -> T1059)
        parent_id = None
        if is_subtechnique and "." in technique_id:
            parent_id = technique_id.split(".")[0]

        url = MITRE_TECHNIQUE_URL.format(
            technique_id=technique_id.replace(".", "/")
        )

        citation = CitationMetadata(
            source_id=technique_id,
            source_type="mitre_attack",
            title=f"{technique_id}: {name}",
            url=url,
            tactics=tactics,
            platforms=platforms,
            extra={
                "is_subtechnique": is_subtechnique,
                "parent_id": parent_id,
                "modified": obj.get("modified"),
            },
        )

        content = _build_technique_content(
            technique_id=technique_id,
            name=name,
            description=description,
            tactics=tactics,
            platforms=platforms,
            is_subtechnique=is_subtechnique,
            parent_id=parent_id,
        )

        documents.append(
            ThreatDocument(
                source_id=technique_id,
                source_type="mitre_attack",
                title=citation.title,
                content=content,
                citation=citation,
            )
        )

    logger.info(
        "MITRE loader: %d techniques loaded, %d skipped",
        len(documents),
        skipped,
    )
    return documents
