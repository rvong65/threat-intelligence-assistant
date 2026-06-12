"""Load MITRE ATT&CK groups and software with technique relationships."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from src.models.document import CitationMetadata, ThreatDocument

logger = logging.getLogger(__name__)

GROUP_ID_PATTERN = re.compile(r"^G\d{4}$")
SOFTWARE_ID_PATTERN = re.compile(r"^S\d{4}$")
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

GROUP_URL = "https://attack.mitre.org/groups/{group_id}"
SOFTWARE_URL = "https://attack.mitre.org/software/{software_id}"


def _extract_mitre_id(
    external_references: list[dict[str, Any]],
    pattern: re.Pattern[str],
) -> str | None:
    for ref in external_references:
        if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id")
            if external_id and pattern.match(external_id):
                return external_id
    return None


def _index_objects(objects: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {obj["id"]: obj for obj in objects if obj.get("id")}


def _technique_ids_for_source(
    source_stix_id: str,
    relationships: list[dict[str, Any]],
    technique_by_stix_id: dict[str, str],
) -> list[str]:
    techniques: list[str] = []
    for rel in relationships:
        if rel.get("revoked") or rel.get("x_mitre_deprecated"):
            continue
        if rel.get("relationship_type") != "uses":
            continue
        if rel.get("source_ref") != source_stix_id:
            continue
        technique_id = technique_by_stix_id.get(rel.get("target_ref", ""))
        if technique_id and technique_id not in techniques:
            techniques.append(technique_id)
    return sorted(techniques)


def load_mitre_groups_software(path: Path) -> list[ThreatDocument]:
    """Parse groups and software from enterprise-attack.json."""
    if not path.exists():
        raise FileNotFoundError(f"MITRE ATT&CK file not found: {path}")

    logger.info("Loading MITRE groups/software from %s", path)
    with path.open(encoding="utf-8") as handle:
        bundle = json.load(handle)

    objects: list[dict[str, Any]] = bundle.get("objects", [])
    by_id = _index_objects(objects)

    technique_by_stix_id: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        tech_id = _extract_mitre_id(obj.get("external_references", []), TECHNIQUE_ID_PATTERN)
        if tech_id:
            technique_by_stix_id[obj["id"]] = tech_id

    relationships = [obj for obj in objects if obj.get("type") == "relationship"]
    documents: list[ThreatDocument] = []

    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        obj_type = obj.get("type")
        if obj_type == "intrusion-set":
            source_id = _extract_mitre_id(obj.get("external_references", []), GROUP_ID_PATTERN)
            kind = "mitre_group"
            prefix = "MITRE ATT&CK Group"
        elif obj_type in {"malware", "tool"}:
            source_id = _extract_mitre_id(obj.get("external_references", []), SOFTWARE_ID_PATTERN)
            kind = "mitre_software"
            prefix = f"MITRE ATT&CK {obj_type.title()}"
        else:
            continue

        if not source_id:
            continue

        name = obj.get("name", "").strip()
        description = obj.get("description", "").strip()
        if not name:
            continue

        techniques = _technique_ids_for_source(obj["id"], relationships, technique_by_stix_id)
        aliases = obj.get("aliases", []) or obj.get("x_mitre_aliases", [])

        lines = [
            f"{prefix} {source_id}: {name}",
            f"Aliases: {', '.join(aliases) if aliases else 'None'}",
            f"Associated techniques: {', '.join(techniques) if techniques else 'None'}",
            "",
            description or "(No description provided.)",
        ]
        content = "\n".join(lines)
        title = f"{source_id}: {name}"

        if kind == "mitre_group":
            url = GROUP_URL.format(group_id=source_id)
        else:
            url = SOFTWARE_URL.format(software_id=source_id)

        documents.append(
            ThreatDocument(
                source_id=source_id,
                source_type=kind,  # type: ignore[arg-type]
                title=title,
                content=content,
                citation=CitationMetadata(
                    source_id=source_id,
                    source_type=kind,  # type: ignore[arg-type]
                    title=title,
                    url=url,
                    extra={
                        "object_type": obj_type,
                        "aliases": aliases,
                        "techniques": techniques,
                    },
                ),
            )
        )

    logger.info("MITRE groups/software loader: %d documents", len(documents))
    return documents
