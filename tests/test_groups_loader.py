"""Tests for MITRE groups/software loader."""

from __future__ import annotations

from pathlib import Path

from config.settings import get_settings
from src.loaders.mitre_groups_software import load_mitre_groups_software


def test_load_mitre_groups_software_from_corpus() -> None:
    settings = get_settings()
    path: Path = settings.mitre_path
    if not path.exists():
        return

    docs = load_mitre_groups_software(path)
    assert len(docs) > 0
    groups = [d for d in docs if d.source_type == "mitre_group"]
    software = [d for d in docs if d.source_type == "mitre_software"]
    assert len(groups) > 0
    assert len(software) > 0
    assert groups[0].source_id.startswith("G")
    assert software[0].source_id.startswith("S")
