"""Detection-domain data structures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DetectionRule:
    """A persisted rule the detector evaluates against normalized events."""

    id: str
    name: str
    enabled: bool
    severity: int
    mitre_tactic: str | None
    mitre_technique: str | None
    condition: dict[str, Any]
    version: int

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "DetectionRule":
        return cls(
            id=row["id"],
            name=row["name"],
            enabled=row["enabled"],
            severity=row["severity"],
            mitre_tactic=row.get("mitre_tactic"),
            mitre_technique=row.get("mitre_technique"),
            condition=row["condition"],
            version=row["version"],
        )
