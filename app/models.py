from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    score: int
    action: str
    threat_types: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    explanation: str = ""
    severity: str = "LOW"
    recommendations: list[str] = field(default_factory=list)
