from typing import List, Tuple, Optional
from app.schemas.review import FindingCreate


class ScoringEngine:
    """
    Deterministic scoring engine calculating Security Score, Code Quality Score,
    and Maintainability Index with calibrated penalties.
    """

    SEVERITY_QUALITY_PENALTIES = {
        "critical": 30,
        "high": 18,
        "medium": 10,
        "low": 4,
        "info": 0
    }

    SEVERITY_SECURITY_PENALTIES = {
        "critical": 40,
        "high": 25,
        "medium": 12,
        "low": 4,
        "info": 0
    }

    @classmethod
    def calculate(
        cls,
        findings: List[FindingCreate],
        code: str,
        status: str
    ) -> Tuple[Optional[int], Optional[int], Optional[int]]:
        """
        Calculates (quality_score, security_score, maintainability_index).
        Returns None for scores if analysis failed, input was invalid, or language is unsupported.
        """
        if status in ("failed", "unsupported_language", "invalid_input"):
            return None, None, None

        lines = [line.strip() for line in code.splitlines() if line.strip()]
        loc = max(1, len(lines))

        # Base clean score starts at 100, but has realistic calibrations
        quality = 100
        security = 100

        has_syntax_errors = any(f.category == "syntax" for f in findings)
        if has_syntax_errors:
            quality -= 40

        for finding in findings:
            q_pen = cls.SEVERITY_QUALITY_PENALTIES.get(finding.severity, 5)
            quality -= q_pen

            if finding.category == "security":
                s_pen = cls.SEVERITY_SECURITY_PENALTIES.get(finding.severity, 10)
                security -= s_pen

        # Clamp between 0 and 100
        quality = max(0, min(100, quality))
        security = max(0, min(100, security))

        # Analysis completed with limitations (syntax/parse constraints) must never award a perfect score
        if status == "completed_with_limitations":
            quality = min(quality, 85)

        # Maintainability Index: penalizes defect density and high code volume
        defect_density = len(findings) / loc
        base_maintainability = 95 - int(defect_density * 130)
        maintainability = max(10, min(95, base_maintainability))

        return quality, security, maintainability
