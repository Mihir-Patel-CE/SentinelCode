import asyncio
from typing import List, Tuple, Optional
from sqlalchemy.orm import Session
from app.models.review import Review, Finding
from app.schemas.review import ReviewCreateRequest, FindingCreate
from app.services.analyzers.registry import registry
from app.services.scoring import ScoringEngine
from app.services.ai.factory import get_ai_provider
from app.core.config import settings
from app.core.logging import logger


class ReviewService:
    async def execute_review(
        self,
        db: Session,
        req: ReviewCreateRequest,
        user_id: Optional[int] = None,
        provider_override: Optional[str] = None
    ) -> Review:
        # Step 1: Language Detection or Validation
        raw_language = req.language.lower().strip()
        if raw_language == "auto" or not raw_language:
            resolved_language = registry.detect_language(req.code)
        else:
            # Explicit selection always takes precedence
            resolved_language = registry.canonical_language(raw_language)

        analyzer = registry.get(resolved_language)

        static_findings: List[FindingCreate] = []
        coverage_summary = ""
        status = "completed"

        if analyzer:
            analysis_result = analyzer.analyze(req.code)
            static_findings = analysis_result.findings
            status = analysis_result.status
            coverage_summary = analysis_result.coverage_summary
        else:
            status = "unsupported_language"
            coverage_summary = f"Unsupported analyzer: No deterministic static analyzer available for '{resolved_language}'."

        # Step 2: Advisory AI Analysis (if enabled)
        ai_findings: List[FindingCreate] = []
        summary = ""

        if status == "failed":
            summary = f"Analyzer unavailable: {analysis_result.error_message or 'Required compiler or static analysis toolchain is unavailable in the deployment environment.'}"
            coverage_summary = f"Analyzer unavailable: {analysis_result.coverage_summary or 'Toolchain unavailable.'}"
        elif status == "unsupported_language" and not req.enable_ai:
            summary = f"Unsupported analyzer: Deterministic static analysis is not available for '{resolved_language}'."
        elif req.enable_ai:
            ai_provider = get_ai_provider(provider_override)
            ai_timeout = min(float(settings.ANALYSIS_TIMEOUT_SECONDS), 15.0)
            try:
                ai_findings, summary = await asyncio.wait_for(
                    ai_provider.analyze(
                        code=req.code,
                        language=resolved_language,
                        static_findings=static_findings
                    ),
                    timeout=ai_timeout
                )
                # Label AI findings with medium confidence and mark advisory source
                for f in ai_findings:
                    f.confidence = "medium"
                    f.source = "ai"
            except Exception as e:
                logger.warning(f"Configured AI provider error or timeout ({type(e).__name__}), utilizing local heuristic fallback: {e}")
                from app.services.ai.heuristic_mock import HeuristicMockAIProvider
                fallback = HeuristicMockAIProvider()
                try:
                    ai_findings, summary = await asyncio.wait_for(
                        fallback.analyze(
                            code=req.code,
                            language=resolved_language,
                            static_findings=static_findings
                        ),
                        timeout=5.0
                    )
                    for f in ai_findings:
                        f.confidence = "medium"
                        f.source = "ai"
                except Exception as fallback_err:
                    logger.error(f"Fallback AI provider also failed: {fallback_err}")
                    summary = f"Deterministic static code analysis completed for {resolved_language.upper()} (Advisory AI reasoning unavailable)."
        else:
            summary = f"Deterministic static code analysis completed for {resolved_language.upper()} without external AI reasoning."

        # Step 3: Deduplicate findings (avoid duplicate rule + line reports)
        all_findings: List[FindingCreate] = []
        seen_keys = set()

        for f in static_findings + ai_findings:
            key = (f.rule_id or f.title, f.line_start)
            if key not in seen_keys:
                seen_keys.add(key)
                all_findings.append(f)

        # Step 4: Calculate Metrics
        quality_score, security_score, maintainability = ScoringEngine.calculate(
            findings=all_findings,
            code=req.code,
            status=status
        )

        # Step 5: Save Review to DB
        title = req.title
        if not title or title.strip() == "Untitled Review":
            title = f"{resolved_language.capitalize()} Source Audit"

        db_review = Review(
            user_id=user_id,
            title=title,
            language=resolved_language,
            code=req.code,
            quality_score=quality_score,
            security_score=security_score,
            maintainability_index=maintainability,
            summary=summary,
            status=status,
            coverage_summary=coverage_summary
        )
        db.add(db_review)
        db.flush()

        for finding in all_findings:
            db_finding = Finding(
                review_id=db_review.id,
                rule_id=finding.rule_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                category=finding.category,
                source=finding.source,
                line_start=finding.line_start,
                line_end=finding.line_end,
                column_start=finding.column_start,
                column_end=finding.column_end,
                evidence=finding.evidence,
                confidence=finding.confidence,
                suggested_fix=finding.suggested_fix,
                fix_diff=finding.fix_diff
            )
            db.add(db_finding)

        db.commit()
        db.refresh(db_review)
        return db_review


review_service = ReviewService()
