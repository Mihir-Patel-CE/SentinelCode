from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.core.database import get_db
from app.core.config import settings
from app.models.user import User
from app.models.review import Review, Finding
from app.schemas.review import ReviewCreateRequest, ReviewResponse, ReviewListResponse, ReviewListItem
from app.services.review_service import review_service
from app.api.deps import get_optional_current_user, get_current_user

router = APIRouter(prefix="/reviews", tags=["Code Reviews"])


@router.post("/analyze", response_model=ReviewResponse, status_code=status.HTTP_201_CREATED)
async def analyze_code(
    req: ReviewCreateRequest,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    """
    Submits source code for multi-layer static & AI inspection.
    Works for authenticated users and anonymous guest/demo sessions.
    """
    if len(req.code.encode("utf-8")) > settings.MAX_CODE_LENGTH_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Code snippet exceeds maximum permitted size of {settings.MAX_CODE_LENGTH_BYTES} bytes."
        )

    user_id = current_user.id if current_user else None
    
    # Read user preferences if authenticated
    provider_override = None
    if current_user and current_user.settings:
        if not current_user.settings.enable_ai_analysis:
            req.enable_ai = False
        provider_override = current_user.settings.preferred_ai_provider

    review = await review_service.execute_review(
        db=db,
        req=req,
        user_id=user_id,
        provider_override=provider_override
    )
    return review


@router.get("/", response_model=ReviewListResponse)
def list_reviews(
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    language: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    """Lists code reviews with pagination, language filtering, and search."""
    query = db.query(Review)

    if current_user:
        # Show user's reviews
        query = query.filter((Review.user_id == current_user.id) | (Review.user_id.is_(None)))
    else:
        # For guest, show global demo/recent unauthenticated reviews
        query = query.filter(Review.user_id.is_(None))

    if language:
        query = query.filter(Review.language == language.lower())

    if q:
        query = query.filter(Review.title.ilike(f"%{q}%"))

    total = query.count()
    offset = (page - 1) * size
    reviews = query.order_by(desc(Review.created_at)).offset(offset).limit(size).all()

    items = []
    for r in reviews:
        items.append(ReviewListItem(
            id=r.id,
            title=r.title,
            language=r.language,
            status=r.status,
            quality_score=r.quality_score,
            security_score=r.security_score,
            total_findings=len(r.findings),
            created_at=r.created_at
        ))

    pages = (total + size - 1) // size if total > 0 else 1

    return ReviewListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages
    )


@router.get("/{review_id}", response_model=ReviewResponse)
def get_review_details(
    review_id: int,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    """Fetches a specific review and all its findings."""
    review = db.query(Review).filter(Review.id == review_id).first()
    if not review:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found.")

    # Isolation check: if user_id is set and doesn't match current user
    if review.user_id and current_user and review.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this review.")

    return review


@router.delete("/{review_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_review(
    review_id: int,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    """Deletes a review record."""
    review = db.query(Review).filter(Review.id == review_id).first()
    if not review:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found.")

    if review.user_id and (not current_user or review.user_id != current_user.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot delete another user's review.")

    db.delete(review)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{review_id}/export")
def export_review_markdown(
    review_id: int,
    db: Session = Depends(get_db)
):
    """Exports the review results as formatted Markdown report."""
    review = db.query(Review).filter(Review.id == review_id).first()
    if not review:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found.")

    md = [
        f"# SentinelCode Security & Quality Audit Report",
        f"**Review Title**: {review.title}",
        f"**Language**: {review.language}",
        f"**Date**: {review.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Quality Score**: {review.quality_score}/100 | **Security Score**: {review.security_score}/100 | **Maintainability**: {review.maintainability_index}/100\n",
        f"## Executive Summary",
        f"{review.summary or 'Automated audit completed.'}\n",
        f"## Findings Breakdown ({len(review.findings)} total issues)\n"
    ]

    for f in review.findings:
        loc = f"Line {f.line_start}" if f.line_start else "General"
        md.append(f"### [{f.severity.upper()}] {f.title} ({f.rule_id or 'N/A'})")
        md.append(f"- **Category**: {f.category} | **Source**: {f.source.upper()} | **Location**: {loc}")
        md.append(f"- **Description**: {f.description}")
        if f.suggested_fix:
            md.append(f"- **Remediation**: {f.suggested_fix}")
        if f.fix_diff:
            md.append(f"```diff\n{f.fix_diff}\n```")
        md.append("")

    content = "\n".join(md)
    return Response(
        content=content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=review_{review.id}_report.md"}
    )
