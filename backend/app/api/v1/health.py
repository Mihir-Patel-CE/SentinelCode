from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """Liveness probe indicating that the service process is up and responding."""
    from app.services.analyzers.sandbox import CompilerSandbox
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "toolchains": {
            "clang": CompilerSandbox.get_toolchain_diagnostics("clang"),
            "clang++": CompilerSandbox.get_toolchain_diagnostics("clang++"),
        }
    }


@router.get("/diagnostics")
def diagnostics_check(db: Session = Depends(get_db)):
    """
    Diagnostic probe reporting environment, database status, and LLVM/Clang compiler versions.
    """
    from app.services.analyzers.sandbox import CompilerSandbox
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "status": "ok",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": {"connected": db_ok},
        "toolchains": {
            "c": CompilerSandbox.get_toolchain_diagnostics("clang"),
            "cpp": CompilerSandbox.get_toolchain_diagnostics("clang++"),
        }
    }


@router.get("/ready")
def readiness_check(db: Session = Depends(get_db)):
    """Readiness probe verifying database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "ready",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connection error: {str(e)}"
        )
