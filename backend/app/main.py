import time
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import engine, Base
from app.core.logging import logger
from app.api.v1.api import api_router

# Initialize database tables on startup (creates tables if not existing)
Base.metadata.create_all(bind=engine)

# Pre-seed default demo account idempotently
try:
    from app.core.database import SessionLocal
    from app.api.v1.auth import ensure_demo_user
    with SessionLocal() as db:
        ensure_demo_user(db)
except Exception as e:
    logger.warning(f"Could not pre-seed demo account on startup: {e}")

# Toolchain diagnostic check on startup
try:
    from app.services.analyzers.sandbox import CompilerSandbox
    _c_diag = CompilerSandbox.get_toolchain_diagnostics("clang")
    _cpp_diag = CompilerSandbox.get_toolchain_diagnostics("clang++")
    if _c_diag["available"]:
        logger.info(f"C Toolchain Diagnostic: clang={_c_diag['path']} ({_c_diag['version']})")
    else:
        logger.warning(f"C Toolchain Diagnostic: clang is NOT available in system PATH. (Error: {_c_diag['error']})")

    if _cpp_diag["available"]:
        logger.info(f"C++ Toolchain Diagnostic: clang++={_cpp_diag['path']} ({_cpp_diag['version']})")
    else:
        logger.warning(f"C++ Toolchain Diagnostic: clang++ is NOT available in system PATH. (Error: {_cpp_diag['error']})")
except Exception as _e:
    logger.warning(f"Could not perform startup compiler diagnostic check: {_e}")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Production-grade AI Code Review & Bug Detection Platform providing static analysis, security checks, and AI remediation.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_process_time_and_logging(request: Request, call_next):
    start_time = time.time()
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = f"{process_time:.4f}s"
        return response
    except Exception as exc:
        logger.exception(f"Unhandled exception during request: {request.method} {request.url.path}")
        # Never expose internal traceback or server paths to clients
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred. Our engineering team has been notified."}
        )


# Global exception handlers
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Exception on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred processing your request."}
    )


# Mount API V1
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    return {
        "message": "Welcome to SentinelCode AI Code Review API",
        "documentation": "/docs",
        "health": f"{settings.API_V1_STR}/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
