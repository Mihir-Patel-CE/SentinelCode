from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.reviews import router as reviews_router
from app.api.v1.samples import router as samples_router
from app.api.v1.settings import router as settings_router
from app.api.v1.health import router as health_router
from app.api.v1.languages import router as languages_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(reviews_router)
api_router.include_router(samples_router)
api_router.include_router(settings_router)
api_router.include_router(languages_router)
