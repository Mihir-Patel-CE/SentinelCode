from fastapi import APIRouter
from typing import List
from app.schemas.review import LanguageCapability
from app.services.analyzers.registry import registry

router = APIRouter(prefix="/languages", tags=["Languages"])


@router.get("/", response_model=List[LanguageCapability])
def get_supported_languages():
    """Returns the matrix of supported languages, analyzer capabilities, and known limitations."""
    return registry.get_supported_languages()
