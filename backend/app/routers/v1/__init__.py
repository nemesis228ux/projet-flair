from fastapi import APIRouter

from app.core.config import settings
from app.routers.v1.base_router import router as base_router
from app.routers.v1.example_router import router as example_router

api_router = APIRouter(prefix=settings.API_PREFIX)
api_router.include_router(base_router)
api_router.include_router(example_router)
