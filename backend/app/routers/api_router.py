from fastapi import APIRouter

from app.routers.analysis_router import router as analysis_router
from app.routers.health_router import router as health_router

router = APIRouter(prefix="/api")
router.include_router(health_router)
router.include_router(analysis_router)
