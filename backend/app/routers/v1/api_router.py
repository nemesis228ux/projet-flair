from fastapi import APIRouter

from app.routers.v1.analysis_router import router as analysis_router
from app.routers.v1.health_router import router as health_router

router = APIRouter(prefix="/api/v1", tags=["api"])
router.include_router(health_router)
router.include_router(analysis_router)
