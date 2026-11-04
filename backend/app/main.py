import uvicorn
from fastapi import FastAPI

from app.core.config import settings
from app.core.logging_config import setup_logging
from app.routers.v1 import api_router
from app.settings.app_lifespan import lifespan
from app.settings.cors import setup_app_cors

setup_logging()
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)
setup_app_cors(app)
app.include_router(api_router)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"message": f"{settings.APP_NAME} is running"}


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True,
    )
