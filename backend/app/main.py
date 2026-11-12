import uvicorn
import secrets
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi.errors import RateLimitExceeded

from app.common.business_error import AppError, AppErrorType
from app.common.constants.messages import Messages
from app.core.config import settings
from app.core.logging_config import setup_logging
from app.core.rate_limit import limiter
from app.routers.v1.api_router import router as public_api_router
from app.settings.app_lifespan import lifespan
from app.settings.cors import setup_app_cors

setup_logging()
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)
app.state.limiter = limiter
setup_app_cors(app)
app.include_router(public_api_router)
Instrumentator(
    excluded_handlers=["/metrics"],
).instrument(app).expose(app, include_in_schema=False)


@app.middleware("http")
async def protect_metrics(request: Request, call_next):
    if request.url.path == "/metrics":
        authorization = request.headers.get("authorization", "")
        expected = f"Bearer {settings.METRICS_TOKEN}"
        if not secrets.compare_digest(authorization, expected):
            return JSONResponse(
                status_code=401,
                content={"detail": "Metrics authentication required"},
            )
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(
    _request: Request, _exception: RequestValidationError
) -> JSONResponse:
    error = AppError(
        error_type=AppErrorType.VALIDATION_ERROR,
        error_message=Messages.VALIDATION_ERROR,
    )
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "result": None,
            "error": error.model_dump(mode="json"),
        },
    )


@app.exception_handler(RateLimitExceeded)
async def handle_rate_limit_exceeded(
    _request: Request, _exception: RateLimitExceeded
) -> JSONResponse:
    error = AppError(
        error_type=AppErrorType.BAD_REQUEST,
        error_message=Messages.RATE_LIMIT_EXCEEDED,
    )
    return JSONResponse(
        status_code=429,
        content={
            "success": False,
            "result": None,
            "error": error.model_dump(mode="json"),
        },
    )


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
