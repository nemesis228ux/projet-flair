# Backend conventions

## Result wrappers by layer

- `GenericAppResult[D, E]` in `app/common/app_result.py` is the shared success/failure container. It exposes `data` on success and `error` on failure.
- Repositories use `CrudResult[D, E]` from `app/repositories/__init__.py`. Repository success and failure factories also carry an HTTP status code. A repository failure can be converted to `ServiceResult` with `to_service_error()`.
- Services use `ServiceResult[D, E]` from `app/services/__init__.py`. It adds a service name and HTTP status code, and converts its result into `ApiBaseResponse[D, E]` for the HTTP layer.
- Routers return `ApiBaseResponse[D, E]`, normally by passing FastAPI's `Response` to the service result conversion method. `AppError` is the standard error payload; `GlobalStringResponse` is a specialized response model for `StringMessage`.
- Integrations do not yet exist. Project instructions require external clients to follow the repository result-wrapper pattern; there is no implementation to use as an example yet.

## Errors

`AppError` in `app/common/business_error.py` is a Pydantic error payload with an `AppErrorType` and user-facing message; it is not an exception class. `Messages` in `app/common/constants/messages.py` contains standard error messages. `RepositoriesUtils.handle_unexpected_error()` logs an unexpected repository exception and returns a generic `CrudResult` failure. Request-validation failures are handled centrally in `app/main.py` and returned as the standard wrapper with a generic message, without validation details or submitted values.

The example router constructs a service success result directly. The example uses the service result's `to_HTTP_api_base_response()` conversion method.

## Settings and application setup

`app/core/config.py` creates the shared `settings` object from Pydantic Settings, loading `.env` and environment variables with case-sensitive names. All settings are required; local and deployment values must be supplied through environment variables or `.env`. `backend/.env.example` lists the configuration keys, while `backend/.env` contains local values and must not be committed. Deployment configuration includes `ENV`, `ALLOWED_ORIGINS`, `GEMINI_API_KEY`, and `GEMINI_MODEL`. `APP_ENV` and `CORS_ORIGINS` remain accepted as legacy aliases.

`app/main.py` uses settings to configure the FastAPI title, version, and lifespan, sets up logging and CORS, and includes both the existing versioned API router and the requested `/api` endpoints. CORS origins are parsed from the comma-separated `ALLOWED_ORIGINS` setting.

## URL analysis

- `UrlAnalysisService` is a FastAPI-injected service class. Its `analyze(url)` method uses the pure `inspect_url()` helper in `app/common/utils/url_analysis.py`, then maps the signals into the shared `AnalysisResult` and `ServiceResult` types.
- The V1 URL analyzer only inspects the submitted string. It does not resolve DNS, fetch the URL, or call external APIs. It reports stable reason codes for malformed URLs, unsupported schemes, missing HTTPS, URL user-info, IP hosts, punycode, brand-like typosquatting, selected suspicious TLDs, known URL shorteners, many subdomains, suspicious keywords, and long URLs.
- Risk points are added and capped at 100. Scores below 20 are `safe`, 20–59 are `suspicious`, and 60 or above are `dangerous`. The current result source is `heuristics`.
- The request schema limits URL input to 1–2048 characters. Domain-age checks and external reputation services are not implemented yet.

## Request flow

The intended layered flow is router → service → repository: a router invokes a service, the service invokes a repository, repository outcomes are expressed as `CrudResult`, and the service returns `ServiceResult`; the router converts the service result to the common `ApiBaseResponse` envelope and HTTP status. URL analysis now uses an injected service class and local heuristic utility; email analysis and password checking remain stubs until their implementation is requested. The existing message example also constructs a `ServiceResult` directly.
