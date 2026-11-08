# Backend conventions

## Result wrappers by layer

- `GenericAppResult[D, E]` in `app/common/app_result.py` is the shared success/failure container. It exposes `data` on success and `error` on failure.
- Repositories use `CrudResult[D, E]` from `app/repositories/__init__.py`. Repository success and failure factories also carry an HTTP status code. A repository failure can be converted to `ServiceResult` with `to_service_error()`.
- Services use `ServiceResult[D, E]` from `app/services/__init__.py`. It adds a service name and HTTP status code, and converts its result into `ApiBaseResponse[D, E]` for the HTTP layer.
- Routers return `ApiBaseResponse[D, E]`, normally by passing FastAPI's `Response` to the service result conversion method. `AppError` is the standard error payload; `GlobalStringResponse` is a specialized response model for `StringMessage`.
- External integrations follow the shared `GenericAppResult` wrapper pattern. Current examples are the HIBP client in `app/integrations/hibp.py` and Gemini client in `app/integrations/gemini.py`.

## Errors

`AppError` in `app/common/business_error.py` is a Pydantic error payload with an `AppErrorType` and user-facing message; it is not an exception class. `Messages` in `app/common/constants/messages.py` contains standard error messages. `RepositoriesUtils.handle_unexpected_error()` logs an unexpected repository exception and returns a generic `CrudResult` failure. Request-validation failures are handled centrally in `app/main.py` and returned as the standard wrapper with a generic message, without validation details or submitted values.

The example router constructs a service success result directly. The example uses the service result's `to_HTTP_api_base_response()` conversion method.

## Settings and application setup

`app/core/config.py` creates the shared `settings` object from Pydantic Settings, loading `.env` and environment variables with case-sensitive names. All settings are required; local and deployment values must be supplied through environment variables or `.env`. `backend/.env.example` lists the configuration keys, while `backend/.env` contains local values and must not be committed. Deployment configuration includes `ENV`, `ALLOWED_ORIGINS`, `GEMINI_API_KEY`, and `GEMINI_MODEL`. `APP_ENV` and `CORS_ORIGINS` remain accepted as legacy aliases.

`app/main.py` uses settings to configure the FastAPI title, version, and lifespan, sets up logging and CORS, and includes the versioned API router. CORS origins are parsed from the comma-separated `ALLOWED_ORIGINS` setting.

## URL analysis

- `UrlAnalysisService` is a FastAPI-injected service class. Its `analyze(url)` method uses the pure `inspect_url()` helper in `app/common/utils/url_analysis.py`, then maps the signals into the shared `AnalysisResult` and `ServiceResult` types.
- The V1 URL analyzer only inspects the submitted string. It does not resolve DNS, fetch the URL, or call external APIs. It reports stable reason codes for malformed URLs, unsupported schemes, missing HTTPS, URL user-info, IP hosts, punycode, brand-like typosquatting, selected suspicious TLDs, known URL shorteners, many subdomains, suspicious keywords, and long URLs.
- Risk points are added and capped at 100. Scores below 20 are `safe`, 20–59 are `suspicious`, and 60 or above are `dangerous`. The current result source is `heuristics`.
- The request schema limits URL input to 1–2048 characters. Domain-age checks and external reputation services are not implemented yet.

## Password analysis

- `PasswordAnalysisService` in `app/services/password_analysis_service.py` computes strength locally with `zxcvbn`, then calls the HIBP integration for a breach count and returns the shared `ServiceResult[AnalysisResult, AppError]`.
- The HIBP integration hashes the submitted password with SHA-1 locally and sends only the first five hexadecimal characters to the Pwned Passwords range API, with `Add-Padding: true`. It compares returned suffixes locally and never logs or persists the submitted password.
- This endpoint is rate-limited to five requests per minute per client IP. Passwords are not cached. Input is limited to 1–128 characters, and validation responses are handled by the global handler without echoing submitted values.
- The risk score is the inverse of `zxcvbn`'s 0–4 strength score, scaled to 0–100; a password found in HIBP receives score 100. Stable reason codes include `PASSWORD_TOO_SHORT`, `PASSWORD_WEAK`, and `BREACHED`; the `breach_count` field reports the HIBP count.
- If HIBP is unavailable or returns an invalid response, the API returns a generic 503 error rather than a success-shaped fallback.

## Email analysis

- `EmailAnalysisService` combines local checks with a provider-neutral `LLMClient`; the Gemini HTTP implementation lives separately in `app/integrations/gemini.py`.
- Local checks look for urgency, credential/money/gift-card requests, visible-link versus destination mismatches, `Reply-To` versus `From`, and SPF/DKIM/DMARC failures when those headers are present. Extracted links are inspected only as strings by `inspect_url()`; Flair never fetches the submitted links.
- Gemini output is requested as JSON and validated by the internal `EmailLLMAnalysis` Pydantic schema before the service combines it with local signals. The model must provide stable, allow-listed reason codes and severities as well as tactics and explanation, so model-detected risks are represented in `reasons` rather than only in prose. Its system instruction treats the email as untrusted content and explicitly forbids following instructions found inside it.
- The email body is limited to 50,000 characters, is not logged or persisted, and is sent only to the configured Gemini provider for the requested analysis. The endpoint is rate-limited to five requests per minute per client IP. No cache is used.
- Heuristic and model scores are combined using the greater risk score; final verdict thresholds remain `<20` safe, `20–59` suspicious, and `>=60` dangerous. A Gemini/network/validation failure returns a generic 503 response instead of a partial success.

## Request flow

The intended layered flow is router → service → repository: a router invokes a service, the service invokes a repository, repository outcomes are expressed as `CrudResult`, and the service returns `ServiceResult`; the router converts the service result to the common `ApiBaseResponse` envelope and HTTP status. Each analysis feature has a separate service module (`url_analysis_service.py`, `password_analysis_service.py`, and `email_analysis_service.py`), while the endpoint definitions remain in the shared analysis router. URL analysis uses an injected service class and local heuristic utility. Password analysis uses an injected service and a wrapped HIBP integration; no database repository is needed because the feature does not persist data. Email analysis uses local heuristics plus a wrapped Gemini integration. API tests are grouped by feature in `test_url_api.py`, `test_password_api.py`, and `test_email_api.py`; external protocol tests are in `test_hibp_integration.py` and `test_gemini_integration.py`. The shared `test_api.py` covers the health endpoint.
