# Backend architecture

## Purpose

The backend is a stateless FastAPI application. It receives URL, e-mail, and
password analysis requests, performs the analysis in memory, and returns a
shared response envelope. It does not introduce an application database.

## Request flow

```text
HTTP router
  -> request schema
  -> service
  -> pure heuristic or external integration
  -> ServiceResult
  -> ApiBaseResponse
```

## Main folders

- `app/routers/`: versioned HTTP endpoints and dependency wiring.
- `app/schemas/`: Pydantic request and response models.
- `app/services/`: feature orchestration and score/verdict composition.
- `app/common/`: shared result types, errors, constants, and pure utilities.
- `app/integrations/`: provider clients such as Gemini and HIBP.
- `app/integrations/domain_metadata.py`: IANA-discovered RDAP and public-address DNS metadata lookup.
- `app/repositories/url_metadata_repository.py`: wrapper adapter for metadata data.
- `app/core/`: configuration, logging, and rate limiting.
- `app/settings/`: application lifespan and CORS setup.
- `tests/`: focused API, service, heuristic, and integration tests.

## Privacy and safety boundaries

URL analysis inspects only the submitted string. It never fetches or resolves
the URL, which prevents the analyzer from becoming an SSRF proxy. Passwords
are processed in memory and are never logged or persisted. External providers
are isolated in `integrations/` and return through the repository/service
result conventions.

RDAP discovery downloads `https://data.iana.org/rdap/dns.json`, caches the
IANA `services` mappings with the existing metadata TTL setting, and selects
the longest matching DNS suffix for the public suffix-derived registrable
domain. It accepts only HTTPS base URLs whose hostname is public and not
localhost or an IP address on a private/loopback/non-global range. Lookups use
`GET /domain/{domain}` with redirects disabled and never append the submitted
URL path. The fixed IANA bootstrap endpoint is residual fallback only.
`publicsuffix2` remains the registrable-domain fallback, and metadata plus
bootstrap mappings use TTL caches under the existing concurrency semaphore.
