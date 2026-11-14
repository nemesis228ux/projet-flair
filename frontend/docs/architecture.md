# Frontend architecture

## Purpose

The frontend is a Vite React application. It collects user input, calls the
backend API, and renders the returned analysis. It does not calculate scores,
verdicts, or heuristic strength in the browser.

## Main folders

- `src/api/`: API client and TypeScript representations of backend payloads.
- `src/components/`: Flair-specific pages and reusable UI composition.
- `src/components/ui/`: shadcn/ui primitives.
- `src/hooks/`: browser-facing hooks such as theme persistence.
- `src/i18n/`: French and English translations.
- `src/lib/`: shared frontend helpers such as class-name composition.
- `src/assets/`: bundled static assets.

## Runtime flow

```text
React form
  -> src/api/client.ts
  -> VITE_API_URL/api/v1/*
  -> backend ApiBaseResponse
  -> translated reason codes
  -> result card
```

`VITE_API_URL` is a build-time public configuration value, not a secret. API
keys and other secrets belong only to the backend deployment environment.
