import i18n from '@/i18n'
import type {
  AnalysisResult,
  ApiResponse,
  Language,
} from './types'

const API_BASE_URL = (import.meta.env.VITE_API_URL ?? '').replace(/\/+$/, '')

type AnalysisInput =
  | { url: string }
  | { content: string }
  | { password: string }

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isAnalysisResult(value: unknown): value is AnalysisResult {
  return (
    isRecord(value) &&
    typeof value.score === 'number' &&
    ['safe', 'suspicious', 'dangerous'].includes(String(value.verdict)) &&
    Array.isArray(value.reasons) &&
    Array.isArray(value.sources)
  )
}

function isApiResponse(value: unknown): value is ApiResponse<unknown> {
  return (
    isRecord(value) &&
    typeof value.success === 'boolean' &&
    'result' in value &&
    'error' in value
  )
}

function currentLanguage(): Language {
  const language = i18n.resolvedLanguage ?? i18n.language
  return language.toLowerCase().startsWith('fr') ? 'fr' : 'en'
}

async function postAnalysis(
  path: string,
  input: AnalysisInput,
): Promise<AnalysisResult> {
  const response = await fetch(`${API_BASE_URL}/api/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...input, lang: currentLanguage() }),
  })

  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    throw new Error('Invalid API response')
  }

  if (!isApiResponse(payload)) {
    throw new Error('Invalid API response')
  }

  if (!response.ok || !payload.success) {
    const message =
      isRecord(payload.error) && typeof payload.error.error_message === 'string'
        ? payload.error.error_message
        : 'Request failed'
    throw new Error(message)
  }

  if (!isAnalysisResult(payload.result)) {
    throw new Error('Invalid analysis result')
  }

  return payload.result
}

export const analyzeUrl = (url: string): Promise<AnalysisResult> =>
  postAnalysis('url/analyze', { url })

export const analyzeEmail = (content: string): Promise<AnalysisResult> =>
  postAnalysis('email/analyze', { content })

export const checkPassword = (password: string): Promise<AnalysisResult> =>
  postAnalysis('password/check', { password })
