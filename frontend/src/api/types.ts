export type Language = 'fr' | 'en'

export type Verdict = 'safe' | 'suspicious' | 'dangerous'

export type Severity = 'low' | 'medium' | 'high'

export interface Reason {
  code: string
  severity: Severity
  detail?: string
}

export interface AnalysisResult {
  score: number
  verdict: Verdict
  reasons: Reason[]
  sources: string[]
  tactics?: string[]
  explanation?: string
  breach_count?: number
}

export interface AppError {
  error_type: string
  error_message: string
}

export interface ApiResponse<T> {
  success: boolean
  result: T | null
  error: AppError | null
}
