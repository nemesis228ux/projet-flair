import { useEffect, useState, type FormEvent } from 'react'
import { ArrowRight, Eye, EyeOff, LoaderCircle, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { analyzeEmail, analyzeUrl, checkPassword } from '@/api/client'
import type { AnalysisResult } from '@/api/types'
import { VerdictCard } from '@/components/VerdictCard'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'

export type AnalysisKind = 'url' | 'email' | 'password'

interface AnalysisPageProps {
  kind: AnalysisKind
}

export function AnalysisPage({ kind }: AnalysisPageProps) {
  const { t } = useTranslation()
  const [input, setInput] = useState('')
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState(false)
  const [loading, setLoading] = useState(false)
  const [waitingLong, setWaitingLong] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  useEffect(() => {
    if (!loading) return

    const timer = window.setTimeout(() => setWaitingLong(true), 3000)
    return () => window.clearTimeout(timer)
  }, [loading])

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(false)
    setResult(null)
    setWaitingLong(false)
    setLoading(true)

    try {
      const analysis =
        kind === 'url'
          ? await analyzeUrl(input)
          : kind === 'email'
            ? await analyzeEmail(input)
            : await checkPassword(input)
      setResult(analysis)
    } catch {
      setError(true)
    } finally {
      if (kind === 'password') setInput('')
      setLoading(false)
    }
  }

  return (
    <div className="grid min-w-0 gap-5">
      <Card className="min-w-0">
        <CardHeader className="p-5 sm:p-6">
          <CardTitle className="text-xl">{t(`pages.${kind}.title`)}</CardTitle>
          <CardDescription>{t(`pages.${kind}.description`)}</CardDescription>
        </CardHeader>
        <CardContent className="grid min-w-0 gap-5 px-5 pb-5 sm:px-6 sm:pb-6">
          <form className="grid min-w-0 gap-4" onSubmit={handleSubmit}>
            <div className="grid min-w-0 gap-2">
              <Label htmlFor={`analysis-${kind}`}>
                {t(`pages.${kind}.label`)}
              </Label>
              {kind === 'email' ? (
                <Textarea
                  id={`analysis-${kind}`}
                  value={input}
                  onChange={(event) => setInput(event.target.value)}
                  placeholder={t(`pages.${kind}.placeholder`)}
                  autoComplete="off"
                  required
                />
              ) : (
                <div className="flex min-w-0 gap-2">
                  <Input
                    id={`analysis-${kind}`}
                    type={
                      kind === 'password'
                        ? showPassword
                          ? 'text'
                          : 'password'
                        : 'url'
                    }
                    value={input}
                    onChange={(event) => setInput(event.target.value)}
                    placeholder={t(`pages.${kind}.placeholder`)}
                    autoComplete={kind === 'password' ? 'off' : 'url'}
                    maxLength={kind === 'password' ? 128 : undefined}
                    inputMode={kind === 'url' ? 'url' : undefined}
                    required
                    className="min-w-0"
                  />
                  {kind === 'password' && (
                    <Button
                      type="button"
                      variant="outline"
                      size="icon"
                      aria-label={t(
                        showPassword
                          ? 'actions.hidePassword'
                          : 'actions.showPassword',
                      )}
                      onClick={() => setShowPassword((visible) => !visible)}
                    >
                      {showPassword ? (
                        <EyeOff aria-hidden="true" />
                      ) : (
                        <Eye aria-hidden="true" />
                      )}
                    </Button>
                  )}
                </div>
              )}
            </div>

            {kind === 'password' && (
              <Alert>
                <ShieldCheck aria-hidden="true" />
                <AlertDescription>{t('common.passwordPrivacy')}</AlertDescription>
              </Alert>
            )}

            <Button className="w-full sm:w-fit" type="submit" disabled={loading}>
              {loading ? (
                <LoaderCircle aria-hidden="true" className="animate-spin" />
              ) : (
                <ArrowRight aria-hidden="true" />
              )}
              {loading ? t('common.loading') : t('actions.analyze')}
            </Button>
          </form>

          {loading && (
            <div className="grid gap-3" role="status" aria-live="polite">
              <Skeleton className="h-5 w-2/3" />
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-3 w-4/5" />
              {waitingLong && (
                <p className="text-sm text-muted-foreground">
                  {t('common.wakingUp')}
                </p>
              )}
            </div>
          )}

          {error && (
            <Alert variant="destructive" role="alert">
              <AlertDescription>
                <span className="font-semibold">
                  {t('common.requestErrorTitle')}
                </span>
                <span className="block">{t('common.requestError')}</span>
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {result && <VerdictCard result={result} />}
    </div>
  )
}
