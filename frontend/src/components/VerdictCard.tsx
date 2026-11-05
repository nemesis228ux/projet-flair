import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { AnalysisResult, Verdict } from '@/api/types'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'

const verdictStyles: Record<
  Verdict,
  { icon: string; background: string; text: string }
> = {
  safe: {
    icon: 'text-verdict-safe',
    background: 'bg-verdict-safe-bg',
    text: 'text-verdict-safe-text',
  },
  suspicious: {
    icon: 'text-verdict-suspicious',
    background: 'bg-verdict-suspicious-bg',
    text: 'text-verdict-suspicious-text',
  },
  dangerous: {
    icon: 'text-verdict-dangerous',
    background: 'bg-verdict-dangerous-bg',
    text: 'text-verdict-dangerous-text',
  },
}

const verdictIcons = {
  safe: CheckCircle2,
  suspicious: AlertTriangle,
  dangerous: XCircle,
}

interface VerdictCardProps {
  result: AnalysisResult
}

export function VerdictCard({ result }: VerdictCardProps) {
  const { t } = useTranslation()
  const styles = verdictStyles[result.verdict]
  const VerdictIcon = verdictIcons[result.verdict]

  return (
    <Card
      className="min-w-0 gap-0 overflow-hidden"
      data-verdict={result.verdict}
      aria-labelledby="result-title"
    >
      <CardHeader className="gap-4 p-5 sm:p-6">
        <div className="flex min-w-0 items-start gap-3">
          <VerdictIcon
            aria-hidden="true"
            className={`mt-0.5 size-7 shrink-0 ${styles.icon}`}
          />
          <div className="min-w-0">
            <CardTitle
              id="result-title"
              className={`text-lg ${styles.text}`}
            >
              {t(`result.verdict.${result.verdict}`)}
            </CardTitle>
            <p className="mt-1 text-sm text-muted-foreground">
              {t('result.score')}: {result.score}/100
            </p>
          </div>
        </div>
        <div className={`rounded-lg p-4 ${styles.background}`}>
          <Progress
            value={result.score}
            aria-label={`${t('result.score')}: ${result.score}%`}
          />
          <span className="sr-only">{result.score}%</span>
        </div>
      </CardHeader>

      <CardContent className="grid min-w-0 gap-5 p-5 pt-0 sm:p-6 sm:pt-0">
        {result.reasons.length > 0 && (
          <section className="grid gap-3" aria-labelledby="reasons-title">
            <h3 id="reasons-title" className="font-semibold">
              {t('result.reasons')}
            </h3>
            <ul className="grid gap-3">
              {result.reasons.map((reason, index) => (
                <li
                  key={`${reason.code}-${index}`}
                  className="flex min-w-0 flex-wrap items-start justify-between gap-2"
                >
                  <div className="min-w-0 flex-1">
                    <p className="break-words [overflow-wrap:anywhere] text-sm">
                      {t(`reasons.${reason.code}`, {
                        defaultValue: t('result.unknownReason', {
                          code: reason.code,
                        }),
                      })}
                    </p>
                    {reason.detail && (
                      <p className="mt-1 break-words [overflow-wrap:anywhere] text-sm text-muted-foreground">
                        {reason.detail}
                      </p>
                    )}
                  </div>
                  <Badge variant="secondary">
                    {t(`result.severity.${reason.severity}`)}
                  </Badge>
                </li>
              ))}
            </ul>
          </section>
        )}

        {result.tactics && result.tactics.length > 0 && (
          <section className="grid gap-2">
            <h3 className="font-semibold">{t('result.tactics')}</h3>
            <ul className="list-inside list-disc break-words text-sm text-muted-foreground">
              {result.tactics.map((tactic) => (
                <li key={tactic}>{tactic}</li>
              ))}
            </ul>
          </section>
        )}

        {result.explanation && (
          <section className="grid gap-2">
            <h3 className="font-semibold">{t('result.explanation')}</h3>
            <p className="break-words [overflow-wrap:anywhere] text-sm text-muted-foreground">
              {result.explanation}
            </p>
          </section>
        )}

        {result.breach_count !== undefined && (
          <p className="text-sm font-medium">
            {t('result.breachCount', { count: result.breach_count })}
          </p>
        )}

        <section className="grid gap-2">
          <h3 className="font-semibold">{t('result.sources')}</h3>
          <ul className="flex flex-wrap gap-2">
            {result.sources.map((source) => (
              <li key={source}>
                <Badge variant="outline" className={styles.text}>
                  {source}
                </Badge>
              </li>
            ))}
          </ul>
        </section>
      </CardContent>
    </Card>
  )
}
