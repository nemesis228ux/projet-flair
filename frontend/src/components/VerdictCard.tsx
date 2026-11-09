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

export function VerdictCard({ result }: Readonly<VerdictCardProps>) {
  const { t } = useTranslation()
  const styles = verdictStyles[result.verdict]
  const VerdictIcon = verdictIcons[result.verdict]

  return (
    <Card
      className="min-w-0 gap-0 overflow-hidden"
      data-verdict={result.verdict}
      aria-labelledby="result-title"
    >
      <CardHeader className="grid-cols-1 gap-4 p-5 sm:p-6">
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

      <CardContent className="grid min-w-0 grid-cols-1 gap-5 p-5 pt-0 sm:p-6 sm:pt-0">
        {result.reasons.length > 0 && (
          <section className="grid min-w-0 grid-cols-1 gap-3" aria-labelledby="reasons-title">
            <h3 id="reasons-title" className="font-semibold">
              {t('result.reasons')}
            </h3>
            <ul className="grid min-w-0 grid-cols-1 gap-3">
              {result.reasons.map((reason, index) => (
                <li
                  key={`${reason.code}-${index}`}
                  className="flex min-w-0 flex-wrap items-start justify-between gap-2"
                >
                  <div className="min-w-0 flex-1">
                    <p className="wrap-anywhere text-sm font-medium">
                      {t(`reasons.${reason.code}`, {
                        defaultValue: t('result.unknownReason'),
                      })}
                    </p>
                    {reason.detail && (
                      <p className="mt-1 wrap-anywhere text-sm text-muted-foreground">
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
          <section className="grid min-w-0 grid-cols-1 gap-2">
            <h3 className="font-semibold">{t('result.tactics')}</h3>
            <ul className="grid min-w-0 grid-cols-1 list-inside list-disc gap-1 wrap-break-word text-sm text-muted-foreground">
              {result.tactics.map((tactic) => (
                <li
                  key={tactic}
                  className="min-w-0 wrap-anywhere"
                >
                  {tactic}
                </li>
              ))}
            </ul>
          </section>
        )}

        {result.explanation && (
          <section className="grid min-w-0 grid-cols-1 gap-2">
            <h3 className="font-semibold">{t('result.explanation')}</h3>
            <p className="w-full min-w-0 wrap-anywhere text-sm text-muted-foreground">
              {result.explanation}
            </p>
          </section>
        )}

        {result.breach_count !== undefined && (
          <p className="min-w-0 text-sm font-medium wrap-anywhere">
            {t('result.breachCount', { count: result.breach_count })}
          </p>
        )}

        <section className="grid min-w-0 grid-cols-1 gap-2">
          <h3 className="font-semibold">{t('result.sources')}</h3>
          <ul className="grid min-w-0 grid-cols-1 gap-4">
            {result.sources.map((source, index) => (
              <li
                key={`${source}-${index}`}
                className="grid min-w-0 justify-items-start gap-1"
              >
                <Badge
                  variant="outline"
                  className={`max-w-full whitespace-normal wrap-break-word ${styles.text}`}
                >
                  {t(`result.sourcesList.${source}`, {
                    defaultValue: t('result.sourceOther'),
                  })}
                </Badge>
                <span className="w-full min-w-0 wrap-break-word text-md text-muted-foreground">
                  {t(`result.sourceDetails.${source}`, {
                    defaultValue: t('result.sourceDetails.other'),
                  })}
                </span>
              </li>
            ))}
          </ul>
        </section>
      </CardContent>
    </Card>
  )
}
