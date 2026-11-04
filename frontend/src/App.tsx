import { AlertTriangle, ShieldAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from 'react-router-dom'
import { AnalysisPage } from '@/components/AnalysisPage'
import { BottomNav } from '@/components/BottomNav'
import { Header } from '@/components/Header'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import { useTheme } from '@/hooks/useTheme'

function App() {
  const { t } = useTranslation()
  const { theme } = useTheme()

  return (
    <BrowserRouter>
      <TooltipProvider>
        <div className="min-h-svh bg-background">
          <Header />
          <main className="mx-auto grid w-full max-w-3xl gap-6 px-4 pb-32 pt-6 sm:pt-10 md:pb-10">
            <Routes>
              <Route path="/" element={<Navigate to="/url" replace />} />
              <Route
                path="/url"
                element={<AnalysisPage key="url" kind="url" />}
              />
              <Route
                path="/email"
                element={<AnalysisPage key="email" kind="email" />}
              />
              <Route
                path="/password"
                element={<AnalysisPage key="password" kind="password" />}
              />
              <Route path="*" element={<Navigate to="/url" replace />} />
            </Routes>

            <section className="grid gap-3">
              <Alert>
                <AlertTriangle aria-hidden="true" />
                <AlertTitle>{t('common.sensitiveNoticeTitle')}</AlertTitle>
                <AlertDescription>
                  {t('common.sensitiveNotice')}
                </AlertDescription>
              </Alert>
              <p className="px-2 text-center text-sm text-muted-foreground">
                <ShieldAlert
                  aria-hidden="true"
                  className="mr-1 inline size-4 align-text-bottom"
                />
                {t('common.disclaimer')}
              </p>
            </section>
          </main>
          <BottomNav />
          <Toaster theme={theme} position="top-center" />
        </div>
      </TooltipProvider>
    </BrowserRouter>
  )
}

export default App
