import { Languages, Moon, ScanSearch, Sun } from 'lucide-react'
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useTheme } from '@/hooks/useTheme'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'

const paths = ['/url', '/email', '/password']

export function Header() {
  const { t, i18n } = useTranslation()
  const { theme, toggleTheme } = useTheme()
  const location = useLocation()
  const navigate = useNavigate()
  const activeTab = paths.includes(location.pathname)
    ? location.pathname.slice(1)
    : 'url'

  useEffect(() => {
    document.documentElement.lang = i18n.resolvedLanguage?.startsWith('fr')
      ? 'fr'
      : 'en'
  }, [i18n.resolvedLanguage])

  const changeLanguage = (language: 'fr' | 'en') => {
    void i18n.changeLanguage(language)
    document.documentElement.lang = language
  }

  return (
    <header className="border-b border-border bg-background">
      <div className="mx-auto flex h-16 w-full max-w-3xl items-center justify-between gap-3 px-4">
        <Link
          to="/url"
          className="flex shrink-0 items-center gap-2 text-brand"
          aria-label={t('brand')}
        >
          <ScanSearch aria-hidden="true" className="size-5" />
          <span className="text-xl font-bold tracking-tight">{t('brand')}</span>
        </Link>

        <nav className="hidden md:block" aria-label={t('navigation.main')}>
          <Tabs
            value={activeTab}
            onValueChange={(value) => navigate(`/${value}`)}
          >
            <TabsList className="h-11">
              <TabsTrigger value="url" className="min-h-11 px-4">
                {t('navigation.url')}
              </TabsTrigger>
              <TabsTrigger value="email" className="min-h-11 px-4">
                {t('navigation.email')}
              </TabsTrigger>
              <TabsTrigger value="password" className="min-h-11 px-4">
                {t('navigation.password')}
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </nav>

        <div className="flex shrink-0 items-center gap-1">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                aria-label={t('actions.chooseLanguage')}
              >
                <Languages aria-hidden="true" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem
                className="min-h-11"
                onSelect={() => changeLanguage('fr')}
                aria-current={i18n.resolvedLanguage?.startsWith('fr')}
              >
                Français
              </DropdownMenuItem>
              <DropdownMenuItem
                className="min-h-11"
                onSelect={() => changeLanguage('en')}
                aria-current={i18n.resolvedLanguage?.startsWith('en')}
              >
                English
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                onClick={toggleTheme}
                aria-label={t(
                  theme === 'dark'
                    ? 'header.themeToLight'
                    : 'header.themeToDark',
                )}
              >
                {theme === 'dark' ? (
                  <Sun aria-hidden="true" />
                ) : (
                  <Moon aria-hidden="true" />
                )}
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              {t(
                theme === 'dark'
                  ? 'header.themeToLight'
                  : 'header.themeToDark',
              )}
            </TooltipContent>
          </Tooltip>
        </div>
      </div>
    </header>
  )
}
