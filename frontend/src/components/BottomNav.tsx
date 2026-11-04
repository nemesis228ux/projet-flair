import { KeyRound, Link2, Mail } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { NavLink } from 'react-router-dom'

const links = [
  { to: '/url', label: 'navigation.url', Icon: Link2 },
  { to: '/email', label: 'navigation.email', Icon: Mail },
  { to: '/password', label: 'navigation.password', Icon: KeyRound },
]

export function BottomNav() {
  const { t } = useTranslation()

  return (
    <nav
      className="fixed inset-x-0 bottom-0 z-40 border-t border-border bg-background/95 pb-[env(safe-area-inset-bottom)] backdrop-blur md:hidden"
      aria-label={t('navigation.main')}
    >
      <div className="mx-auto grid max-w-3xl grid-cols-3 gap-1 px-2 pt-1">
        {links.map(({ to, label, Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex min-h-11 min-w-0 flex-col items-center justify-center gap-0.5 rounded-md px-1 py-1 text-xs transition-colors ${
                isActive
                  ? 'bg-accent text-brand'
                  : 'text-muted-foreground hover:bg-muted'
              }`
            }
          >
            <Icon aria-hidden="true" className="size-5 shrink-0" />
            <span className="truncate">{t(label)}</span>
          </NavLink>
        ))}
      </div>
    </nav>
  )
}
