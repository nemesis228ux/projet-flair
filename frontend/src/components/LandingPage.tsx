import type { AnalysisKind } from "@/components/AnalysisPage";
import { AnalysisPage } from "@/components/AnalysisPage";
import {
  ArrowDown,
  KeyRound,
  Link2,
  Mail,
  ScanSearch,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

const tools: {
  kind: AnalysisKind;
  label: string;
  Icon: typeof Link2;
}[] = [
  { kind: "url", label: "navigation.url", Icon: Link2 },
  { kind: "email", label: "navigation.email", Icon: Mail },
  { kind: "password", label: "navigation.password", Icon: KeyRound },
];

export function LandingPage() {
  const { t } = useTranslation();
  const [selectedTool, setSelectedTool] = useState<AnalysisKind>("url");

  return (
    <div className="grid gap-14 sm:gap-20">
      <section className="grid items-center gap-10 py-8 sm:py-14 lg:grid-cols-[1.15fr_0.85fr]">
        <div className="grid justify-items-start gap-6">
          <div className="inline-flex min-h-11 items-center gap-2 rounded-full border border-border bg-card px-4 text-sm font-medium text-muted-foreground">
            <Sparkles aria-hidden="true" className="size-4 text-brand" />
            {t("home.eyebrow")}
          </div>
          <h1 className="max-w-3xl text-4xl leading-[1.08] font-bold tracking-tight sm:text-6xl">
            {t("home.title")}{" "}
            <span className="text-brand">{t("home.titleHighlight")}</span>
          </h1>
          <p className="max-w-xl text-lg leading-8 text-muted-foreground">
            {t("home.description")}
          </p>
          <a
            href="#tools"
            className="inline-flex min-h-11 items-center justify-center gap-2 rounded-md bg-primary px-5 py-3 font-medium text-primary-foreground transition-colors hover:bg-primary-hover focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
          >
            {t("home.cta")}
            <ArrowDown aria-hidden="true" className="size-4" />
          </a>
          <p className="text-sm text-muted-foreground">
            {t("home.privacyNote")}
          </p>
        </div>

        <div
          aria-hidden="true"
          className="relative mx-auto w-full max-w-md rounded-3xl border border-border bg-card p-5 shadow-xl shadow-primary/5 sm:p-7"
        >
          <div className="absolute top-4 right-4 grid size-14 place-items-center rounded-2xl bg-accent text-brand shadow-sm">
            <ShieldCheck className="size-7" />
          </div>
          <div className="grid gap-6">
            <div className="grid size-14 place-items-center rounded-2xl bg-accent text-brand">
              <ScanSearch className="size-7" />
            </div>
            <div className="grid gap-2">
              <p className="text-sm font-medium text-muted-foreground">
                {t("home.previewLabel")}
              </p>
              <p className="text-2xl font-semibold tracking-tight">
                {t("home.previewTitle")}
              </p>
              <p className="text-sm leading-6 text-muted-foreground">
                {t("home.previewDescription")}
              </p>
            </div>
            <div className="grid gap-3">
              {[0, 1, 2].map((item) => (
                <div
                  key={item}
                  className="h-3 rounded-full bg-muted"
                  style={{ width: `${100 - item * 19}%` }}
                />
              ))}
            </div>
            <div className="flex items-center gap-2 border-t border-border pt-4 text-sm text-muted-foreground">
              <ShieldCheck aria-hidden="true" className="size-4 text-brand" />
              {t("home.previewFootnote")}
            </div>
          </div>
        </div>
      </section>

      <section id="tools" className="grid scroll-mt-8 gap-7">
        <div className="grid gap-2">
          <p className="text-sm font-semibold tracking-wide text-brand uppercase">
            {t("home.toolsEyebrow")}
          </p>
          <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">
            {t("home.toolsTitle")}
          </h2>
          <p className="max-w-2xl text-muted-foreground">
            {t("home.toolsDescription")}
          </p>
        </div>

        <fieldset
          className="grid gap-3 sm:grid-cols-3"
          aria-label={t("home.toolsTitle")}
        >
          {tools.map(({ kind, label, Icon }) => {
            const selected = selectedTool === kind;
            return (
              <button
                key={kind}
                type="button"
                aria-pressed={selected}
                onClick={() => setSelectedTool(kind)}
                className={`grid min-h-28 content-start justify-items-start gap-3 rounded-xl border p-4 text-left transition-colors focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none sm:min-h-32 ${
                  selected
                    ? "border-primary bg-accent"
                    : "border-border bg-card hover:bg-muted"
                }`}
              >
                <span
                  className={`grid size-10 place-items-center rounded-lg ${
                    selected
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-brand"
                  }`}
                >
                  <Icon aria-hidden="true" className="size-5" />
                </span>
                <span className="grid gap-1">
                  <span className="font-semibold">{t(label)}</span>
                  <span className="text-sm leading-5 text-muted-foreground">
                    {t(`pages.${kind}.description`)}
                  </span>
                </span>
              </button>
            );
          })}
        </fieldset>

        <div className="grid gap-4">
          <p className="text-sm text-muted-foreground">
            {t("home.formHint", { tool: t(`navigation.${selectedTool}`) })}
          </p>
          <AnalysisPage key={selectedTool} kind={selectedTool} />
        </div>
      </section>
    </div>
  );
}
