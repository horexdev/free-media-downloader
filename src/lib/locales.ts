import type { Locale } from "./paraglide/runtime.js";

export type LocaleReview = "reviewed" | "beta";

export interface LocaleMetadata {
  autonym: string;
  direction: "ltr" | "rtl";
  review: LocaleReview;
}

export const localeMetadata: Record<Locale, LocaleMetadata> = {
  en: { autonym: "English", direction: "ltr", review: "reviewed" },
  "zh-Hans": { autonym: "简体中文", direction: "ltr", review: "beta" },
  "zh-Hant": { autonym: "繁體中文", direction: "ltr", review: "beta" },
  es: { autonym: "Español", direction: "ltr", review: "beta" },
  hi: { autonym: "हिन्दी", direction: "ltr", review: "beta" },
  ar: { autonym: "العربية", direction: "rtl", review: "beta" },
  fr: { autonym: "Français", direction: "ltr", review: "beta" },
  "pt-BR": { autonym: "Português (Brasil)", direction: "ltr", review: "beta" },
  ru: { autonym: "Русский", direction: "ltr", review: "reviewed" },
  de: { autonym: "Deutsch", direction: "ltr", review: "beta" },
  id: { autonym: "Bahasa Indonesia", direction: "ltr", review: "beta" },
  ja: { autonym: "日本語", direction: "ltr", review: "beta" },
  bn: { autonym: "বাংলা", direction: "ltr", review: "beta" },
  ur: { autonym: "اردو", direction: "rtl", review: "beta" },
  vi: { autonym: "Tiếng Việt", direction: "ltr", review: "beta" },
  tr: { autonym: "Türkçe", direction: "ltr", review: "beta" },
  it: { autonym: "Italiano", direction: "ltr", review: "beta" },
  fa: { autonym: "فارسی", direction: "rtl", review: "beta" },
  ko: { autonym: "한국어", direction: "ltr", review: "beta" },
  th: { autonym: "ไทย", direction: "ltr", review: "beta" },
  fil: { autonym: "Filipino", direction: "ltr", review: "beta" },
  ms: { autonym: "Bahasa Melayu", direction: "ltr", review: "beta" },
  pl: { autonym: "Polski", direction: "ltr", review: "beta" },
  uk: { autonym: "Українська", direction: "ltr", review: "beta" },
  ky: { autonym: "Кыргызча", direction: "ltr", review: "beta" },
  tg: { autonym: "Тоҷикӣ", direction: "ltr", review: "beta" },
  kk: { autonym: "Қазақша", direction: "ltr", review: "beta" },
  uz: { autonym: "Oʻzbekcha", direction: "ltr", review: "beta" },
  nl: { autonym: "Nederlands", direction: "ltr", review: "beta" },
  te: { autonym: "తెలుగు", direction: "ltr", review: "beta" },
  mr: { autonym: "मराठी", direction: "ltr", review: "beta" },
  ta: { autonym: "தமிழ்", direction: "ltr", review: "beta" },
  cs: { autonym: "Čeština", direction: "ltr", review: "beta" },
  ro: { autonym: "Română", direction: "ltr", review: "beta" },
};
