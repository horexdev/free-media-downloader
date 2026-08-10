import { readFile } from "node:fs/promises";

const settings = JSON.parse(await readFile(new URL("../project.inlang/settings.json", import.meta.url), "utf8"));
const required = (settings.locales ?? ["en"]).filter((locale) => locale !== "en");
const base = JSON.parse(await readFile(new URL("../messages/en.json", import.meta.url), "utf8"));
const baseKeys = Object.keys(base).filter((key) => key !== "$schema").sort();
for (const locale of required) {
  const catalog = JSON.parse(await readFile(new URL(`../messages/${locale}.json`, import.meta.url), "utf8"));
  const keys = Object.keys(catalog).filter((key) => key !== "$schema").sort();
  if (JSON.stringify(keys) !== JSON.stringify(baseKeys)) fail(`${locale}: message keys are incomplete`);
  for (const key of baseKeys) {
    if (typeof catalog[key] !== "string" || catalog[key].trim() === "") fail(`${locale}.${key}: message is empty`);
    if (placeholders(catalog[key]) !== placeholders(base[key])) fail(`${locale}.${key}: placeholders differ from English`);
    if (/\uFFFD/.test(catalog[key])) fail(`${locale}.${key}: replacement character found`);
  }
}
console.log(`validated ${required.length} complete Beta catalogs`);

function placeholders(value) {
  return [...value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)].map((match) => match[1]).sort().join(",");
}
function fail(message) { console.error(message); process.exit(1); }
