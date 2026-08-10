import { mkdir, readFile, writeFile, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";

const baseLocale = "en";
const messagesDir = "messages";
const settingsPath = join(process.cwd(), "project.inlang", "settings.json");
const basePath = join(process.cwd(), messagesDir, `${baseLocale}.json`);

const settings = JSON.parse(await readFile(settingsPath, "utf8"));
const locales = settings.locales ?? [];
const baseCatalog = JSON.parse(await readFile(basePath, "utf8"));
const schema = baseCatalog.$schema ?? "https://inlang.com/schema/inlang-message-format";
const baseKeys = Object.keys(baseCatalog).filter((key) => key !== "$schema").sort();

if (!baseCatalog.$schema) {
  fail("base locale message file is missing $schema");
}

await mkdir(messagesDir, { recursive: true });
const allFiles = new Set(
  (await readdir(messagesDir))
    .filter((name) => name.endsWith(".json"))
    .map((name) => name.replace(/\.json$/, "")),
);

const localesToProcess = locales.filter((value) => value !== baseLocale);
if (localesToProcess.length === 0) {
  fail("no locales configured");
}

for (const locale of localesToProcess) {
  const filePath = join(process.cwd(), messagesDir, `${locale}.json`);
  const existingContent = await readFile(filePath, "utf8").catch(() => null);
  const existing = existingContent ? JSON.parse(existingContent) : {};
  const merged = { $schema: schema };
  for (const key of baseKeys) {
    merged[key] = existing[key] ?? baseCatalog[key];
  }
  await writeFile(filePath, `${JSON.stringify(merged, null, 2)}\n`, "utf8");
  allFiles.delete(locale);
}

for (const locale of allFiles) {
  if (locale === baseLocale) {
    continue;
  }
  console.warn(`warning: message file exists for unconfigured locale ${locale}.json`);
}

console.log(`synchronized ${localesToProcess.length} locales from ${baseLocale}`);

function fail(message) {
  console.error(message);
  process.exit(1);
}
