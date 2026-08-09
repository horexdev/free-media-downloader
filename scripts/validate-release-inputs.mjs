import { readFile, readdir } from "node:fs/promises";

const lock = JSON.parse(await readFile(new URL("../packs/source-lock.json", import.meta.url), "utf8"));
const targets = ["windows-x64", "windows-arm64", "macos-x64", "macos-arm64", "linux-x64", "linux-arm64"];
const digest = /^[0-9a-f]{64}$/;
const commit = /^[0-9a-f]{40}$/;

if (lock.schemaVersion !== 1 || !lock.components) fail("source lock schema is invalid");
for (const [name, component] of Object.entries(lock.components)) {
  if (!component.version) fail(`${name} has no version`);
  if (component.assets) {
    for (const target of targets) {
      const asset = component.assets[target];
      if (!asset || !asset.url.startsWith("https://") || !digest.test(asset.sha256)) {
        fail(`${name} is not locked for ${target}`);
      }
    }
  }
  for (const field of ["commit", "baseCommit", "tagObject"]) {
    if (component[field] && !commit.test(component[field])) fail(`${name}.${field} is invalid`);
  }
}
const libssh2 = lock.components.libssh2;
if (libssh2.requiredSecurityCommits.length < 2 || libssh2.requiredSecurityCommits.some((value) => !commit.test(value))) {
  fail("libssh2 security patch set is incomplete");
}
const recipes = await readdir(new URL("../packs/recipes/", import.meta.url));
for (const filename of recipes) {
  const recipe = JSON.parse(await readFile(new URL(`../packs/recipes/${filename}`, import.meta.url), "utf8"));
  if (!recipe.packId || !Number.isSafeInteger(recipe.sizeBudget)) fail(`${filename} is invalid`);
}
console.log(`validated ${Object.keys(lock.components).length} components and ${recipes.length} recipes`);

function fail(message) {
  console.error(message);
  process.exit(1);
}
