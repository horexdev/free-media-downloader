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
      if ((asset.checksumUrl || asset.checksumSha256) &&
          (!asset.checksumUrl?.startsWith("https://") || !digest.test(asset.checksumSha256))) {
        fail(`${name}.${target} checksum sidecar is invalid`);
      }
    }
  }
  if (component.binaryLicense && typeof component.binaryLicense !== "string") {
    fail(`${name}.binaryLicense is invalid`);
  }
  if (component.signatureRequired && component.assets) {
    const verification = component.releaseVerification;
    for (const item of [verification?.checksumManifest, verification?.signature, verification?.publicKey]) {
      if (!item?.url?.startsWith("https://") || !digest.test(item.sha256)) {
        fail(`${name}.releaseVerification is incomplete`);
      }
    }
    if (!/^[0-9A-F]{40}$/.test(verification.publicKey.fingerprint ?? "")) {
      fail(`${name}.releaseVerification key fingerprint is invalid`);
    }
  }
  if (component.signatureRequired && component.sourceDistribution) {
    const verification = component.releaseVerification;
    for (const item of [verification?.signature, verification?.publicKey]) {
      if (!item?.url?.startsWith("https://") || !digest.test(item.sha256)) {
        fail(`${name}.releaseVerification is incomplete`);
      }
    }
    if (!/^[0-9A-F]{40}$/.test(verification.publicKey.fingerprint ?? "")) {
      fail(`${name}.releaseVerification key fingerprint is invalid`);
    }
  }
  if (component.sourceDistribution &&
      (!component.sourceDistribution.url?.startsWith("https://") || !digest.test(component.sourceDistribution.sha256))) {
    fail(`${name}.sourceDistribution is invalid`);
  }
  if (component.license) {
    if (!component.license.spdx || !component.license.url?.startsWith("https://") || !digest.test(component.license.sha256)) {
      fail(`${name}.license is invalid`);
    }
  }
  if (component.licenseFiles?.some((file) =>
    !file.path || file.path.startsWith("/") || file.path.includes("..") || !digest.test(file.sha256))) {
    fail(`${name}.licenseFiles is invalid`);
  }
  for (const field of ["commit", "baseCommit", "tagObject"]) {
    if (component[field] && !commit.test(component[field])) fail(`${name}.${field} is invalid`);
  }
}
for (const [licenseId, license] of Object.entries(lock.licenseTexts ?? {})) {
  if (!licenseId || !license.url?.startsWith("https://") || !digest.test(license.sha256)) {
    fail(`license text ${licenseId} is invalid`);
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
  if (recipe.sourceDateEpoch !== undefined && (!Number.isSafeInteger(recipe.sourceDateEpoch) || recipe.sourceDateEpoch <= 0)) {
    fail(`${filename}.sourceDateEpoch is invalid`);
  }
}
console.log(`validated ${Object.keys(lock.components).length} components and ${recipes.length} recipes`);

function fail(message) {
  console.error(message);
  process.exit(1);
}
