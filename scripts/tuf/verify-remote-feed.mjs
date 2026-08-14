import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const options = parseArguments(process.argv.slice(2));
if (!options["base-url"] || !options["expected-timestamp"]) {
  fail("required: --base-url and --expected-timestamp");
}
const base = options["base-url"].replace(/\/$/, "");
const expectedTimestamp = readFileSync(options["expected-timestamp"]);
const expectedDigest = sha256(expectedTimestamp);
let timestampBytes;
for (let attempt = 1; attempt <= 30; attempt += 1) {
  const response = await fetch(`${base}/metadata/timestamp.json`, { cache: "no-store" });
  if (response.ok) {
    const candidate = Buffer.from(await response.arrayBuffer());
    if (sha256(candidate) === expectedDigest) {
      timestampBytes = candidate;
      break;
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 10_000));
}
if (!timestampBytes) fail("published timestamp did not become visible before the deadline");

const timestamp = JSON.parse(timestampBytes);
const snapshotMeta = timestamp.signed.meta["snapshot.json"];
const snapshotBytes = await download(`metadata/${snapshotMeta.version}.snapshot.json`);
verify(snapshotBytes, snapshotMeta, "snapshot");
const snapshot = JSON.parse(snapshotBytes);
const targetsMeta = snapshot.signed.meta["targets.json"];
const targetsBytes = await download(`metadata/${targetsMeta.version}.targets.json`);
verify(targetsBytes, targetsMeta, "targets");
const targets = JSON.parse(targetsBytes);
for (const [name, meta] of Object.entries(targets.signed.targets)) {
  const bytes = await download(`targets/${meta.hashes.sha256}.${name}`);
  verify(bytes, meta, name);
  const descriptor = JSON.parse(bytes);
  if (descriptor.target_name !== name) fail(`descriptor name mismatch: ${name}`);
}
console.log(JSON.stringify({ ok: true, targets: Object.keys(targets.signed.targets).length }));

async function download(path) {
  const response = await fetch(`${base}/${path}`, { cache: "no-store" });
  if (!response.ok) fail(`download failed (${response.status}): ${path}`);
  return Buffer.from(await response.arrayBuffer());
}

function verify(bytes, meta, label) {
  if (bytes.length !== meta.length || sha256(bytes) !== meta.hashes.sha256) {
    fail(`${label} hash/length mismatch`);
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseArguments(values) {
  if (values.length % 2 !== 0) fail("arguments must be --name value pairs");
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) {
    parsed[values[index].replace(/^--/, "")] = values[index + 1];
  }
  return parsed;
}

function fail(message) {
  console.error(`[verify-remote-tuf-feed] ${message}`);
  process.exit(1);
}
