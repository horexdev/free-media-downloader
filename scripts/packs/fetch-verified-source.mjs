import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import { Readable, Transform } from "node:stream";
import { resolve } from "node:path";

const options = argumentsFrom(process.argv.slice(2));
if (!options.component || !options.out) fail("usage: --component <name> [--target <target>] --out <file>");
const lock = JSON.parse(await readFile(new URL("../../packs/source-lock.json", import.meta.url), "utf8"));
const component = lock.components[options.component];
if (!component) fail("unknown component");
const asset = component.assets ? component.assets[options.target] : component.sourceUrl ? { url: component.sourceUrl, sha256: component.sha256 } : null;
if (!asset?.url || !asset?.sha256) fail("component must be checked out from its signed Git tag");
const destination = resolve(options.out);
const response = await fetch(asset.url, { redirect: "follow" });
if (!response.ok || !response.body) fail(`download failed with HTTP ${response.status}`);
const hash = createHash("sha256");
const meter = new Transform({ transform(chunk, _encoding, callback) { hash.update(chunk); callback(null, chunk); } });
try {
  await pipeline(Readable.fromWeb(response.body), meter, createWriteStream(destination, { flags: "wx", mode: 0o600 }));
  const actual = hash.digest("hex");
  if (actual !== asset.sha256) throw new Error(`digest mismatch: ${actual}`);
  console.log(`${options.component} ${options.target ?? "source"}: ${actual}`);
} catch (error) {
  await rm(destination, { force: true });
  fail(error instanceof Error ? error.message : String(error));
}

function argumentsFrom(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) parsed[values[index].replace(/^--/, "")] = values[index + 1];
  return parsed;
}
function fail(message) { console.error(message); process.exit(1); }
