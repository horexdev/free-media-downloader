import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

const options = parseArguments(process.argv.slice(2));
if (!options.kind || !options.file) {
  fail("usage: node scripts/check-artifact-size.mjs --kind <budget> --file <artifact> [--baseline <bytes>]");
}

const budgets = JSON.parse(await readFile(new URL("../size-budgets.json", import.meta.url), "utf8"));
const maximum = budgets[options.kind];
if (!Number.isSafeInteger(maximum) || maximum <= 0) {
  fail(`unknown size budget: ${options.kind}`);
}

const artifact = resolve(options.file);
const bytes = (await stat(artifact)).size;
if (bytes > maximum) {
  fail(`${options.kind} is ${bytes} bytes, above the ${maximum} byte budget`);
}

if (options.baseline) {
  const baseline = Number(options.baseline);
  if (!Number.isSafeInteger(baseline) || baseline <= 0) fail("baseline must be a positive integer");
  const allowedGrowth = Math.floor(baseline * 1.1);
  if (bytes > allowedGrowth) {
    fail(`${options.kind} grew from ${baseline} to ${bytes} bytes, more than 10 percent`);
  }
}

console.log(`${options.kind}: ${bytes} / ${maximum} bytes`);

function parseArguments(arguments_) {
  const result = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index]?.replace(/^--/, "");
    const value = arguments_[index + 1];
    if (!key || value === undefined) fail("arguments must be key-value pairs");
    result[key] = value;
  }
  return result;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
