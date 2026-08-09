import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const options = argumentsFrom(process.argv.slice(2));
if (!options.component || !options.out) fail("usage: --component <name> --out <directory>");
const lock = JSON.parse(await readFile(new URL("../../packs/source-lock.json", import.meta.url), "utf8"));
const component = lock.components[options.component];
if (!component?.source || !component?.tag) fail("component has no Git source lock");
const destination = resolve(options.out);
run("git", ["clone", "--filter=blob:none", "--no-checkout", component.source, destination]);
run("git", ["-C", destination, "fetch", "--depth=1", "origin", `refs/tags/${component.tag}:refs/tags/${component.tag}`]);
if (component.signatureRequired) run("git", ["-C", destination, "verify-tag", component.tag]);
const expected = component.baseCommit ?? component.commit;
const actual = output("git", ["-C", destination, "rev-list", "-n", "1", component.tag]);
if (actual !== expected) fail(`tag resolved to ${actual}, expected ${expected}`);
run("git", ["-C", destination, "checkout", "--detach", expected]);
for (const patchCommit of component.requiredSecurityCommits ?? []) {
  run("git", ["-C", destination, "fetch", "--depth=1", "origin", patchCommit]);
  const patch = spawnSync("git", ["-C", destination, "show", "--format=", "--binary", patchCommit], { encoding: null });
  if (patch.status !== 0) fail(`could not read security commit ${patchCommit}`);
  const applied = spawnSync("git", ["-C", destination, "apply", "--index", "--whitespace=error-all", "-"], { input: patch.stdout });
  if (applied.status !== 0) fail(`could not apply security commit ${patchCommit}`);
}
console.log(`${options.component}: verified ${component.tag} at ${expected}`);

function run(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.status !== 0) fail(`${command} failed`);
}
function output(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.status !== 0) fail(`${command} failed`);
  return result.stdout.trim();
}
function argumentsFrom(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) parsed[values[index].replace(/^--/, "")] = values[index + 1];
  return parsed;
}
function fail(message) { console.error(message); process.exit(1); }
