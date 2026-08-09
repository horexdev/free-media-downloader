import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { chmod, copyFile, cp, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { spawnSync } from "node:child_process";

const targets = new Set([
  "windows-x64", "windows-arm64", "macos-x64",
  "macos-arm64", "linux-x64", "linux-arm64",
]);
const allowedPacks = new Set(["live-streams", "galleries"]);
const downloadHosts = new Set([
  "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
  "raw.githubusercontent.com", "files.pythonhosted.org",
]);
const maxDownloadBytes = 512 * 1024 * 1024;
const options = parseArguments(process.argv.slice(2));
for (const name of ["pack", "target", "bundle", "licenses", "lock", "work", "out", "packager"]) {
  if (!options[name]) fail("missing --" + name);
}
if (!allowedPacks.has(options.pack)) fail("unsupported pack: " + options.pack);
if (!targets.has(options.target)) fail("unsupported target: " + options.target);
if (currentTarget() !== options.target) fail("pack assembly must run on its native target");

const lock = JSON.parse(await readFile(new URL("../../packs/source-lock.json", import.meta.url), "utf8"));
const recipe = JSON.parse(await readFile(
  new URL(`../../packs/recipes/${options.pack}.json`, import.meta.url),
  "utf8",
));
const work = resolve(options.work);
const output = resolve(options.out);
const bundle = resolve(options.bundle);
const licenses = resolve(options.licenses);
const requirementsLock = resolve(options.lock);
const packager = resolve(options.packager);
await requireAbsent(work, "work directory");
await requireAbsent(output, "output archive");
await requireDirectory(bundle, "bundle");
await requireDirectory(licenses, "license directory");
await requireFile(requirementsLock, "requirements lock");
await requireFile(packager, "packager");
await mkdir(join(work, "payload", "bin"), { recursive: true, mode: 0o700 });
await mkdir(join(work, "payload", "LICENSES"), { recursive: true, mode: 0o700 });
await mkdir(join(work, "downloads"), { recursive: true, mode: 0o700 });
await mkdir(dirname(output), { recursive: true });

const payload = join(work, "payload");
const suffix = options.target.startsWith("windows-") ? ".exe" : "";
const isLive = options.pack === "live-streams";
const engineName = isLive ? "streamlink" : "gallery-dl";
const bundleName = isLive ? "streamlink" : "gallery_dl";
const primary = lock.components[engineName];
const bundleDestination = join(payload, "bin", engineName);
await cp(bundle, bundleDestination, {
  recursive: true,
  dereference: true,
  errorOnExist: true,
  force: false,
});
await rejectDevelopmentFiles(bundleDestination);
await cp(licenses, join(payload, "LICENSES", "python"), {
  recursive: true, errorOnExist: true, force: false,
});
await copyFile(requirementsLock, join(payload, "python-requirements.lock"));
await fetchVerified(
  primary.license.url,
  primary.license.sha256,
  join(payload, "LICENSES", `${engineName}-${primary.binaryLicense}.txt`),
);

const entrypoint = `bin/${engineName}/${bundleName}${suffix}`;
await requireFile(join(payload, entrypoint), "Python bundle entrypoint");
if (!options.target.startsWith("windows-")) await chmod(join(payload, entrypoint), 0o755);
const engines = [{
  id: engineName,
  version: primary.version,
  adapter_id: isLive ? "streamlink_v1" : "gallery_dl_v1",
  adapter_api: 1,
  entrypoint,
  companions: {},
  capabilities: isLive ? ["live_plugin", "hls", "dash"] : ["gallery_extraction"],
}];
const components = [manifestPrimary(engineName, primary)];
const subjects = [{ name: entrypoint, sha256: await sha256File(join(payload, entrypoint)) }];

if (isLive) {
  const manifestEngine = lock.components["n-m3u8dl-re"];
  const asset = manifestEngine.assets[options.target];
  if (!asset?.url || !asset?.sha256) fail("N_m3u8DL-RE asset is not locked for target");
  const archive = join(work, "downloads", options.target.startsWith("windows-") ? "n.zip" : "n.tar.gz");
  const nEntrypoint = `bin/N_m3u8DL-RE${suffix}`;
  await fetchVerified(asset.url, asset.sha256, archive);
  await fetchVerified(
    manifestEngine.license.url,
    manifestEngine.license.sha256,
    join(payload, "LICENSES", "N_m3u8DL-RE-MIT.txt"),
  );
  run(packager, [
    options.target.startsWith("windows-") ? "extract-zip-entry" : "extract-tar-gz-entry",
    archive,
    `N_m3u8DL-RE${suffix}`,
    join(payload, nEntrypoint),
  ]);
  if (!options.target.startsWith("windows-")) await chmod(join(payload, nEntrypoint), 0o755);
  engines.push({
    id: "n-m3u8dl-re",
    version: manifestEngine.version,
    adapter_id: "n_m3u8_dl_re_v1",
    adapter_api: 1,
    entrypoint: nEntrypoint,
    companions: {},
    capabilities: ["hls", "dash", "mss"],
  });
  components.push({
    name: "n-m3u8dl-re",
    version: manifestEngine.version,
    source_url: asset.url,
    source_revision: manifestEngine.version,
    source_sha256: asset.sha256,
    license_id: manifestEngine.binaryLicense,
    original_sha256: asset.sha256,
  });
  subjects.push({ name: nEntrypoint, sha256: await sha256File(join(payload, nEntrypoint)) });
  smoke(join(payload, nEntrypoint), ["--version"], (text) => text.includes("0.6.0"), "N_m3u8DL-RE");
}

smoke(
  join(payload, entrypoint),
  ["--version"],
  (text) => text.includes(primary.version),
  engineName,
);
await writeJson(join(payload, "sources.json"), {
  schemaVersion: 1,
  packId: recipe.packId,
  packVersion: recipe.version,
  target: options.target,
  pythonVersion: "3.12",
  requirementsSha256: await sha256File(requirementsLock),
  components,
});
await writeJson(join(payload, "sbom.spdx.json"), {
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name: `${recipe.packId}-${recipe.version}-${options.target}`,
  documentNamespace: `https://horexdev.github.io/free-media-downloader-updates/sbom/${recipe.packId}/${recipe.version}/${options.target}`,
  creationInfo: { created: new Date(0).toISOString(), creators: ["Organization: FMD contributors"] },
  packages: components.map((component, index) => ({
    SPDXID: `SPDXRef-Package-${index}`,
    name: component.name,
    versionInfo: component.version,
    downloadLocation: component.source_url,
    filesAnalyzed: false,
    licenseConcluded: component.license_id,
    licenseDeclared: component.license_id,
    checksums: [{ algorithm: "SHA256", checksumValue: component.source_sha256 }],
  })),
});
await writeFile(join(payload, "provenance.intoto.jsonl"), JSON.stringify({
  _type: "https://in-toto.io/Statement/v1",
  subject: subjects.map((subject) => ({ name: subject.name, digest: { sha256: subject.sha256 } })),
  predicateType: "https://slsa.dev/provenance/v1",
  predicate: {
    buildDefinition: {
      buildType: "https://github.com/horexdev/free-media-downloader/engine-pack/v1",
      externalParameters: { packId: recipe.packId, packVersion: recipe.version, target: options.target },
      internalParameters: {},
      resolvedDependencies: components.map((component) => ({
        uri: component.source_url, digest: { sha256: component.source_sha256 },
      })),
    },
    runDetails: { builder: { id: "https://github.com/horexdev/free-media-downloader/.github/workflows/engine-packs.yml" } },
  },
}) + "\n", { encoding: "utf8", flag: "wx", mode: 0o600 });

const template = join(work, "manifest-template.json");
await writeJson(template, {
  schema_version: 1,
  id: recipe.packId,
  version: recipe.version,
  target: options.target,
  core_api_min: 1,
  core_api_max: 1,
  security_sequence: 1,
  dependencies: (recipe.dependencies ?? []).map((dependency) => ({
    pack_id: dependency.packId,
    version_req: dependency.version,
    required: dependency.required,
  })),
  engines,
  components,
  files: [],
  self_tests: engines.map((engine) => ({
    engine_id: engine.id,
    expected_version: engine.version,
    timeout_seconds: 20,
  })),
});
run(packager, ["package", template, payload, output]);
const archiveSize = (await stat(output)).size;
if (archiveSize > recipe.sizeBudget) {
  await rm(output, { force: true });
  fail(`${recipe.packId} exceeds its size budget: ${archiveSize} > ${recipe.sizeBudget}`);
}
const repeat = join(work, "repeat.zip");
run(packager, ["package", template, payload, repeat]);
const archiveHash = await sha256File(output);
if (archiveHash !== await sha256File(repeat)) fail(`${recipe.packId} packaging is not reproducible`);
await rm(repeat, { force: true });
console.log(JSON.stringify({ pack: `${recipe.packId}@${recipe.version}`, target: options.target, size: archiveSize, sha256: archiveHash }));

function manifestPrimary(name, component) {
  const source = component.sourceDistribution ?? { url: component.sourceUrl, sha256: component.sha256 };
  return {
    name,
    version: component.version,
    source_url: source.url,
    source_revision: component.commit ?? component.version,
    source_sha256: source.sha256,
    license_id: component.binaryLicense,
    original_sha256: null,
  };
}

async function rejectDevelopmentFiles(root) {
  for (const entry of await readdir(root, { recursive: true, withFileTypes: true })) {
    const name = entry.name.toLowerCase();
    if (name === "__pycache__" || name.endsWith(".pyc") || name === "tests" || name === "test") {
      fail("Python bundle contains development-only files: " + entry.name);
    }
  }
}

async function fetchVerified(url, expectedHash, destination) {
  if (!url.startsWith("https://") || !/^[0-9a-f]{64}$/.test(expectedHash)) fail("download is not fully locked");
  let current = new URL(url);
  let response;
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    if (current.protocol !== "https:" || !downloadHosts.has(current.hostname)) fail("download origin is not allowlisted");
    response = await fetch(current, { redirect: "manual" });
    if (response.status < 300 || response.status >= 400) break;
    const location = response.headers.get("location");
    if (!location) fail("download redirect is missing a location");
    current = new URL(location, current);
  }
  if (!response?.ok || !response.body) fail("download failed");
  const hash = createHash("sha256");
  let received = 0;
  const meter = new Transform({ transform(chunk, _encoding, callback) {
    received += chunk.length;
    if (received > maxDownloadBytes) return callback(new Error("download exceeds input limit"));
    hash.update(chunk);
    callback(null, chunk);
  }});
  try {
    await pipeline(Readable.fromWeb(response.body), meter, createWriteStream(destination, { flags: "wx", mode: 0o600 }));
    if (hash.digest("hex") !== expectedHash) throw new Error("download digest mismatch");
  } catch (error) {
    await rm(destination, { force: true });
    fail(error instanceof Error ? error.message : String(error));
  }
}

function smoke(executable, args, accepts, label) {
  const result = spawnSync(executable, args, { encoding: "utf8", timeout: 30_000, windowsHide: true, env: smokeEnvironment() });
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (result.status !== 0 || !accepts(output)) fail(`${label} smoke test failed`);
}

function smokeEnvironment() {
  const environment = { NO_COLOR: "1" };
  for (const name of ["SystemRoot", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE"]) {
    if (process.env[name]) environment[name] = process.env[name];
  }
  return environment;
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8", windowsHide: true });
  if (result.status !== 0) fail(`${basename(command)} failed: ${result.stderr ?? result.stdout ?? ""}`);
}

async function writeJson(path, value) {
  await writeFile(path, JSON.stringify(value, null, 2) + "\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
}

async function sha256File(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function requireAbsent(path, label) {
  try { await stat(path); fail(label + " already exists"); } catch (error) { if (error?.code !== "ENOENT") throw error; }
}

async function requireFile(path, label) {
  if (!(await stat(path).catch(() => null))?.isFile()) fail(label + " is not a file");
}

async function requireDirectory(path, label) {
  if (!(await stat(path).catch(() => null))?.isDirectory()) fail(label + " is not a directory");
}

function currentTarget() {
  const os = { win32: "windows", darwin: "macos", linux: "linux" }[process.platform];
  const architecture = { x64: "x64", arm64: "arm64" }[process.arch];
  return os && architecture ? `${os}-${architecture}` : null;
}

function parseArguments(values) {
  if (values.length % 2 !== 0) fail("arguments must be --name value pairs");
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    if (!name.startsWith("--") || parsed[name.slice(2)] !== undefined) fail("invalid argument: " + name);
    parsed[name.slice(2)] = values[index + 1];
  }
  return parsed;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
