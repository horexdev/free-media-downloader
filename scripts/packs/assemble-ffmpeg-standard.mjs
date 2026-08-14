import { createHash } from "node:crypto";
import { chmod, cp, copyFile, lstat, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const targets = new Set([
  "linux-x64", "linux-arm64", "macos-x64", "macos-arm64", "windows-x64", "windows-arm64",
]);
const options = parseArguments(process.argv.slice(2));
for (const required of ["target", "work", "out", "packager", "ffmpeg", "ffprobe"]) {
  if (!options[required]) fail("missing --" + required);
}
if (!targets.has(options.target)) fail("unsupported target: " + options.target);
const hostTarget = currentTarget();
if (!isCompatibleTarget(hostTarget, options.target)) {
  fail(
    "native assembly requires " + options.target +
    ", current host is " + (hostTarget ?? "unsupported"),
  );
}

const lock = JSON.parse(await readFile(new URL("../../packs/source-lock.json", import.meta.url), "utf8"));
const recipe = JSON.parse(await readFile(new URL("../../packs/recipes/ffmpeg-standard.json", import.meta.url), "utf8"));
const work = resolve(options.work);
const output = resolve(options.out);
const packager = resolve(options.packager);
const ffmpegBinary = resolve(options.ffmpeg);
const ffprobeBinary = resolve(options.ffprobe);
await requireAbsent(work, "work directory");
await requireAbsent(output, "output archive");
await requireFile(packager, "packager");
await requireFile(ffmpegBinary, "ffmpeg binary");
await requireFile(ffprobeBinary, "ffprobe binary");
await mkdir(join(work, "payload", "bin"), { recursive: true, mode: 0o700 });
await mkdir(join(work, "payload", "LICENSES"), { recursive: true, mode: 0o700 });
await mkdir(join(work, "temp"), { recursive: true, mode: 0o700 });
await mkdir(dirname(output), { recursive: true });

const component = lock.components["ffmpeg"];
if (!component) fail("source lock has no ffmpeg component");
if (!Array.isArray(component.licenseFiles) || component.licenseFiles.length === 0) {
  fail("ffmpeg component is missing locked source license files");
}
const source = component.sourceDistribution ?? component.sourceUrl;
if (!source?.url || !source.sha256) fail("ffmpeg source distribution is not locked");
if (!component.version) fail("ffmpeg version is not locked");

const payload = join(work, "payload");
const suffix = options.target.startsWith("windows-") ? ".exe" : "";
const ffmpegEntrypoint = `bin/ffmpeg${suffix}`;
const ffprobeEntrypoint = `bin/ffprobe${suffix}`;
const ffmpegTarget = join(payload, ffmpegEntrypoint);
const ffprobeTarget = join(payload, ffprobeEntrypoint);

await cp(ffmpegBinary, ffmpegTarget, { errorOnExist: true, force: false });
await cp(ffprobeBinary, ffprobeTarget, { errorOnExist: true, force: false });
if (!options.target.startsWith("windows-")) {
  await chmod(ffmpegTarget, 0o755);
  await chmod(ffprobeTarget, 0o755);
}

const sourceRoot = await resolveLicenseSourceRoot(options, work);
const licenseTargets = new Set();
for (const file of component.licenseFiles) {
  if (!file?.path || file.path.includes("..") || file.path.includes("\\") || file.path.includes("\0")) {
    fail(`invalid ffmpeg license file path: ${file?.path ?? "<missing>"}`);
  }
  const sourceFile = join(sourceRoot, file.path);
  const sourceMetadata = await stat(sourceFile).catch(() => null);
  if (!sourceMetadata || !sourceMetadata.isFile()) fail("license file is missing in source: " + file.path);
  const expectedHash = file.sha256?.toLowerCase?.();
  if (!/^[0-9a-f]{64}$/.test(expectedHash ?? "")) fail("invalid license sha for " + file.path);
  const actual = await sha256File(sourceFile);
  if (actual !== expectedHash) fail(`license hash mismatch: ${file.path}`);
  const destinationName = basename(file.path).replace(/[^A-Za-z0-9._-]/g, "-");
  if (licenseTargets.has(destinationName)) {
    fail("duplicate license filename in payload: " + destinationName);
  }
  licenseTargets.add(destinationName);
  await copyFile(sourceFile, join(payload, "LICENSES", destinationName));
}

const componentRecord = manifestSourceComponent(component, source);
const files = await collectFiles(payload);
await writeJson(join(payload, "sources.json"), {
  schemaVersion: 1,
  packId: recipe.packId,
  packVersion: recipe.version,
  target: options.target,
  sourceDateEpoch: recipe.sourceDateEpoch ?? 0,
  components: [componentRecord],
});
await writeJson(
  join(payload, "sbom.spdx.json"),
  spdxDocument(recipe, options.target, componentRecord),
);
const subjects = [
  { name: ffmpegEntrypoint, sha256: await sha256File(ffmpegTarget) },
  { name: ffprobeEntrypoint, sha256: await sha256File(ffprobeTarget) },
];
await writeFile(
  join(payload, "provenance.intoto.jsonl"),
  JSON.stringify(
    provenance(recipe, options.target, subjects, [componentRecord]),
    null,
    2,
  ) + "\n",
  { encoding: "utf8", flag: "wx", mode: 0o600 },
);

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
  engines: [{
    id: "ffmpeg",
    version: component.version,
    adapter_id: "ffmpeg_v1",
    adapter_api: 1,
    entrypoint: ffmpegEntrypoint,
    companions: {
      ffprobe: ffprobeEntrypoint,
    },
    capabilities: ["post_processing"],
  }],
  components: [componentRecord],
  files,
  self_tests: [{
    engine_id: "ffmpeg",
    expected_version: component.version,
    timeout_seconds: 30,
  }],
});

if (hostTarget === options.target) {
  smoke(
    ffmpegTarget,
    ["-version"],
    (stdout) => stdout.includes(component.version),
    "ffmpeg",
  );
  smoke(
    ffprobeTarget,
    ["-version"],
    (stdout) => stdout.includes(component.version),
    "ffprobe",
  );
}

run(packager, ["package", template, payload, output]);
const archiveSize = (await stat(output)).size;
if (archiveSize > recipe.sizeBudget) {
  await rm(output, { force: true });
  fail(`${recipe.packId} exceeds its size budget: ${archiveSize} > ${recipe.sizeBudget}`);
}
const repeat = join(work, "repeat.zip");
run(packager, ["package", template, payload, repeat]);
const archiveHash = await sha256File(output);
if (archiveHash !== await sha256File(repeat)) {
  await rm(output, { force: true });
  fail(`${recipe.packId} packaging is not reproducible`);
}
await rm(repeat, { force: true });
console.log(JSON.stringify({
  pack: `${recipe.packId}@${recipe.version}`,
  target: options.target,
  size: archiveSize,
  sha256: archiveHash,
}));

async function resolveLicenseSourceRoot(cliOptions, workingDirectory) {
  const sourceDirectory = cliOptions["source-dir"];
  const sourceArchive = cliOptions["source-archive"];
  if (sourceDirectory) {
    const directory = resolve(sourceDirectory);
    const metadata = await stat(directory).catch(() => null);
    if (!metadata?.isDirectory()) fail("source-dir must be a directory");
    return directory;
  }
  if (!sourceArchive) {
    fail("either --source-dir or --source-archive is required for ffmpeg license extraction");
  }
  const archive = resolve(sourceArchive);
  const metadata = await stat(archive).catch(() => null);
  if (!metadata?.isFile()) fail("source-archive must be a file");
  const extractDirectory = join(workingDirectory, "source");
  run("tar", ["-xJf", archive, "--strip-components=1", "-C", extractDirectory]);
  return extractDirectory;
}

function spdxDocument(recipe, target, component) {
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `${recipe.packId}-${recipe.version}-${target}`,
    documentNamespace:
      `https://horexdev.github.io/free-media-downloader-updates/sbom/${recipe.packId}/${recipe.version}/${target}`,
    creationInfo: {
      created: new Date((recipe.sourceDateEpoch ?? 0) * 1000).toISOString().replace(".000", ""),
      creators: ["Organization: FMD contributors"],
    },
    packages: [{
      SPDXID: "SPDXRef-Package-ffmpeg",
      name: component.name,
      versionInfo: component.version,
      downloadLocation: component.source_url,
      filesAnalyzed: false,
      licenseConcluded: component.license_id,
      licenseDeclared: component.license_id,
      checksums: [{ algorithm: "SHA256", checksumValue: component.source_sha256 }],
    }],
    relationships: [{
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: "SPDXRef-Package-ffmpeg",
    }],
  };
}

function provenance(recipe, target, subjects, components) {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: subjects.map((subject) => ({
      name: subject.name,
      digest: { sha256: subject.sha256 },
    })),
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://github.com/horexdev/free-media-downloader/engine-pack/v1",
        externalParameters: {
          packId: recipe.packId,
          packVersion: recipe.version,
          target,
          sourceDateEpoch: recipe.sourceDateEpoch ?? 0,
        },
        internalParameters: {},
        resolvedDependencies: components.map((component) => ({
          uri: component.source_url,
          digest: { sha256: component.source_sha256 },
        })),
      },
      runDetails: {
        builder: { id: "https://github.com/horexdev/free-media-downloader/.github/workflows/engine-packs.yml" },
        metadata: { invocationId: `${recipe.packId}/${recipe.version}/${target}` },
      },
    },
  };
}

function manifestSourceComponent(component, source) {
  return {
    name: "ffmpeg",
    version: component.version,
    source_url: source.url,
    source_revision: component.commit ?? component.version,
    source_sha256: source.sha256,
    license_id: component.binaryLicense,
    original_sha256: source.sha256,
  };
}

function smoke(executable, args, accepts, label) {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    timeout: 30_000,
    env: smokeEnvironment(),
    windowsHide: true,
  });
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (result.status !== 0 || !accepts(output)) {
    const diagnostic = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trim();
    fail(`${label} smoke test failed${diagnostic ? `: ${diagnostic}` : ""}`);
  }
}

function smokeEnvironment() {
  const environment = { NO_COLOR: "1" };
  for (const variable of ["SystemRoot", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "SSL_CERT_FILE"]) {
    if (process.env[variable]) environment[variable] = process.env[variable];
  }
  return environment;
}

function run(command, commandArguments) {
  const result = spawnSync(command, commandArguments, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  if (result.status !== 0) {
    const diagnostic = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trim();
    fail(`${command} failed${diagnostic ? ": " + diagnostic : ""}`);
  }
}

async function writeJson(path, value) {
  await writeFile(path, JSON.stringify(value, null, 2) + "\n", {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

async function sha256File(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function requireAbsent(path, label) {
  try {
    await stat(path);
    fail(label + " already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

async function requireFile(path, label) {
  const metadata = await stat(path).catch(() => null);
  if (!metadata?.isFile()) fail(label + " is not a file");
}

function currentTarget() {
  const os = { darwin: "macos", win32: "windows", linux: "linux" }[process.platform];
  const architecture = { x64: "x64", arm64: "arm64" }[process.arch];
  return os && architecture ? `${os}-${architecture}` : null;
}

function isCompatibleTarget(host, target) {
  if (host === target) return true;
  if (!host) return false;
  const hostIsLinux = host === "linux-x64";
  const targetIsWindows = target.startsWith("windows-");
  return hostIsLinux && targetIsWindows;
}

function parseArguments(values) {
  if (values.length % 2 !== 0) fail("arguments must be --name value pairs");
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    if (!name.startsWith("--") || parsed[name.slice(2)] !== undefined) {
      fail("invalid argument: " + name);
    }
    parsed[name.slice(2)] = values[index + 1];
  }
  return parsed;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

async function collectFiles(root) {
  const result = [];
  for await (const entry of walkFiles(root, "")) {
    const absolutePath = join(root, entry);
    const metadata = await lstat(absolutePath);
    if (!metadata.isFile()) fail(`manifest collection allows regular files only: ${entry}`);
    const role = collectRole(entry);
    result.push({
      path: entry,
      size: metadata.size,
      sha256: await sha256File(absolutePath),
      role,
      executable: role === "executable",
    });
  }
  return result;
}

async function* walkFiles(root, relative) {
  const entries = await readdir(join(root, relative));
  entries.sort((left, right) => left.localeCompare(right));
  for (const entry of entries) {
    const entryPath = `${relative ? `${relative}/${entry}` : entry}`;
    const item = await lstat(join(root, entryPath));
    if (item.isDirectory()) {
      yield* walkFiles(root, entryPath);
    } else if (item.isFile()) {
      yield entryPath;
    } else {
      fail(`unsupported file type in ffmpeg payload: ${entryPath}`);
    }
  }
}

function collectRole(relativePath) {
  if (relativePath === ffmpegEntrypoint || relativePath === ffprobeEntrypoint) return "executable";
  if (relativePath.startsWith("LICENSES/")) return "license";
  return ["sources.json", "sbom.spdx.json", "provenance.intoto.jsonl", "manifest.json"]
    .includes(relativePath)
      ? "metadata"
      : "resource";
}
