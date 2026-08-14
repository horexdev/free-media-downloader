import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  rm,
  stat,
  readdir,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable, Transform } from "node:stream";
import { spawnSync } from "node:child_process";

const targets = new Set([
  "windows-x64",
  "windows-arm64",
  "macos-x64",
  "macos-arm64",
  "linux-x64",
  "linux-arm64",
]);
const allowedDownloadHosts = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "raw.githubusercontent.com",
]);
const maxDownloadBytes = 512 * 1024 * 1024;

const options = parseArguments(process.argv.slice(2));
for (const required of ["target", "work", "out", "packager", "aria2", "worker"]) {
  if (!options[required]) {
    fail("missing required argument: " + required);
  }
}
if (!targets.has(options.target)) {
  fail("unsupported target: " + options.target);
}
const hostTarget = currentTarget();
if (hostTarget !== options.target) {
  fail(`assembly must run on the selected target host (${options.target}), current is ${hostTarget ?? "unsupported"}`);
}

const lock = JSON.parse(await readFile(new URL("../../packs/source-lock.json", import.meta.url), "utf8"));
const recipe = JSON.parse(await readFile(
  new URL("../../packs/recipes/general-downloads.json", import.meta.url),
  "utf8",
));
const workspace = await readFile(new URL("../../Cargo.toml", import.meta.url), "utf8");
const workspaceVersion = extractWorkspaceVersion(workspace);
const work = resolve(options.work);
const output = resolve(options.out);
const packager = resolve(options.packager);
const aria2Source = resolve(options.aria2);
const workerSource = resolve(options.worker);

await requireAbsent(work, "work directory");
await requireAbsent(output, "output archive");
await requireFile(packager, "packager binary");
await requireFile(aria2Source, "aria2 binary");
await requireFile(workerSource, "fmd-curl-worker binary");
await mkdir(join(work, "payload", "bin"), { recursive: true, mode: 0o700 });
await mkdir(join(work, "payload", "LICENSES"), { recursive: true, mode: 0o700 });
await mkdir(dirname(output), { recursive: true });

const payload = join(work, "payload");
const suffix = options.target.startsWith("windows-") ? ".exe" : "";
const aria2 = lock.components.aria2;
const curl = lock.components.curl;
const componentNames = Array.from(new Set(recipe.components ?? [
  "aria2",
  "curl",
  "libssh2",
  "openssl",
  "nghttp2",
  "zlib",
]));

if (!aria2 || !curl) {
  fail("source lock must define aria2 and curl");
}

const aria2Entrypoint = `bin/aria2${suffix}`;
const workerEntrypoint = `bin/fmd-curl-worker${suffix}`;
const aria2TargetBinary = join(payload, aria2Entrypoint);
const workerTargetBinary = join(payload, workerEntrypoint);

await copyFile(aria2Source, aria2TargetBinary);
await copyFile(workerSource, workerTargetBinary);
if (!options.target.startsWith("windows-")) {
  await chmod(aria2TargetBinary, 0o755);
  await chmod(workerTargetBinary, 0o755);
}

const licenseFiles = new Set();
for (const componentName of componentNames) {
  const component = lock.components[componentName];
  if (!component) {
    fail(`component ${componentName} is missing in source lock`);
  }
  if (!component.license?.url || !component.license.sha256 || !component.binaryLicense) {
    fail(`component ${componentName} lacks locked license metadata`);
  }
  const filename = safeLicenseFile(componentName, component.binaryLicense);
  if (licenseFiles.has(filename)) continue;
  licenseFiles.add(filename);
  await fetchVerified(
    component.license.url,
    component.license.sha256,
    join(payload, "LICENSES", filename),
  );
}

const workerHello = smokeWorkerHello(workerTargetBinary);
const hasSftp = workerHello.capabilities.includes("sftp_hostkey_callback");
const shouldRequireSftp = parseBoolean(
  options["require-sftp"],
  recipe.requiresCurlWorkerFeature === "native-stack",
);
if (shouldRequireSftp && !hasSftp) {
  fail("fmd-curl-worker must expose sftp_hostkey_callback for requested general-downloads requirements");
}

const components = componentNames.map((name) => {
  const component = lock.components[name];
  const source = component.sourceDistribution ?? {
    url: component.sourceUrl ?? component.source,
    sha256: component.sha256,
  };
  if (!source?.url || !source.sha256) {
    fail(`component ${name} has no locked source artifact`);
  }
  return {
    name,
    version: component.version,
    source_url: source.url,
    source_revision: component.commit ?? component.baseCommit ?? component.version,
    source_sha256: source.sha256,
    license_id: component.binaryLicense,
    original_sha256: source.sha256,
  };
});

await writeJson(join(payload, "sources.json"), {
  schemaVersion: 1,
  packId: recipe.packId,
  packVersion: recipe.version,
  target: options.target,
  sourceDateEpoch: 0,
  components,
  worker: {
    name: "fmd-curl-worker",
    packageVersion: workspaceVersion || "0.1.0",
    binaryVersion: workspaceVersion || "0.1.0",
    sourceUrl: "https://github.com/horexdev/free-media-downloader/tree/main/crates/fmd-curl-worker",
  },
});

await writeJson(
  join(payload, "sbom.spdx.json"),
  spdxDocument(recipe, options.target, components),
);
await writeFile(
  join(payload, "provenance.intoto.jsonl"),
  JSON.stringify(
    provenance(
      recipe,
      options.target,
      [
        { name: aria2Entrypoint, sha256: await sha256File(aria2TargetBinary) },
        { name: workerEntrypoint, sha256: await sha256File(workerTargetBinary) },
      ],
      components,
    ),
  ) + "\n",
  { encoding: "utf8", flag: "wx", mode: 0o600 },
);
const files = await collectFiles(payload, new Set([aria2Entrypoint, workerEntrypoint]));

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
  engines: [
    {
      id: "aria2",
      version: aria2.version,
      adapter_id: "aria2_v1",
      adapter_api: 1,
      entrypoint: aria2Entrypoint,
      companions: {},
      capabilities: ["direct_http", "ftp", "metalink"],
    },
      {
        id: "fmd-curl-worker",
        version: workspaceVersion || "0.1.0",
        adapter_id: "curl_worker_v2",
        adapter_api: 1,
        entrypoint: workerEntrypoint,
        companions: {},
        capabilities: [
          "direct_http",
          "ftp",
          "metalink",
          ...(hasSftp ? ["sftp"] : []),
        ],
      },
  ],
  components,
  files,
  self_tests: [
    { engine_id: "aria2", expected_version: aria2.version, timeout_seconds: 20 },
    {
      engine_id: "fmd-curl-worker",
      expected_version: workspaceVersion || "0.1.0",
      timeout_seconds: 20,
    },
  ],
});

smoke(
  aria2TargetBinary,
  ["--version"],
  (text) => text.toLowerCase().includes("aria2"),
  "aria2 version",
);
smokeWorkerHello(workerTargetBinary);

run(packager, ["package", template, payload, output]);
const archiveSize = (await stat(output)).size;
if (archiveSize > recipe.sizeBudget) {
  await rm(output, { force: true });
  fail(`general-downloads exceeds size budget: ${archiveSize} > ${recipe.sizeBudget}`);
}
const repeat = join(work, "repeat.zip");
run(packager, ["package", template, payload, repeat]);
const archiveHash = await sha256File(output);
const repeatHash = await sha256File(repeat);
await rm(repeat, { force: true });
if (archiveHash !== repeatHash) {
  await rm(output, { force: true });
  fail("general-downloads packaging is not reproducible");
}

console.log(
  JSON.stringify({
    pack: recipe.packId + "@" + recipe.version,
    target: options.target,
    size: archiveSize,
    sha256: archiveHash,
  }),
);

function smokeWorkerHello(executable) {
  const result = spawnSync(executable, [], {
    encoding: "utf8",
    timeout: 10_000,
    env: smokeEnvironment(),
    windowsHide: true,
  });
  if (result.status !== 0) {
    fail("fmd-curl-worker failed to start");
  }
  const lines = `${result.stdout ?? ""}`.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const line = lines.find((value) => value.startsWith("{"));
  if (!line) {
    fail("fmd-curl-worker did not emit any JSON line");
  }
  let message;
  try {
    message = JSON.parse(line);
  } catch (_error) {
    fail("fmd-curl-worker hello output is not JSON");
  }
  const hello =
    message?.type === "hello"
      ? message
      : message?.Hello
        ? message.Hello
        : null;
  if (!hello) {
    fail("fmd-curl-worker did not emit hello message");
  }
  if (hello.protocol_version !== 2 || !hello.package_version) {
    fail("fmd-curl-worker hello payload is invalid");
  }
  return {
    protocolVersion: hello.protocol_version,
    packageVersion: hello.package_version,
    capabilities: hello.capabilities,
  };
}

function spdxDocument(recipeConfig, target, components) {
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `${recipeConfig.packId}-${recipeConfig.version}-${target}`,
    documentNamespace:
      `https://horexdev.github.io/free-media-downloader-updates/sbom/${recipeConfig.packId}/${recipeConfig.version}/${target}`,
    creationInfo: {
      created: new Date(0).toISOString(),
      creators: ["Organization: FMD contributors"],
    },
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
    relationships: components.map((_, index) => ({
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: `SPDXRef-Package-${index}`,
    })),
  };
}

function provenance(recipeConfig, target, subjects, components) {
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
          packId: recipeConfig.packId,
          packVersion: recipeConfig.version,
          target,
        },
        internalParameters: {},
        resolvedDependencies: components.map((component) => ({
          uri: component.source_url,
          digest: { sha256: component.source_sha256 },
        })),
      },
      runDetails: {
        builder: { id: "https://github.com/horexdev/free-media-downloader/.github/workflows/engine-packs.yml" },
        metadata: { invocationId: `${recipeConfig.packId}/${recipeConfig.version}/${target}` },
      },
    },
  };
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

function parseBoolean(value, defaultValue) {
  if (value === undefined) return defaultValue;
  if (typeof value === "boolean") return value;
  const normalized = `${value}`.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  fail("invalid boolean argument: " + value);
}

async function fetchVerified(url, expectedHash, destination) {
  if (!url.startsWith("https://") || !/^[0-9a-f]{64}$/.test(expectedHash)) {
    fail("download is not fully locked");
  }
  let current = new URL(url);
  let response;
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    if (current.protocol !== "https:" || !allowedDownloadHosts.has(current.hostname)) {
      fail("download origin is not allowlisted: " + current.origin);
    }
    response = await fetch(current, { redirect: "manual" });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) fail("download redirect is missing target");
      current = new URL(location, current);
      continue;
    }
    if (!response.ok || !response.body) {
      fail("download failed with status " + response.status);
    }
    break;
  }
  if (!response) fail("download failed");
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxDownloadBytes) fail("download is too large");
  const hash = createHash("sha256");
  let received = 0;
  const meter = new Transform({
    transform(chunk, _encoding, callback) {
      received += chunk.length;
      if (received > maxDownloadBytes) {
        callback(new Error("download is too large"));
        return;
      }
      hash.update(chunk);
      callback(null, chunk);
    },
  });
  try {
    await pipeline(
      Readable.fromWeb(response.body),
      meter,
      createWriteStream(destination, { flags: "wx", mode: 0o600 }),
    );
    const actual = hash.digest("hex");
    if (actual !== expectedHash) throw new Error("download digest mismatch: " + url);
  } catch (error) {
    await rm(destination, { force: true });
    fail(error instanceof Error ? error.message : String(error));
  }
}

function smoke(executable, args, accepts, label) {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    env: smokeEnvironment(),
    timeout: 30_000,
    windowsHide: true,
  });
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (result.status !== 0 || !accepts(output)) {
    fail(`${label} smoke test failed`);
  }
}

function smokeEnvironment() {
  const environment = { NO_COLOR: "1" };
  for (const variable of ["SystemRoot", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE"]) {
    if (process.env[variable]) environment[variable] = process.env[variable];
  }
  return environment;
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

function extractWorkspaceVersion(cargoText) {
  const workspaceMatch = cargoText.match(
    /\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m,
  );
  return workspaceMatch?.[1] ?? null;
}

function currentTarget() {
  const os = { win32: "windows", darwin: "macos", linux: "linux" }[process.platform];
  const architecture = { x64: "x64", arm64: "arm64" }[process.arch];
  return os && architecture ? `${os}-${architecture}` : null;
}

function safeLicenseFile(name, licenseId) {
  const safeName = name.replace(/[^A-Za-z0-9._-]/g, "-");
  const safeLicense = licenseId.replace(/[^A-Za-z0-9._-]/g, "-");
  return `${safeName}-${safeLicense}.txt`;
}

function run(command, commandArguments) {
  const result = spawnSync(command, commandArguments, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  if (result.status !== 0) {
    const diagnostic = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trim();
    fail(`${basename(command)} failed${diagnostic ? ": " + diagnostic : ""}`);
  }
}

async function writeJson(path, value) {
  await writeFile(
    path,
    JSON.stringify(value, null, 2) + "\n",
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
}

async function sha256File(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

async function collectFiles(root, executableFiles) {
  const result = [];
  for await (const entry of walkFiles(root, "")) {
    const absolutePath = join(root, entry);
    const metadata = await lstat(absolutePath);
    if (!metadata.isFile()) fail(`manifest collection allows regular files only: ${entry}`);
    const role = collectRole(entry, executableFiles);
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
      fail(`unsupported file type in general-downloads payload: ${entryPath}`);
    }
  }
}

function collectRole(relativePath, executableFiles) {
  if (executableFiles.has(relativePath)) return "executable";
  if (relativePath.startsWith("LICENSES/")) return "license";
  return ["sources.json", "sbom.spdx.json", "provenance.intoto.jsonl", "manifest.json"].includes(relativePath)
    ? "metadata"
    : "resource";
}
