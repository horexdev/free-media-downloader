import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { chmod, copyFile, lstat, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable, Transform } from "node:stream";
import { spawnSync } from "node:child_process";

const targets = new Set([
  "windows-x64", "windows-arm64", "macos-x64",
  "macos-arm64", "linux-x64", "linux-arm64",
]);
const downloadHosts = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
  "raw.githubusercontent.com",
  "keys.openpgp.org",
]);
const maxDownloadBytes = 512 * 1024 * 1024;
const options = parseArguments(process.argv.slice(2));
for (const required of ["target", "work", "out", "packager"]) {
  if (!options[required]) fail("missing --" + required);
}
if (!targets.has(options.target)) fail("unsupported target: " + options.target);
const hostTarget = currentTarget();
if (hostTarget !== options.target) {
  fail("native assembly requires " + options.target + ", current host is " + (hostTarget ?? "unsupported"));
}

const lock = JSON.parse(await readFile(new URL("../../packs/source-lock.json", import.meta.url), "utf8"));
const recipe = JSON.parse(await readFile(new URL("../../packs/recipes/video-core.json", import.meta.url), "utf8"));
const work = resolve(options.work);
const output = resolve(options.out);
const packager = resolve(options.packager);
await requireAbsent(work, "work directory");
await requireAbsent(output, "output archive");
await requireFile(packager, "packager");
await mkdir(join(work, "downloads"), { recursive: true, mode: 0o700 });
await mkdir(join(work, "payload", "bin"), { recursive: true, mode: 0o700 });
await mkdir(join(work, "payload", "LICENSES"), { recursive: true, mode: 0o700 });
await mkdir(dirname(output), { recursive: true });

const payload = join(work, "payload");
const ytDlp = lock.components["yt-dlp"];
const ejs = lock.components["yt-dlp-ejs"];
const deno = lock.components.deno;
const ytAsset = requireAsset(ytDlp, options.target);
const denoAsset = requireAsset(deno, options.target);
const suffix = options.target.startsWith("windows-") ? ".exe" : "";
const ytEntrypoint = "bin/yt-dlp" + suffix;
const denoEntrypoint = "bin/deno" + suffix;
const ytDownload = join(work, "downloads", "yt-dlp" + suffix);
const denoArchive = join(work, "downloads", "deno.zip");
const checksumManifest = join(work, "downloads", "SHA2-256SUMS");
const checksumSignature = join(work, "downloads", "SHA2-256SUMS.sig");
const publicKey = join(work, "downloads", "yt-dlp-public.key");

await fetchVerified(ytAsset.url, ytAsset.sha256, ytDownload);
await fetchVerified(denoAsset.url, denoAsset.sha256, denoArchive);
await verifyDenoChecksum(denoAsset, work);
await verifyYtDlpRelease(
  ytDlp,
  basename(new URL(ytAsset.url).pathname),
  checksumManifest,
  checksumSignature,
  publicKey,
  work,
  options.gpg ?? "gpg",
);
await copyFile(ytDownload, join(payload, ytEntrypoint));
run(packager, ["extract-zip-entry", denoArchive, "deno" + suffix, join(payload, denoEntrypoint)]);
if (!options.target.startsWith("windows-")) {
  await chmod(join(payload, ytEntrypoint), 0o755);
  await chmod(join(payload, denoEntrypoint), 0o755);
}

await fetchVerified(
  ytDlp.license.url,
  ytDlp.license.sha256,
  join(payload, "LICENSES", "yt-dlp-Unlicense.txt"),
);
await fetchVerified(
  deno.license.url,
  deno.license.sha256,
  join(payload, "LICENSES", "deno-MIT.txt"),
);
await fetchVerified(
  ejs.license.url,
  ejs.license.sha256,
  join(payload, "LICENSES", "yt-dlp-ejs-Unlicense.txt"),
);
const gpl = lock.licenseTexts["GPL-3.0-or-later"];
await fetchVerified(
  gpl.url,
  gpl.sha256,
  join(payload, "LICENSES", "GPL-3.0-or-later.txt"),
);

const binarySubjects = [
  { name: ytEntrypoint, sha256: await sha256File(join(payload, ytEntrypoint)) },
  { name: denoEntrypoint, sha256: await sha256File(join(payload, denoEntrypoint)) },
];
await writeJson(join(payload, "sources.json"), {
  schemaVersion: 1,
  packId: recipe.packId,
  packVersion: recipe.version,
  target: options.target,
  sourceDateEpoch: recipe.sourceDateEpoch,
  components: [
    {
      name: "yt-dlp",
      version: ytDlp.version,
      artifact: ytAsset,
      correspondingSource: ytDlp.sourceDistribution,
      releaseVerification: ytDlp.releaseVerification,
      binaryLicense: ytDlp.binaryLicense,
    },
    {
      name: "yt-dlp-ejs",
      version: ejs.version,
      source: ejs.sourceDistribution,
      sourceRevision: ejs.commit,
      embeddedIn: ejs.embeddedIn,
      binaryLicense: ejs.binaryLicense,
    },
    {
      name: "deno",
      version: deno.version,
      artifact: denoAsset,
      binaryLicense: deno.binaryLicense,
    },
  ],
});
await writeJson(
  join(payload, "sbom.spdx.json"),
  spdxDocument(recipe, options.target, ytDlp, ytAsset, ejs, deno, denoAsset),
);
await writeFile(
  join(payload, "provenance.intoto.jsonl"),
  JSON.stringify(provenance(recipe, options.target, binarySubjects, ytAsset, ejs, denoAsset)) + "\n",
  { encoding: "utf8", flag: "wx", mode: 0o600 },
);
const files = await collectFiles(payload, new Set([ytEntrypoint, denoEntrypoint]));

const template = join(work, "manifest-template.json");
await writeJson(template, {
  schema_version: 1,
  id: recipe.packId,
  version: recipe.version,
  target: options.target,
  core_api_min: 1,
  core_api_max: 1,
  security_sequence: 1,
  dependencies: recipe.dependencies.map((dependency) => ({
    pack_id: dependency.packId,
    version_req: dependency.version,
    required: dependency.required,
  })),
  engines: [{
    id: "yt-dlp",
    version: ytDlp.version,
    adapter_id: "yt_dlp_v1",
    adapter_api: 1,
    entrypoint: ytEntrypoint,
    companions: { deno: denoEntrypoint },
    capabilities: ["site_extraction", "hls", "dash"],
  }],
  components: [
    manifestComponent("yt-dlp", ytDlp, ytAsset),
    manifestSourceComponent("yt-dlp-ejs", ejs),
    manifestComponent("deno", deno, denoAsset),
  ],
  files,
  self_tests: [{
    engine_id: "yt-dlp",
    expected_version: ytDlp.version,
    timeout_seconds: 15,
  }],
});

smoke(
  join(payload, ytEntrypoint),
  ["--ignore-config", "--no-plugin-dirs", "--version"],
  (stdout) => stdout.trim() === ytDlp.version,
  "yt-dlp version",
);
smoke(
  join(payload, denoEntrypoint),
  ["--version"],
  (stdout) => stdout.split(/\r?\n/, 1)[0].startsWith("deno " + deno.version + " "),
  "Deno version",
);

run(packager, ["package", template, payload, output]);
const archiveSize = (await stat(output)).size;
if (archiveSize > recipe.sizeBudget) {
  await rm(output, { force: true });
  fail("video-core archive exceeds its size budget: " + archiveSize + " > " + recipe.sizeBudget);
}
const repeat = join(work, "repeat.zip");
run(packager, ["package", template, payload, repeat]);
const archiveHash = await sha256File(output);
const repeatHash = await sha256File(repeat);
await rm(repeat, { force: true });
if (archiveHash !== repeatHash) {
  await rm(output, { force: true });
  fail("video-core packaging is not reproducible");
}
console.log(JSON.stringify({
  pack: recipe.packId + "@" + recipe.version,
  target: options.target,
  archive: output,
  size: archiveSize,
  sha256: archiveHash,
}));

async function verifyYtDlpRelease(
  component,
  assetName,
  manifestPath,
  signaturePath,
  keyPath,
  root,
  gpg,
) {
  const verification = component.releaseVerification;
  await fetchVerified(
    verification.checksumManifest.url,
    verification.checksumManifest.sha256,
    manifestPath,
  );
  await fetchVerified(
    verification.signature.url,
    verification.signature.sha256,
    signaturePath,
  );
  await fetchVerified(
    verification.publicKey.url,
    verification.publicKey.sha256,
    keyPath,
  );
  const manifest = await readFile(manifestPath, "utf8");
  const line = manifest.split(/\r?\n/).find((candidate) => candidate.trim().endsWith("  " + assetName));
  if (!line || line.slice(0, 64).toLowerCase() !== component.assets[options.target].sha256) {
    fail("yt-dlp checksum manifest does not authorize the selected artifact");
  }
  const home = join(root, "gpg");
  await mkdir(home, { mode: 0o700 });
  const gpgHome = signatureToolPath(home);
  const gpgKey = signatureToolPath(keyPath);
  const gpgSignature = signatureToolPath(signaturePath);
  const gpgManifest = signatureToolPath(manifestPath);
  run(gpg, ["--batch", "--homedir", gpgHome, "--import", gpgKey]);
  const fingerprint = runOutput(gpg, [
    "--batch", "--homedir", gpgHome, "--with-colons", "--fingerprint",
  ]).split(/\r?\n/).find((candidate) => candidate.startsWith("fpr:"))?.split(":")[9];
  if (fingerprint !== verification.publicKey.fingerprint) {
    fail("yt-dlp signing key fingerprint does not match the source lock");
  }
  run(gpg, [
    "--batch", "--homedir", gpgHome, "--verify", gpgSignature, gpgManifest,
  ]);
}

function signatureToolPath(path) {
  const absolute = resolve(path).replaceAll("\\", "/");
  return process.platform === "win32"
    ? absolute.replace(/^([A-Za-z]):/, (_match, drive) => "/" + drive.toLowerCase())
    : absolute;
}

async function verifyDenoChecksum(asset, root) {
  if (!asset.checksumUrl || !asset.checksumSha256) fail("Deno checksum sidecar is not locked");
  const sidecar = join(root, "downloads", "deno.sha256sum");
  await fetchVerified(asset.checksumUrl, asset.checksumSha256, sidecar);
  const checksum = await readFile(sidecar, "utf8");
  const declared = checksum.match(/[0-9a-fA-F]{64}/)?.[0]?.toLowerCase();
  if (declared !== asset.sha256) fail("Deno checksum sidecar does not match the source lock");
}

function spdxDocument(recipe, target, ytDlp, ytAsset, ejs, deno, denoAsset) {
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: recipe.packId + "-" + recipe.version + "-" + target,
    documentNamespace:
      "https://horexdev.github.io/free-media-downloader-updates/sbom/" +
      recipe.packId + "/" + recipe.version + "/" + target,
    creationInfo: {
      created: new Date(recipe.sourceDateEpoch * 1000).toISOString().replace(".000", ""),
      creators: ["Organization: FMD contributors"],
    },
    packages: [
      spdxPackage("SPDXRef-Package-yt-dlp", "yt-dlp", ytDlp, ytAsset),
      spdxPackage(
        "SPDXRef-Package-yt-dlp-ejs",
        "yt-dlp-ejs",
        ejs,
        ejs.sourceDistribution,
      ),
      spdxPackage("SPDXRef-Package-deno", "deno", deno, denoAsset),
    ],
    relationships: [
      {
        spdxElementId: "SPDXRef-DOCUMENT",
        relationshipType: "DESCRIBES",
        relatedSpdxElement: "SPDXRef-Package-yt-dlp",
      },
      {
        spdxElementId: "SPDXRef-DOCUMENT",
        relationshipType: "DESCRIBES",
        relatedSpdxElement: "SPDXRef-Package-yt-dlp-ejs",
      },
      {
        spdxElementId: "SPDXRef-DOCUMENT",
        relationshipType: "DESCRIBES",
        relatedSpdxElement: "SPDXRef-Package-deno",
      },
    ],
  };
}

function spdxPackage(id, name, component, asset) {
  return {
    SPDXID: id,
    name,
    versionInfo: component.version,
    downloadLocation: asset.url,
    filesAnalyzed: false,
    licenseConcluded: component.binaryLicense,
    licenseDeclared: component.binaryLicense,
    checksums: [{ algorithm: "SHA256", checksumValue: asset.sha256 }],
  };
}

function provenance(recipe, target, subjects, ytAsset, ejs, denoAsset) {
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
          sourceDateEpoch: recipe.sourceDateEpoch,
        },
        internalParameters: {},
        resolvedDependencies: [ytAsset, ejs.sourceDistribution, denoAsset].map((asset) => ({
          uri: asset.url,
          digest: { sha256: asset.sha256 },
        })),
      },
      runDetails: {
        builder: {
          id: "https://github.com/horexdev/free-media-downloader/.github/workflows/engine-packs.yml",
        },
        metadata: { invocationId: recipe.packId + "/" + recipe.version + "/" + target },
      },
    },
  };
}

function manifestComponent(name, component, asset) {
  return {
    name,
    version: component.version,
    source_url: asset.url,
    source_revision: component.version,
    source_sha256: asset.sha256,
    license_id: component.binaryLicense,
    original_sha256: asset.sha256,
  };
}

function manifestSourceComponent(name, component) {
  return {
    name,
    version: component.version,
    source_url: component.sourceDistribution.url,
    source_revision: component.commit,
    source_sha256: component.sourceDistribution.sha256,
    license_id: component.binaryLicense,
    original_sha256: null,
  };
}

async function fetchVerified(url, expectedHash, destination) {
  if (!url.startsWith("https://") || !/^[0-9a-f]{64}$/.test(expectedHash)) {
    fail("download is not fully locked");
  }
  const response = await fetchWithPolicy(url);
  if (!response.ok || !response.body) fail("download failed with HTTP " + response.status);
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxDownloadBytes) {
    fail("download exceeds the input size limit");
  }
  const hash = createHash("sha256");
  let received = 0;
  const meter = new Transform({
    transform(chunk, _encoding, callback) {
      received += chunk.length;
      if (received > maxDownloadBytes) {
        callback(new Error("download exceeds the input size limit"));
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
    if (actual !== expectedHash) throw new Error("digest mismatch for " + url);
  } catch (error) {
    await rm(destination, { force: true });
    fail(error instanceof Error ? error.message : String(error));
  }
}

async function fetchWithPolicy(input) {
  let current = new URL(input);
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    if (current.protocol !== "https:" || !downloadHosts.has(current.hostname)) {
      fail("download origin is not allowlisted: " + current.origin);
    }
    const response = await fetch(current, { redirect: "manual" });
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get("location");
    if (!location) fail("download redirect is missing a location");
    current = new URL(location, current);
  }
  fail("download exceeded the redirect limit");
}

function smoke(executable, commandArguments, accepts, label) {
  const result = spawnSync(executable, commandArguments, {
    encoding: "utf8",
    env: smokeEnvironment(),
    timeout: 30_000,
    windowsHide: true,
  });
  if (result.status !== 0 || !accepts(result.stdout ?? "")) {
    fail(label + " smoke test failed");
  }
}

function smokeEnvironment() {
  const environment = {};
  for (const name of [
    "SystemRoot", "WINDIR", "TEMP", "TMP", "HOME",
    "USERPROFILE", "SSL_CERT_FILE",
  ]) {
    if (process.env[name]) environment[name] = process.env[name];
  }
  environment.NO_COLOR = "1";
  return environment;
}

function requireAsset(component, target) {
  const asset = component?.assets?.[target];
  if (!asset?.url || !asset?.sha256) fail("component is not locked for " + target);
  return asset;
}

function run(command, commandArguments) {
  const result = spawnSync(command, commandArguments, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  if (result.status !== 0) {
    const diagnostic = ((result.stdout ?? "") + "\n" + (result.stderr ?? "")).trim();
    fail(basename(command) + " failed" + (diagnostic ? ": " + diagnostic : ""));
  }
}

function runOutput(command, commandArguments) {
  const result = spawnSync(command, commandArguments, { encoding: "utf8", windowsHide: true });
  if (result.status !== 0) fail(basename(command) + " failed");
  return result.stdout;
}

async function writeJson(path, value) {
  await writeFile(path, JSON.stringify(value, null, 2) + "\n", {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

async function sha256File(path) {
  const bytes = await readFile(path);
  return createHash("sha256").update(bytes).digest("hex");
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
  const os = { win32: "windows", darwin: "macos", linux: "linux" }[process.platform];
  const architecture = { x64: "x64", arm64: "arm64" }[process.arch];
  return os && architecture ? os + "-" + architecture : null;
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
      fail(`unsupported file type in video-core payload: ${entryPath}`);
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
