import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readFile, rm, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { spawnSync } from "node:child_process";

const maximumInputBytes = 64 * 1024 * 1024;
const allowedHosts = new Set([
  "ffmpeg.org", "www.ffmpeg.org", "github.com", "objects.githubusercontent.com",
  "release-assets.githubusercontent.com", "mirror.openssl-library.org",
]);
const options = parseArguments(process.argv.slice(2));
if (!options.work) fail("missing --work");
const transport = options.transport ?? "fetch";
if (!new Set(["fetch", "curl"]).has(transport)) fail("unsupported source transport");
const work = resolve(options.work);
await requireAbsent(work);
await mkdir(work, { recursive: true, mode: 0o700 });

const lock = JSON.parse(await readFile(new URL("../../packs/source-lock.json", import.meta.url), "utf8"));
const componentId = options.component ?? "ffmpeg";
if (!new Set(["ffmpeg", "openssl"]).has(componentId)) fail("unsupported source component");
const component = lock.components[componentId];
const verification = component.releaseVerification;
const source = join(work, basename(new URL(component.sourceDistribution.url).pathname));
const signature = source + ".asc";
const publicKey = join(work, "ffmpeg-release.asc");

await download(component.sourceDistribution, source);
await download(verification.signature, signature);
await download(verification.publicKey, publicKey);

const gpgHome = join(work, "gpg");
await mkdir(gpgHome, { mode: 0o700 });
const gpg = options.gpg ?? "gpg";
run(gpg, [
  "--batch", "--no-autostart", "--homedir", toolPath(gpgHome), "--import", toolPath(publicKey),
]);
const fingerprints = runOutput(gpg, [
  "--batch", "--no-autostart", "--homedir", toolPath(gpgHome), "--with-colons", "--fingerprint",
]).split(/\r?\n/)
  .filter((line) => line.startsWith("fpr:"))
  .map((line) => line.split(":")[9]);
if (!fingerprints.includes(verification.publicKey.fingerprint)) {
  fail(componentId + " release key fingerprint does not match the source lock");
}
run(gpg, [
  "--batch", "--no-autostart", "--homedir", toolPath(gpgHome), "--verify",
  toolPath(signature), toolPath(source),
]);

console.log(JSON.stringify({
  component: componentId + "@" + component.version,
  source,
  size: (await stat(source)).size,
  sha256: component.sourceDistribution.sha256,
  signer: verification.publicKey.fingerprint,
}));

async function download(input, destination) {
  if (!input?.url?.startsWith("https://") || !/^[0-9a-f]{64}$/.test(input.sha256)) {
    fail("source input is not fully locked");
  }
  if (transport === "curl") {
    await downloadWithCurl(input, destination);
    return;
  }
  let response;
  try {
    response = await fetchWithRetries(input.url);
  } catch (error) {
    const hostname = new URL(input.url).hostname;
    if (!new Set(["ffmpeg.org", "www.ffmpeg.org"]).has(hostname)) throw error;
    console.error("fetch transport failed for " + hostname + "; retrying with curl");
    await downloadWithCurl(input, destination);
    return;
  }
  if (!response.ok || !response.body) fail("download failed with HTTP " + response.status);
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maximumInputBytes) fail("source input is too large");
  let received = 0;
  const digest = createHash("sha256");
  const meter = new Transform({
    transform(chunk, _encoding, callback) {
      received += chunk.length;
      if (received > maximumInputBytes) return callback(new Error("source input is too large"));
      digest.update(chunk);
      callback(null, chunk);
    },
  });
  try {
    await pipeline(
      Readable.fromWeb(response.body),
      meter,
      createWriteStream(destination, { flags: "wx", mode: 0o600 }),
    );
    if (digest.digest("hex") !== input.sha256) throw new Error("source input digest mismatch");
  } catch (error) {
    await rm(destination, { force: true });
    fail(error instanceof Error ? error.message : String(error));
  }
}

async function fetchWithRetries(input) {
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      return await fetchWithPolicy(input);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error("source download failed");
}

async function downloadWithCurl(input, destination) {
  const origin = new URL(input.url);
  if (origin.protocol !== "https:" ||
      !new Set(["ffmpeg.org", "www.ffmpeg.org"]).has(origin.hostname)) {
    fail("curl fallback is restricted to the FFmpeg source origin");
  }
  const curl = options.curl ?? "curl";
  const result = spawnSync(curl, [
    "--fail", "--silent", "--show-error",
    "--proto", "=https", "--proto-redir", "=https",
    "--max-redirs", "0", "--tlsv1.2",
    "--connect-timeout", "20", "--max-time", "300",
    "--retry", "5", "--retry-delay", "1", "--retry-all-errors",
    "--max-filesize", String(maximumInputBytes),
    "--output", destination,
    "--url", input.url,
  ], {
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  });
  if (result.status !== 0) {
    await rm(destination, { force: true });
    const diagnostic = (result.stderr ?? "").trim();
    fail("curl source download failed" + (diagnostic ? ": " + diagnostic : ""));
  }
  const metadata = await stat(destination).catch(() => null);
  if (!metadata?.isFile() || metadata.size > maximumInputBytes) {
    await rm(destination, { force: true });
    fail("curl source input is missing or too large");
  }
  if (await sha256File(destination) !== input.sha256) {
    await rm(destination, { force: true });
    fail("curl source input digest mismatch");
  }
}

async function sha256File(path) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest("hex");
}

async function fetchWithPolicy(input) {
  let current = new URL(input);
  for (let redirects = 0; redirects <= 3; redirects += 1) {
    if (current.protocol !== "https:" || !allowedHosts.has(current.hostname)) {
      fail("source origin is not allowlisted: " + current.origin);
    }
    const response = await fetch(current, { redirect: "manual" });
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get("location");
    if (!location) fail("source redirect is missing a location");
    current = new URL(location, current);
  }
  fail("source download exceeded the redirect limit");
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8", windowsHide: true });
  if (result.status !== 0) {
    const diagnostic = ((result.stdout ?? "") + "\n" + (result.stderr ?? "")).trim();
    fail(basename(command) + " failed" + (diagnostic ? ": " + diagnostic : ""));
  }
}

function runOutput(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8", windowsHide: true });
  if (result.status !== 0) fail(basename(command) + " failed");
  return result.stdout;
}

function toolPath(path) {
  const absolute = resolve(path).replaceAll("\\", "/");
  return process.platform === "win32"
    ? absolute.replace(/^([A-Za-z]):/, (_match, drive) => "/" + drive.toLowerCase())
    : absolute;
}

function parseArguments(values) {
  if (values.length % 2 !== 0) fail("arguments must be --name value pairs");
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    if (!key.startsWith("--") || parsed[key.slice(2)] !== undefined) fail("invalid argument: " + key);
    parsed[key.slice(2)] = values[index + 1];
  }
  return parsed;
}

async function requireAbsent(path) {
  try {
    await stat(path);
    fail("work directory already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
