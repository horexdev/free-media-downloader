import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";

const options = parseArguments(process.argv.slice(2));
for (const required of [
  "feed", "root", "assets", "out", "release-base-url", "release-version",
  "targets-key", "snapshot-key", "timestamp-key",
]) {
  if (!options[required]) fail(`required: --${required}`);
}
if (!new Set(["core", "engines"]).has(options.feed)) fail("feed must be core or engines");
if (!/^https:\/\/github\.com\/horexdev\/free-media-downloader\/releases\/download\//.test(options["release-base-url"])) {
  fail("release base URL is outside the authorized GitHub Releases origin");
}

const rootPath = resolve(options.root);
const assetsDir = resolve(options.assets);
const feedOut = resolve(options.out, options.feed);
const metadataOut = resolve(feedOut, "metadata");
const targetsOut = resolve(feedOut, "targets");
mkdirSync(metadataOut, { recursive: true });
mkdirSync(targetsOut, { recursive: true });

const root = JSON.parse(readFileSync(rootPath, "utf8"));
if (root?.signed?._type !== "root" || root.signed.consistent_snapshot !== true) {
  fail("trusted root is not a consistent-snapshot TUF root");
}
const keys = {
  targets: loadRoleKey(root, "targets", options["targets-key"]),
  snapshot: loadRoleKey(root, "snapshot", options["snapshot-key"]),
  timestamp: loadRoleKey(root, "timestamp", options["timestamp-key"]),
};

const previousTargets = readVersion(resolve(metadataOut, "targets.json"));
const previousSnapshot = readVersion(resolve(metadataOut, "snapshot.json"));
const previousTimestamp = readVersion(resolve(metadataOut, "timestamp.json"));
const versions = {
  targets: previousTargets + 1,
  snapshot: previousSnapshot + 1,
  timestamp: previousTimestamp + 1,
};
const securitySequence = Number(options["security-sequence"] || versions.targets);
if (!Number.isSafeInteger(securitySequence) || securitySequence < 1) fail("invalid security sequence");

const descriptors = buildDescriptors();
const targetEntries = {};
for (const descriptor of descriptors) {
  const bytes = Buffer.from(`${JSON.stringify(descriptor.body, null, 2)}\n`);
  const digest = sha256(bytes);
  const name = descriptor.body.target_name;
  writeFileSync(resolve(targetsOut, `${digest}.${name}`), bytes);
  writeFileSync(resolve(targetsOut, name), bytes);
  targetEntries[name] = {
    length: bytes.length,
    hashes: { sha256: digest },
    custom: descriptor.custom,
  };
}

const targets = signedEnvelope("targets", versions.targets, expiresInDays(30), {
  targets: targetEntries,
}, keys.targets);
const targetsBytes = writeMetadata("targets", versions.targets, targets);
const snapshot = signedEnvelope("snapshot", versions.snapshot, expiresInDays(14), {
  meta: {
    "targets.json": fileMeta(versions.targets, targetsBytes),
  },
}, keys.snapshot);
const snapshotBytes = writeMetadata("snapshot", versions.snapshot, snapshot);
const timestamp = signedEnvelope("timestamp", versions.timestamp, expiresInDays(2), {
  meta: {
    "snapshot.json": fileMeta(versions.snapshot, snapshotBytes),
  },
}, keys.timestamp);
writeFileSync(resolve(metadataOut, "timestamp.json"), serialize(timestamp));
copyFileSync(rootPath, resolve(metadataOut, `${root.signed.version}.root.json`));
copyFileSync(rootPath, resolve(metadataOut, "root.json"));

console.log(JSON.stringify({
  feed: options.feed,
  descriptors: descriptors.length,
  versions,
  securitySequence,
  rootSha256: sha256(readFileSync(rootPath)),
}, null, 2));

function buildDescriptors() {
  const files = readdirSync(assetsDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();
  if (options.feed === "core") {
    const patterns = [
      [/^FMD-(windows-(?:x64|arm64))-update\.zip$/, "zip"],
      [/^FMD-(macos-(?:x64|arm64))\.app\.zip$/, "zip"],
      [/^FMD-(linux-(?:x64|arm64))\.AppImage$/, "appimage"],
    ];
    return files.flatMap((file) => {
      const match = patterns.map(([pattern, kind]) => ({ match: file.match(pattern), kind }))
        .find((candidate) => candidate.match);
      if (!match) return [];
      return [descriptorFor(file, "core", match.match[1], null, options["release-version"], match.kind)];
    });
  }
  return files.flatMap((file) => {
    const match = file.match(/^(.+)-(windows-(?:x64|arm64)|macos-(?:x64|arm64)|linux-(?:x64|arm64))\.zip$/);
    if (!match) return [];
    const packId = match[1];
    const recipePath = resolve("packs", "recipes", `${packId}.json`);
    if (!existsSync(recipePath)) fail(`missing recipe for engine pack ${packId}`);
    const recipe = JSON.parse(readFileSync(recipePath, "utf8"));
    if (recipe.packId !== packId || typeof recipe.version !== "string") fail(`invalid recipe for ${packId}`);
    return [descriptorFor(file, "engine_pack", match[2], packId, recipe.version, "zip")];
  });
}

function descriptorFor(file, component, target, packId, version, artifactKind) {
  const artifact = readFileSync(resolve(assetsDir, file));
  const targetName = component === "core" ? `core-${target}.json` : `${packId}-${target}.json`;
  const body = {
    schema_version: 1,
    target_name: targetName,
    component,
    version,
    target,
    security_sequence: securitySequence,
    ...(packId ? { pack_id: packId } : {}),
    artifact_url: `${options["release-base-url"].replace(/\/$/, "")}/${encodeURIComponent(file)}`,
    artifact_length: artifact.length,
    artifact_sha256: sha256(artifact),
    unsigned: true,
  };
  return {
    body,
    custom: {
      component,
      version,
      target,
      security_sequence: securitySequence,
      artifact_kind: artifactKind,
      ...(packId ? { pack_id: packId } : {}),
    },
  };
}

function signedEnvelope(type, version, expires, fields, roleKey) {
  const signed = { _type: type, spec_version: "1.0", version, expires, ...fields };
  const signature = sign(null, Buffer.from(canonical(signed)), roleKey.privateKey).toString("hex");
  return { signatures: [{ keyid: roleKey.keyid, sig: signature }], signed };
}

function writeMetadata(role, version, value) {
  const bytes = serialize(value);
  writeFileSync(resolve(metadataOut, `${version}.${role}.json`), bytes);
  writeFileSync(resolve(metadataOut, `${role}.json`), bytes);
  return bytes;
}

function loadRoleKey(rootDocument, role, path) {
  const keyids = rootDocument.signed.roles?.[role]?.keyids;
  if (!Array.isArray(keyids) || keyids.length !== 1) fail(`${role} must have exactly one key for beta`);
  const privateKey = createPrivateKey(readFileSync(resolve(path), "utf8"));
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const value = { keytype: "ed25519", scheme: "ed25519", keyval: { public: publicDer.subarray(-32).toString("hex") } };
  const keyid = sha256(Buffer.from(canonical(value)));
  if (keyid !== keyids[0] || canonical(rootDocument.signed.keys[keyid]) !== canonical(value)) {
    fail(`${role} signing key does not match the trusted root`);
  }
  return { keyid, privateKey };
}

function fileMeta(version, bytes) {
  return { version, length: bytes.length, hashes: { sha256: sha256(bytes) } };
}

function readVersion(path) {
  if (!existsSync(path)) return 0;
  const version = JSON.parse(readFileSync(path, "utf8"))?.signed?.version;
  if (!Number.isSafeInteger(version) || version < 1) fail(`invalid existing metadata: ${path}`);
  return version;
}

function expiresInDays(days) {
  return new Date(Date.now() + days * 86400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function serialize(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseArguments(values) {
  if (values.length % 2 !== 0) fail("arguments must be --name value pairs");
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    if (!key.startsWith("--")) fail(`unexpected argument: ${key}`);
    parsed[key.slice(2)] = values[index + 1];
  }
  return parsed;
}

function fail(message) {
  console.error(`[publish-tuf-feed] ${message}`);
  process.exit(1);
}
