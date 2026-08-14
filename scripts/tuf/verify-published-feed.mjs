import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const [feedRoot] = process.argv.slice(2);
if (!feedRoot) fail("usage: verify-published-feed.mjs <feed-directory>");
const root = resolve(feedRoot);
const trustedRoot = read("metadata/root.json");
verifyEnvelope(trustedRoot, "root", trustedRoot);
const timestamp = read("metadata/timestamp.json");
verifyEnvelope(timestamp, "timestamp", trustedRoot);
const snapshotVersion = timestamp.signed.meta["snapshot.json"].version;
const snapshotBytes = readFileSync(resolve(root, `metadata/${snapshotVersion}.snapshot.json`));
verifyFile(snapshotBytes, timestamp.signed.meta["snapshot.json"], "snapshot");
const snapshot = JSON.parse(snapshotBytes);
verifyEnvelope(snapshot, "snapshot", trustedRoot);
const targetsVersion = snapshot.signed.meta["targets.json"].version;
const targetsBytes = readFileSync(resolve(root, `metadata/${targetsVersion}.targets.json`));
verifyFile(targetsBytes, snapshot.signed.meta["targets.json"], "targets");
const targets = JSON.parse(targetsBytes);
verifyEnvelope(targets, "targets", trustedRoot);
for (const [name, meta] of Object.entries(targets.signed.targets)) {
  const digest = meta.hashes.sha256;
  const bytes = readFileSync(resolve(root, "targets", `${digest}.${name}`));
  verifyFile(bytes, meta, name);
  const descriptor = JSON.parse(bytes);
  if (descriptor.target_name !== name || descriptor.artifact_length < 1 || !/^https:\/\//.test(descriptor.artifact_url)) {
    fail(`invalid artifact descriptor: ${name}`);
  }
}
console.log(JSON.stringify({ ok: true, targets: Object.keys(targets.signed.targets).length }));

function read(path) {
  return JSON.parse(readFileSync(resolve(root, path), "utf8"));
}

function verifyFile(bytes, meta, label) {
  if (bytes.length !== meta.length || sha256(bytes) !== meta.hashes.sha256) {
    fail(`${label} hash/length mismatch`);
  }
}

function verifyEnvelope(envelope, role, rootDocument) {
  if (envelope?.signed?._type !== role || Date.parse(envelope.signed.expires) <= Date.now()) {
    fail(`${role} metadata is invalid or expired`);
  }
  const roleInfo = rootDocument.signed.roles[role];
  const signed = Buffer.from(canonical(envelope.signed));
  const valid = new Set();
  for (const signature of envelope.signatures ?? []) {
    if (!roleInfo.keyids.includes(signature.keyid) || valid.has(signature.keyid)) continue;
    const key = rootDocument.signed.keys[signature.keyid];
    if (!key || sha256(Buffer.from(canonical(key))) !== signature.keyid) continue;
    const publicDer = Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(key.keyval.public, "hex"),
    ]);
    const publicKey = createPublicKey({ key: publicDer, format: "der", type: "spki" });
    if (verifySignature(null, signed, publicKey, Buffer.from(signature.sig, "hex"))) {
      valid.add(signature.keyid);
    }
  }
  if (valid.size < roleInfo.threshold) fail(`${role} signature threshold was not met`);
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function fail(message) {
  console.error(`[verify-tuf-feed] ${message}`);
  process.exit(1);
}
