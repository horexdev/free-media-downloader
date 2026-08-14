import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const options = parseArguments(process.argv.slice(2));
for (const required of ["feed", "root-out", "key-out-dir", "expires"]) {
  if (!options[required]) fail(`required: --${required}`);
}
if (!/^[a-z][a-z0-9_-]{1,31}$/.test(options.feed)) fail("invalid feed name");
if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(options.expires)) {
  fail("expires must be an RFC 3339 UTC timestamp without fractions");
}

const rootOut = resolve(options["root-out"]);
const keyOut = resolve(options["key-out-dir"]);
mkdirSync(dirname(rootOut), { recursive: true });
mkdirSync(keyOut, { recursive: true, mode: 0o700 });

const roles = ["root", "targets", "snapshot", "timestamp"];
const keys = new Map();
for (const role of roles) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicHex = publicDer.subarray(publicDer.length - 32).toString("hex");
  const value = {
    keytype: "ed25519",
    scheme: "ed25519",
    keyval: { public: publicHex },
  };
  const keyid = sha256(canonical(value));
  const privatePem = privateKey.export({ format: "pem", type: "pkcs8" });
  writeFileSync(resolve(keyOut, `${options.feed}-${role}.pem`), privatePem, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  keys.set(role, { keyid, privateKey, value });
}

const signed = {
  _type: "root",
  spec_version: "1.0",
  consistent_snapshot: true,
  version: 1,
  expires: options.expires,
  keys: Object.fromEntries(roles.map((role) => {
    const key = keys.get(role);
    return [key.keyid, key.value];
  })),
  roles: Object.fromEntries(roles.map((role) => {
    const key = keys.get(role);
    return [role, { keyids: [key.keyid], threshold: 1 }];
  })),
};
const rootKey = keys.get("root");
const signature = sign(null, Buffer.from(canonical(signed)), rootKey.privateKey).toString("hex");
const root = { signatures: [{ keyid: rootKey.keyid, sig: signature }], signed };
const bytes = `${JSON.stringify(root, null, 2)}\n`;
writeFileSync(rootOut, bytes, {
  encoding: "utf8",
  flag: options.replace === "true" ? "w" : "wx",
  mode: 0o644,
});
console.log(JSON.stringify({
  feed: options.feed,
  root: rootOut,
  rootSha256: sha256(bytes),
  keyids: Object.fromEntries(roles.map((role) => [role, keys.get(role).keyid])),
}, null, 2));

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
  console.error(`[generate-tuf-root] ${message}`);
  process.exit(1);
}
