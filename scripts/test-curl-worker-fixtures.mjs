import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { spawn, spawnSync } from "node:child_process";

const options = parseArgs(process.argv.slice(2));
const worker = resolve(required(options, "worker"));
const python = options.python ?? (process.platform === "win32" ? "python" : "python3");
const fixtureScript = resolve("scripts/fixtures/transfer_server.py");
const scratch = mkdtempSync(join(tmpdir(), "fmd-worker-fixtures-"));
const fixture = spawn(python, ["-u", fixtureScript], {
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
});
let fixtureErrors = "";
fixture.stderr.setEncoding("utf8");
fixture.stderr.on("data", (chunk) => {
  fixtureErrors += chunk;
});

try {
  const config = await firstJsonLine(fixture);
  const baseEnvironment = minimalEnvironment(scratch);
  const httpsDestination = join(scratch, "https-payload.txt");
  const httpsMessages = runWorker(
    worker,
    downloadRequest("https-download", config.https_url, httpsDestination),
    {
      ...baseEnvironment,
      FMD_CURL_FIXTURE_CA: config.ca_path,
    },
  );
  requireCompleted(httpsMessages, "https-download");
  requirePayload(httpsDestination, config.payload, "HTTPS");

  const rejectedDestination = join(scratch, "https-untrusted.txt");
  const rejectedHttps = runWorker(
    worker,
    downloadRequest("https-untrusted", config.https_url, rejectedDestination),
    { ...baseEnvironment, FMD_CURL_FIXTURE_CA: join(scratch, "missing-ca.pem") },
  );
  requireFailure(rejectedHttps, "https-untrusted", "worker.request_rejected");

  const hello = httpsMessages.find((message) => message.type === "hello");
  const hasSftp = hello?.capabilities?.includes("sftp_hostkey_callback") === true;
  const requireSftp = options["require-sftp"] !== "false";
  if (!hasSftp && requireSftp) throw new Error("worker is missing sftp_hostkey_callback");

  if (hasSftp) {
    const probeMessages = runWorker(
      worker,
      {
        protocol_version: 2,
        request_id: "sftp-probe",
        request: { operation: "probe_host_key", url: config.sftp_url },
      },
      baseEnvironment,
    );
    const hostKey = requireEvent(probeMessages, "sftp-probe", "host_key");
    requireCompleted(probeMessages, "sftp-probe");

    const unknownDestination = join(scratch, "sftp-unknown.txt");
    const unknownMessages = runWorker(
      worker,
      downloadRequest(
        "sftp-unknown",
        config.sftp_url,
        unknownDestination,
        passwordCredentials(config),
      ),
      baseEnvironment,
    );
    requireFailure(unknownMessages, "sftp-unknown", "worker.sftp_host_key_untrusted");

    const passwordDestination = join(scratch, "sftp-password.txt");
    const passwordMessages = runWorker(
      worker,
      downloadRequest(
        "sftp-password",
        config.sftp_url,
        passwordDestination,
        passwordCredentials(config),
        trustedHostKey(hostKey),
      ),
      baseEnvironment,
    );
    requireCompleted(passwordMessages, "sftp-password");
    requirePayload(passwordDestination, config.payload, "SFTP password");

    const keyDestination = join(scratch, "sftp-key.txt");
    const keyMessages = runWorker(
      worker,
      downloadRequest(
        "sftp-key",
        config.sftp_url,
        keyDestination,
        {
          kind: "private_key",
          username: config.username,
          key_path: config.client_key_path,
          passphrase: config.key_passphrase,
        },
        trustedHostKey(hostKey),
      ),
      baseEnvironment,
    );
    requireCompleted(keyMessages, "sftp-key");
    requirePayload(keyDestination, config.payload, "SFTP private key");

    const mismatchDestination = join(scratch, "sftp-mismatch.txt");
    const mismatchMessages = runWorker(
      worker,
      downloadRequest(
        "sftp-mismatch",
        config.sftp_url,
        mismatchDestination,
        passwordCredentials(config),
        {
          ...trustedHostKey(hostKey),
          fingerprint_sha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        },
      ),
      baseEnvironment,
    );
    requireFailure(mismatchMessages, "sftp-mismatch", "worker.sftp_host_key_mismatch");
  }

  console.log(
    hasSftp
      ? "verified HTTPS and SFTP fixtures (unknown, match, mismatch, password, private key)"
      : "verified HTTPS fixture; SFTP was not available in this local worker",
  );
} finally {
  fixture.kill();
  rmSync(scratch, { recursive: true, force: true });
}

function downloadRequest(requestId, url, destination, credentials = null, trusted_host_key = null) {
  return {
    protocol_version: 2,
    request_id: requestId,
    request: {
      operation: "download",
      url,
      destination,
      resume_from: 0,
      expected_validator: null,
      credentials,
      trusted_host_key,
    },
  };
}

function passwordCredentials(config) {
  return { kind: "password", username: config.username, password: config.password };
}

function trustedHostKey(event) {
  return {
    algorithm: event.algorithm,
    raw_key_base64: event.raw_key_base64,
    fingerprint_sha256: event.fingerprint_sha256,
  };
}

function runWorker(binary, request, environment) {
  const result = spawnSync(binary, [], {
    input: JSON.stringify(request),
    encoding: "utf8",
    env: environment,
    windowsHide: true,
    timeout: 30_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`worker exited with ${result.status}: ${result.stderr}`);
  }
  return result.stdout
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .map((message) => ({ ...message, ...(result.stderr ? { fixture_stderr: result.stderr } : {}) }));
}

function requireEvent(messages, requestId, event) {
  const found = messages.find(
    (message) => message.type === "event" && message.request_id === requestId && message.event === event,
  );
  if (!found) throw new Error(`missing ${event} event for ${requestId}: ${JSON.stringify(messages)}`);
  return found;
}

function requireCompleted(messages, requestId) {
  requireEvent(messages, requestId, "completed");
}

function requireFailure(messages, requestId, code) {
  const failure = requireEvent(messages, requestId, "failed");
  if (failure.code !== code) {
    throw new Error(`expected ${code} for ${requestId}, received ${failure.code}`);
  }
}

function requirePayload(path, expected, label) {
  const actual = readFileSync(path, "utf8");
  if (actual !== expected) throw new Error(`${label} fixture payload mismatch`);
}

function minimalEnvironment(home) {
  const allowed = ["SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR"];
  const environment = { HOME: home, USERPROFILE: home };
  for (const name of allowed) {
    if (process.env[name]) environment[name] = process.env[name];
  }
  return environment;
}

function firstJsonLine(child) {
  return new Promise((resolveValue, reject) => {
    const lines = createInterface({ input: child.stdout });
    const timeout = setTimeout(() => reject(new Error(`fixture startup timed out: ${fixtureErrors}`)), 20_000);
    lines.once("line", (line) => {
      clearTimeout(timeout);
      lines.close();
      resolveValue(JSON.parse(line));
    });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`fixture exited with ${code}: ${fixtureErrors}`));
    });
  });
}

function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error(`invalid argument: ${key}`);
    parsed[key.slice(2)] = value;
  }
  return parsed;
}

function required(values, name) {
  if (!values[name]) throw new Error(`missing --${name}`);
  return values[name];
}
