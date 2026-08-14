import { chmodSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const options = parseArguments(process.argv.slice(2));
if (!options.target || !options.artifacts) fail("required: --target and --artifacts");
const target = options.target;
const artifacts = resolve(options.artifacts);
const staging = resolve(artifacts, "smoke-staging");
rmSync(staging, { force: true, recursive: true });
mkdirSync(staging, { recursive: true });

try {
  if (target.startsWith("windows-")) smokeWindows();
  else if (target.startsWith("macos-")) smokeMacos();
  else if (target.startsWith("linux-")) smokeLinux();
  else fail(`unsupported target: ${target}`);
  console.log(JSON.stringify({ ok: true, target }));
} finally {
  rmSync(staging, { force: true, recursive: true });
}

function smokeWindows() {
  const portable = resolve(artifacts, `FMD-${target}-portable.zip`);
  const portableRoot = resolve(staging, "portable");
  run("powershell", ["-NoProfile", "-Command", `Expand-Archive -LiteralPath '${ps(portable)}' -DestinationPath '${ps(portableRoot)}' -Force`]);
  run(findFile(portableRoot, /^fmd-app\.exe$/i), ["--fmd-smoke-check"]);

  const installer = resolve(artifacts, `FMD-${target}-setup.exe`);
  const installedRoot = resolve(staging, "installed");
  mkdirSync(installedRoot, { recursive: true });
  run(installer, ["/S", `/D=${installedRoot}`]);
  run(findFile(installedRoot, /\.exe$/i, (path) => !/uninstall/i.test(path)), ["--fmd-smoke-check"]);
}

function smokeMacos() {
  const portable = resolve(artifacts, `FMD-${target}.app.zip`);
  const portableRoot = resolve(staging, "portable");
  mkdirSync(portableRoot, { recursive: true });
  run("/usr/bin/ditto", ["-x", "-k", portable, portableRoot]);
  run(findMacExecutable(portableRoot), ["--fmd-smoke-check"]);

  const dmg = resolve(artifacts, `FMD-${target}.dmg`);
  const mount = resolve(staging, "mount");
  mkdirSync(mount, { recursive: true });
  run("/usr/bin/hdiutil", ["verify", dmg]);
  run("/usr/bin/hdiutil", ["attach", "-nobrowse", "-readonly", "-mountpoint", mount, dmg]);
  try {
    run(findMacExecutable(mount), ["--fmd-smoke-check"]);
  } finally {
    run("/usr/bin/hdiutil", ["detach", mount]);
  }
}

function smokeLinux() {
  const appImage = resolve(artifacts, `FMD-${target}.AppImage`);
  chmodSync(appImage, 0o755);
  run(appImage, ["--fmd-smoke-check"], { APPIMAGE_EXTRACT_AND_RUN: "1" });

  const deb = resolve(artifacts, `FMD-${target}.deb`);
  const installedRoot = resolve(staging, "deb");
  run("dpkg-deb", ["--info", deb]);
  run("dpkg-deb", ["--extract", deb, installedRoot]);
  run(findFile(installedRoot, /^fmd-app$/, (path) => path.includes(`${join("usr", "bin")}`)), ["--fmd-smoke-check"]);
}

function findMacExecutable(root) {
  return findFile(root, /.+/, (path) => path.includes(".app") && path.includes(`${join("Contents", "MacOS")}`));
}

function findFile(root, pattern, predicate = () => true) {
  const pending = [root];
  const matches = [];
  while (pending.length) {
    const directory = pending.pop();
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile() && pattern.test(entry.name) && predicate(path)) matches.push(path);
    }
  }
  matches.sort();
  if (!matches.length) fail(`smoke executable not found under ${root}`);
  return matches[0];
}

function run(executable, args, extraEnv = {}) {
  const result = spawnSync(executable, args, {
    stdio: "inherit",
    shell: false,
    env: { ...process.env, ...extraEnv },
  });
  if (result.status !== 0) fail(`${executable} failed with status ${result.status}`);
}

function ps(value) {
  return value.replaceAll("'", "''");
}

function parseArguments(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    if (!key?.startsWith("--")) fail(`unexpected argument: ${key}`);
    result[key.slice(2)] = values[index + 1];
  }
  return result;
}

function fail(message) {
  console.error(`[smoke-core-artifacts] ${message}`);
  process.exit(1);
}
