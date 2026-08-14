import { cpSync, copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const argv = parseArguments(process.argv.slice(2));
const target = argv.target;
if (!target) fail("required: --target");
if (!argv.out) fail("required: --out");

const workspace = resolve(argv.workspace || process.cwd());
const outDir = resolve(argv.out);
const targetTriples = {
  "windows-x64": "x86_64-pc-windows-msvc",
  "windows-arm64": "aarch64-pc-windows-msvc",
  "macos-x64": "x86_64-apple-darwin",
  "macos-arm64": "aarch64-apple-darwin",
  "linux-x64": "x86_64-unknown-linux-gnu",
  "linux-arm64": "aarch64-unknown-linux-gnu",
};

const triple = targetTriples[target];
if (!triple) fail(`unknown target ${target}`);
const bundleDir = resolve(workspace, "src-tauri", "target", triple, "release", "bundle");
const outputs = [];
const prefix = `FMD-${target}`;

rmSync(outDir, { force: true, recursive: true });
mkdirSync(outDir, { recursive: true });

if (target.startsWith("windows-")) {
  const nsisDir = join(bundleDir, "nsis");
  const installer = pickFirstFile(nsisDir, /_setup\.exe$/i, /-setup\.exe$/i, /\.exe$/i);
  if (!installer) fail(`no windows installer found in ${nsisDir}`);

  const setupOut = resolve(outDir, `${prefix}-setup.exe`);
  const portableOut = resolve(outDir, `${prefix}-portable.zip`);
  const updateOut = resolve(outDir, `${prefix}-update.zip`);
  copyFileSync(installer, setupOut);
  const releaseDir = resolve(workspace, "src-tauri", "target", triple, "release");
  const app = pickFirstFile(releaseDir, /^fmd-app\.exe$/i);
  const launcher = pickFirstFile(releaseDir, /^fmd-launcher\.exe$/i);
  if (!app || !launcher) fail(`portable binaries are missing in ${releaseDir}`);
  const version = readWorkspaceVersion();
  const portableRoot = resolve(outDir, "portable-staging");
  const payloadRoot = resolve(portableRoot, "app", version);
  mkdirSync(payloadRoot, { recursive: true });
  mkdirSync(resolve(portableRoot, "state"), { recursive: true });
  copyFileSync(app, resolve(payloadRoot, "fmd-app.exe"));
  copyFileSync(launcher, resolve(portableRoot, "fmd-launcher.exe"));
  writeFileSync(resolve(portableRoot, "portable.json"), "{}\n");
  writeFileSync(resolve(portableRoot, "state", "current.json"), `${JSON.stringify({
    version,
    executable: "fmd-app.exe",
  }, null, 2)}\n`);
  zipDirectory(portableRoot, portableOut);
  zipDirectory(payloadRoot, updateOut);
  rmSync(portableRoot, { force: true, recursive: true });
  outputs.push(setupOut, portableOut, updateOut);
}

if (target.startsWith("macos-")) {
  const dmgDir = join(bundleDir, "dmg");
  const appDir = findDirBySuffix(join(bundleDir, "macos"), ".app");
  const dmg = pickFirstFile(dmgDir, /\.dmg$/i);

  if (!dmg) fail(`no dmg found in ${dmgDir}`);
  if (!appDir) fail(`no app bundle found in ${join(bundleDir, "macos")}`);

  const dmgOut = resolve(outDir, `${prefix}.dmg`);
  const appZipOut = resolve(outDir, `${prefix}.app.zip`);
  cpSync(dmg, dmgOut);
  runDittoZip(appDir, appZipOut);
  outputs.push(dmgOut, appZipOut);
}

if (target.startsWith("linux-")) {
  const appImage = pickFirstFile(join(bundleDir, "appimage"), /\.AppImage$/i);
  const deb = pickFirstFile(join(bundleDir, "deb"), /\.deb$/i);

  if (!appImage) fail(`no AppImage found in ${join(bundleDir, "appimage")}`);
  if (!deb) fail(`no deb package found in ${join(bundleDir, "deb")}`);

  const appImageOut = resolve(outDir, `${prefix}.AppImage`);
  const debOut = resolve(outDir, `${prefix}.deb`);
  cpSync(appImage, appImageOut);
  cpSync(deb, debOut);
  outputs.push(appImageOut, debOut);
}

console.log(JSON.stringify({ target, outDir, outputs }, null, 2));

function zipDirectory(inputDirectory, outputZip) {
  if (process.platform === "win32") {
    const powershell = [
      "powershell",
      "-NoProfile",
      "-Command",
      `$items = Join-Path ${quoteShell(inputDirectory)} '*'; Compress-Archive -Path $items -DestinationPath ${quoteShell(outputZip)} -Force`,
    ];
    runCommand(powershell, { cwd: outDir });
    return;
  }

  runCommand(["zip", "-q", "-r", outputZip, "."], { cwd: inputDirectory });
}

function readWorkspaceVersion() {
  const manifest = readFileSync(resolve(workspace, "Cargo.toml"), "utf8");
  const match = manifest.match(/\[workspace\.package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/);
  if (!match) fail("workspace version is missing from Cargo.toml");
  return match[1];
}

function runDittoZip(inputApp, outputZip) {
  const exe = "/usr/bin/ditto";
  const result = spawnSync(exe, ["-c", "-k", "--keepParent", inputApp, outputZip], { stdio: "inherit" });
  if (result.status !== 0) fail(`zip app failed: ${result.status}`);
}

function pickFirstFile(directory, ...patterns) {
  let files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    if (patterns.some((pattern) => pattern.test(entry.name))) {
      files.push(join(directory, entry.name));
    }
  }
  files.sort();
  return files[0];
}

function findDirBySuffix(directory, suffix) {
  const dirs = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && entry.name.endsWith(suffix)) {
      dirs.push(join(directory, entry.name));
    }
  }
  dirs.sort();
  return dirs[0];
}

function runCommand(command, options) {
  const [exe, ...args] = command;
  const result = spawnSync(exe, args, { stdio: "inherit", shell: false, ...options });
  if (result.status !== 0) fail(`command failed: ${command.join(" ")} (${result.status})`);
}

function quoteShell(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function parseArguments(raw) {
  const result = {};
  for (let i = 0; i < raw.length; i += 1) {
    const key = raw[i];
    const value = raw[i + 1];
    if (key?.startsWith("--")) {
      result[key.slice(2)] = value;
      i += 1;
    }
  }
  return result;
}

function fail(message) {
  console.error(`[package-core-artifacts] ${message}`);
  process.exit(1);
}
