#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: build-ffmpeg-standard-windows-cross.sh <target> <ffmpeg-archive> <work-dir> <output-dir>" >&2
  exit 2
}

[[ $# -eq 4 ]] || usage
target=$1
ffmpeg_archive=$2
work_dir=$3
output_dir=$4
recipe_path="$(cd "$(dirname "$0")/../.." && pwd -P)/packs/recipes/ffmpeg-standard.json"
source_lock_path="$(cd "$(dirname "$0")/../.." && pwd -P)/packs/source-lock.json"
source_version="$(node -e 'const lock=require(process.argv[1]); console.log(lock.components.ffmpeg.version);' "$source_lock_path")"
recipe_source_date_epoch="$(node -e 'const recipe=require(process.argv[1]); console.log(recipe.sourceDateEpoch ?? 0);' "$recipe_path")"

if [[ -z "$source_version" || -z "$recipe_source_date_epoch" ]]; then
  echo "unable to resolve ffmpeg recipe metadata" >&2
  exit 1
fi

case "$target" in
  windows-x64|windows-arm64) ;;
  *) echo "unsupported windows target: $target" >&2; exit 2 ;;
esac

if [[ ! -e "$ffmpeg_archive" ]]; then
  echo "ffmpeg source archive not found: $ffmpeg_archive" >&2
  exit 1
fi
if [[ -e "$work_dir" || -e "$output_dir" ]]; then
  echo "work and output directories must not exist" >&2
  exit 1
fi
mkdir -m 700 -p "$work_dir" "$output_dir"

work_dir=$(cd "$work_dir" && pwd -P)
output_dir=$(cd "$output_dir" && pwd -P)
host_os=$(uname -s)
if [[ "$host_os" != "Linux" ]]; then
  echo "windows cross compile is currently wired for Linux runners only" >&2
  exit 1
fi

jobs=${FMD_BUILD_JOBS:-2}
if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]]; then
  echo "FMD_BUILD_JOBS must be a positive integer" >&2
  exit 1
fi

if [[ "$target" == windows-x64 ]]; then
  cross_prefix="x86_64-w64-mingw32"
  recipe_arch="x86_64"
else
  cross_prefix="aarch64-w64-mingw32"
  recipe_arch="aarch64"
fi

validate_archive() {
  local archive=$1
  tar -tf "$archive" | awk '
    /^\// || /(^|\/)\.\.($|\/)/ || /\\/ { bad=1 }
    END { exit bad }
  ' || { echo "archive contains an unsafe path: $archive" >&2; exit 1; }
}

validate_archive "$ffmpeg_archive"
mkdir "$work_dir/ffmpeg-source"
tar -xf "$ffmpeg_archive" -C "$work_dir/ffmpeg-source" --strip-components=1

if command -v "$cross_prefix-gcc" >/dev/null; then
  cc="$cross_prefix-gcc"
  cxx="$cross_prefix-g++"
  assembler="$cross_prefix-as"
  ar="$cross_prefix-ar"
  ranlib="$cross_prefix-ranlib"
  nm="$cross_prefix-nm"
  strip_tool="$cross_prefix-strip"
  strings_tool="$cross_prefix-strings"
elif command -v "$cross_prefix-clang" >/dev/null; then
  cc="$cross_prefix-clang"
  cxx="$cross_prefix-clang++"
  assembler="$cross_prefix-clang"
  ar="llvm-ar"
  ranlib="llvm-ranlib"
  nm="llvm-nm"
  strip_tool="llvm-strip"
  strings_tool="llvm-strings"
else
  echo "required compiler missing for target: $cross_prefix" >&2
  exit 1
fi

required_tools=(
  "$cc" "$cxx" "$assembler" "$ar" "$ranlib" "$nm" "$strip_tool"
  "$strings_tool" make pkg-config
)
for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null; then
    echo "required tool missing: $tool" >&2
    echo "install mingw toolchain for $cross_prefix and retry" >&2
    exit 1
  fi
done

command -v nasm >/dev/null || { echo "nasm is required for x86/arm Windows optimizations" >&2; exit 1; }
nasm -v

export SOURCE_DATE_EPOCH="$recipe_source_date_epoch"
export ZERO_AR_DATE=1
export LC_ALL=C
if command -v "${cross_prefix}-pkg-config" >/dev/null; then
  export PKG_CONFIG="${cross_prefix}-pkg-config"
else
  unset PKG_CONFIG
fi
export CFLAGS="-O2 -fstack-protector-strong -D_WIN32_WINNT=0x0A00"

recipe_configuration=()
while IFS= read -r option; do
  recipe_configuration+=("$option")
done < <(
  node -e '
    const recipe = require(process.argv[1]);
    for (const option of recipe.configure) console.log(option);
  ' "$recipe_path"
)

mkdir "$work_dir/ffmpeg-build" "$work_dir/ffmpeg-prefix"

(
  cd "$work_dir/ffmpeg-build"
  if ! "$work_dir/ffmpeg-source/configure" \
    --prefix="$work_dir/ffmpeg-prefix" \
    --cross-prefix="${cross_prefix}-" \
    --target-os=mingw64 \
    --arch="$recipe_arch" \
    --extra-version=fmd.1 \
    --enable-cross-compile \
    --cc="$cc" \
    --cxx="$cxx" \
    --ld="$cc" \
    --ar="$ar" \
    --as="$assembler" \
    --nm="$nm" \
    --ranlib="$ranlib" \
    --strip="$strip_tool" \
    --pkg-config-flags="--static" \
    --enable-schannel \
    "${recipe_configuration[@]}" \
    --extra-cflags="$CFLAGS"; then
    cat ffbuild/config.log >&2
    exit 1
  fi

  grep -Eq '^#define CONFIG_OPENSSL 0$' config.h || {
    echo "FFmpeg unexpectedly enabled OpenSSL" >&2
    exit 1
  }
  grep -Eq '^#define CONFIG_SCHANNEL 1$' config.h || {
    echo "FFmpeg did not enable Schannel" >&2
    exit 1
  }
  grep -Eq '^#define HAVE_W32THREADS 1$' config.h || {
    echo "FFmpeg did not enable the Windows threading backend" >&2
    exit 1
  }
  if grep -Eq '^#define CONFIG_(XLIB|LIBXCB|LIBXCB_SHM|LIBXCB_XFIXES|LIBXCB_SHAPE) 1$' config.h; then
    echo "FFmpeg unexpectedly enabled an X11 dependency" >&2
    exit 1
  fi
  if grep -Eq '^#define CONFIG_GPL 1$' config.h; then
    echo "FFmpeg unexpectedly enabled GPL components" >&2
    exit 1
  fi
  if grep -Eq '^#define CONFIG_NONFREE 1$' config.h; then
    echo "FFmpeg unexpectedly enabled nonfree components" >&2
    exit 1
  fi
  make -j"$jobs"
  make install
)

cp "$work_dir/ffmpeg-prefix/bin/ffmpeg.exe" "$output_dir/ffmpeg.exe"
cp "$work_dir/ffmpeg-prefix/bin/ffprobe.exe" "$output_dir/ffprobe.exe"
"$strip_tool" "$output_dir/ffmpeg.exe" "$output_dir/ffprobe.exe"
chmod 755 "$output_dir/ffmpeg.exe" "$output_dir/ffprobe.exe"

verify_pe_machine() {
  local binary=$1
  local expected_machine=$2
  node - "$binary" "$expected_machine" <<'NODE'
const { readFileSync } = require("node:fs");

const [binary, expectedText] = process.argv.slice(2);
const contents = readFileSync(binary);
if (contents.length < 0x40 || contents.toString("ascii", 0, 2) !== "MZ") {
  throw new Error(`${binary} is not a DOS/PE executable`);
}
const peOffset = contents.readUInt32LE(0x3c);
if (peOffset + 26 > contents.length || contents.toString("binary", peOffset, peOffset + 4) !== "PE\0\0") {
  throw new Error(`${binary} has an invalid PE signature`);
}
const machine = contents.readUInt16LE(peOffset + 4);
const expected = Number(expectedText);
if (machine !== expected) {
  throw new Error(`${binary} has PE machine 0x${machine.toString(16)}, expected 0x${expected.toString(16)}`);
}
const characteristics = contents.readUInt16LE(peOffset + 22);
if ((characteristics & 0x0002) === 0) {
  throw new Error(`${binary} is not marked executable`);
}
const optionalMagic = contents.readUInt16LE(peOffset + 24);
if (optionalMagic !== 0x20b) {
  throw new Error(`${binary} is not a PE32+ executable`);
}
NODE
}

if [[ "$target" == windows-x64 ]]; then
  expected_machine=0x8664
else
  expected_machine=0xaa64
fi
verify_pe_machine "$output_dir/ffmpeg.exe" "$expected_machine"
verify_pe_machine "$output_dir/ffprobe.exe" "$expected_machine"

verify_binary_string() {
  local strings_file=$1
  local expected=$2
  if ! grep -Fq -- "$expected" "$strings_file"; then
    echo "expected string not found in cross-compiled binary: $expected" >&2
    exit 1
  fi
}

ffmpeg_strings="$work_dir/ffmpeg.strings"
ffprobe_strings="$work_dir/ffprobe.strings"
"$strings_tool" "$output_dir/ffmpeg.exe" > "$ffmpeg_strings"
"$strings_tool" "$output_dir/ffprobe.exe" > "$ffprobe_strings"
verify_binary_string "$ffmpeg_strings" "${source_version}-fmd.1"
verify_binary_string "$ffprobe_strings" "${source_version}-fmd.1"
verify_binary_string "$ffmpeg_strings" '--disable-gpl'
verify_binary_string "$ffmpeg_strings" '--disable-nonfree'
