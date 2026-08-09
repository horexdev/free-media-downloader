#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: build-ffmpeg-standard.sh <target> <ffmpeg-archive> <work-dir> <output-dir> [openssl-archive]" >&2
  exit 2
}

[[ $# -ge 4 && $# -le 5 ]] || usage
target=$1
ffmpeg_archive=$2
work_dir=$3
output_dir=$4
openssl_archive=${5:-}

case "$target" in
  linux-x64|linux-arm64) [[ -n "$openssl_archive" ]] || usage ;;
  macos-x64|macos-arm64) [[ -z "$openssl_archive" ]] || usage ;;
  *) echo "unsupported Unix target: $target" >&2; exit 2 ;;
esac

[[ ! -e "$work_dir" ]] || { echo "work directory already exists" >&2; exit 1; }
[[ ! -e "$output_dir" ]] || { echo "output directory already exists" >&2; exit 1; }
mkdir -m 700 -p "$work_dir" "$output_dir"
work_dir=$(cd "$work_dir" && pwd -P)
output_dir=$(cd "$output_dir" && pwd -P)

host_os=$(uname -s)
host_arch=$(uname -m)
case "$target:$host_os:$host_arch" in
  linux-x64:Linux:x86_64|linux-arm64:Linux:aarch64|macos-x64:Darwin:x86_64|macos-arm64:Darwin:arm64) ;;
  *) echo "native target does not match host: $target on $host_os/$host_arch" >&2; exit 1 ;;
esac

jobs=${FMD_BUILD_JOBS:-2}
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "FMD_BUILD_JOBS must be a positive integer" >&2; exit 1; }
export SOURCE_DATE_EPOCH=1785792082
export ZERO_AR_DATE=1
export LC_ALL=C

validate_archive() {
  local archive=$1
  tar -tf "$archive" | awk '
    /^\// || /(^|\/)\.\.($|\/)/ || /\\/ { bad=1 }
    END { exit bad }
  ' || { echo "archive contains an unsafe path" >&2; exit 1; }
}

validate_archive "$ffmpeg_archive"
mkdir "$work_dir/ffmpeg-source"
tar -xf "$ffmpeg_archive" -C "$work_dir/ffmpeg-source" --strip-components=1

extra_configuration=()
if [[ "$target" == linux-* ]]; then
  validate_archive "$openssl_archive"
  mkdir "$work_dir/openssl-source" "$work_dir/openssl-prefix"
  tar -xf "$openssl_archive" -C "$work_dir/openssl-source" --strip-components=1
  openssl_target=linux-x86_64
  [[ "$target" == linux-arm64 ]] && openssl_target=linux-aarch64
  (
    cd "$work_dir/openssl-source"
    ./Configure "$openssl_target" no-shared no-tests no-apps no-docs no-module \
      --prefix="$work_dir/openssl-prefix" --openssldir="$work_dir/openssl-prefix/ssl"
    make -j"$jobs"
    make install_sw
  )
  extra_configuration+=(
    --enable-openssl
    "--extra-cflags=-I$work_dir/openssl-prefix/include"
    "--extra-ldflags=-L$work_dir/openssl-prefix/lib64 -L$work_dir/openssl-prefix/lib"
    --extra-libs=-ldl
  )
else
  extra_configuration+=(--disable-openssl)
fi

recipe_configuration=()
while IFS= read -r option; do
  recipe_configuration+=("$option")
done < <(
  node -e '
    const recipe = require(process.argv[1]);
    for (const option of recipe.configure) console.log(option);
  ' "$(cd "$(dirname "$0")/../.." && pwd -P)/packs/recipes/ffmpeg-standard.json"
)

mkdir "$work_dir/ffmpeg-build" "$work_dir/ffmpeg-prefix"
(
  cd "$work_dir/ffmpeg-build"
  "$work_dir/ffmpeg-source/configure" \
    --prefix="$work_dir/ffmpeg-prefix" \
    --extra-version=fmd.1 \
    "${recipe_configuration[@]}" \
    "${extra_configuration[@]}"
  if [[ "$target" == linux-* ]]; then
    grep -Eq '^#define CONFIG_OPENSSL 1$' config.h
  else
    grep -Eq '^#define CONFIG_SECURETRANSPORT 1$' config.h
  fi
  ! grep -Eq '^#define CONFIG_(GPL|NONFREE) 1$' config.h
  make -j"$jobs"
  make install
)

suffix=
cp "$work_dir/ffmpeg-prefix/bin/ffmpeg$suffix" "$output_dir/ffmpeg$suffix"
cp "$work_dir/ffmpeg-prefix/bin/ffprobe$suffix" "$output_dir/ffprobe$suffix"
chmod 755 "$output_dir/ffmpeg$suffix" "$output_dir/ffprobe$suffix"

"$output_dir/ffmpeg" -hide_banner -version | grep -F "ffmpeg version 9.0-fmd.1"
"$output_dir/ffprobe" -hide_banner -version | grep -F "ffprobe version 9.0-fmd.1"
build_configuration=$("$output_dir/ffmpeg" -hide_banner -buildconf 2>&1)
grep -F -- '--disable-gpl' <<<"$build_configuration"
grep -F -- '--disable-nonfree' <<<"$build_configuration"

if [[ "$target" == linux-* ]]; then
  if ldd "$output_dir/ffmpeg" | grep -Eqi 'lib(ssl|crypto)'; then
    echo "Linux FFmpeg retains a runtime OpenSSL dependency" >&2
    exit 1
  fi
else
  if otool -L "$output_dir/ffmpeg" | tail -n +2 | grep -Ev '^\s*/(System|usr/lib)/' | grep -q .; then
    echo "macOS FFmpeg retains a non-system runtime dependency" >&2
    exit 1
  fi
fi
