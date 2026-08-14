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
recipe_version="$(node -e 'const recipe=require(process.argv[1]); console.log(recipe.version);' "$recipe_path")"
recipe_source_date_epoch="$(node -e 'const recipe=require(process.argv[1]); console.log(recipe.sourceDateEpoch ?? 0);' "$recipe_path")"

if [[ -z "$recipe_version" || -z "$recipe_source_date_epoch" ]]; then
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

required_tools=(
  "$cross_prefix-gcc" "$cross_prefix-g++" "$cross_prefix-ar" "$cross_prefix-ranlib"
  "$cross_prefix-nm" "$cross_prefix-objdump" "$cross_prefix-strip"
  make pkg-config strip
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
export LDFLAGS="-s"

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
  "$work_dir/ffmpeg-source/configure" \
    --prefix="$work_dir/ffmpeg-prefix" \
    --cross-prefix="${cross_prefix}-" \
    --target-os=mingw64 \
    --arch="$recipe_arch" \
    --extra-version=fmd.1 \
    --cpu="$recipe_arch" \
    --enable-cross-compile \
    --cc="${cross_prefix}-gcc" \
    --cxx="${cross_prefix}-g++" \
    --ar="${cross_prefix}-ar" \
    --as="${cross_prefix}-as" \
    --nm="${cross_prefix}-nm" \
    --ranlib="${cross_prefix}-ranlib" \
    --strip="${cross_prefix}-strip" \
    --objdump="${cross_prefix}-objdump" \
    --pkg-config-flags="--static" \
    --enable-schannel \
    "${recipe_configuration[@]}" \
    --extra-cflags="$CFLAGS" \
    --extra-ldflags="$LDFLAGS"

  grep -Eq '^#define CONFIG_OPENSSL 0$' config.h
  grep -Eq '^#define CONFIG_SCHANNEL 1$' config.h
  grep -Eq '^#define HAVE_PTHREADS 1$' config.h
  ! grep -Eq '^#define CONFIG_(XLIB|LIBXCB|LIBXCB_SHM|LIBXCB_XFIXES|LIBXCB_SHAPE) 1$' config.h
  ! grep -Eq '^#define CONFIG_GPL 1$' config.h
  ! grep -Eq '^#define CONFIG_NONFREE 1$' config.h
  make -j"$jobs"
  make install
)

cp "$work_dir/ffmpeg-prefix/bin/ffmpeg.exe" "$output_dir/ffmpeg.exe"
cp "$work_dir/ffmpeg-prefix/bin/ffprobe.exe" "$output_dir/ffprobe.exe"
chmod 755 "$output_dir/ffmpeg.exe" "$output_dir/ffprobe.exe"

"$output_dir/ffmpeg.exe" -hide_banner -version | grep -F "ffmpeg version ${recipe_version}-fmd.1"
"$output_dir/ffprobe.exe" -hide_banner -version | grep -F "ffprobe version ${recipe_version}-fmd.1"
"$output_dir/ffmpeg.exe" -hide_banner -buildconf 2>&1 | grep -F -- '--disable-gpl'
"$output_dir/ffmpeg.exe" -hide_banner -buildconf 2>&1 | grep -F -- '--disable-nonfree'
