#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: build-curl-static-prefix.sh <target> <work-dir>" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
target="$1"
work_dir="$2"

case "$target" in
  linux-x64|linux-arm64|macos-x64|macos-arm64) ;;
  *)
    echo "unsupported target: $target" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
lock_file="$repo_root/packs/source-lock.json"
component_source() {
  local component="$1"
  node - <<'NODE' "$lock_file" "$component"
    const fs = require("node:fs");
    const lock = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
    const component = lock.components[process.argv[3]];
    if (!component) process.exit(2);
    const source =
      component.sourceDistribution ??
      (component.sourceUrl && component.sha256 ? {
        url: component.sourceUrl,
        sha256: component.sha256,
      } : null);
    if (!source?.url || !source.sha256) process.exit(1);
    console.log(`${source.url} ${source.sha256}`);
NODE
}

host_os=$(uname -s)
host_arch=$(uname -m)
case "$target:$host_os:$host_arch" in
  linux-x64:Linux:x86_64|linux-arm64:Linux:aarch64|macos-x64:Darwin:x86_64|macos-arm64:Darwin:arm64) ;;
  *) echo "runner is not native for target $target: $host_os/$host_arch" >&2; exit 2 ;;
esac

jobs=${FMD_BUILD_JOBS:-2}
if ! [[ "$jobs" =~ ^[1-9][0-9]*$ ]]; then
  echo "FMD_BUILD_JOBS must be a positive integer" >&2
  exit 1
fi

sha256sum_cmd="sha256sum"
if ! command -v sha256sum >/dev/null; then
  if command -v shasum >/dev/null; then
    sha256sum_cmd="shasum -a 256"
  else
    echo "sha256 utility not found" >&2
    exit 1
  fi
fi

check_sha256() {
  local archive="$1"
  local expected="$2"
  local actual
  actual=$($sha256sum_cmd "$archive" | awk '{ print $1 }')
  if [[ "$actual" != "$expected" ]]; then
    echo "SHA-256 mismatch for $archive" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
  fi
}

safe_tar() {
  local archive="$1"
  tar -tf "$archive" | awk '
    /(^\/|(^|\/)\.\.($|\/)|\\)/ { bad=1; exit 1 }
    END {}
  ' || { echo "unsafe archive path in $archive" >&2; exit 1; }
}

extract_source() {
  local component="$1"
  local marker="$2"
  if ! read -r url sha <<<"$(component_source "$component")"; then
    echo "Failed to read locked source for ${component}" >&2
    exit 1
  fi
  if [[ -z "$url" || -z "$sha" ]]; then
    echo "Invalid source entry for component $component" >&2
    exit 1
  fi
  if [[ ! "$url" =~ ^https?:// ]]; then
    echo "Blocked unsupported curl source URL: $url" >&2
    exit 1
  fi
  if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Invalid source SHA-256 for component $component: $sha" >&2
    exit 1
  fi
  local archive="$work_dir/$component.tar.gz"
  local unpack_dir="$work_dir/$component-src"
  mkdir -p "$work_dir" "$marker" "$unpack_dir"
  curl -fsSL --fail --retry 5 --retry-all-errors --location "$url" -o "$archive"
  check_sha256 "$archive" "$sha"
  safe_tar "$archive"
  tar -xf "$archive" -C "$unpack_dir" --strip-components=1
  rm -f "$archive"
}

build_zlib() {
  local source_dir="$work_dir/zlib-src"
  local source_log="$work_dir/build-zlib.log"
  (
    cd "$source_dir"
    ./configure --prefix="$prefix_dir" --static
    make -j"$jobs"
    make install
  ) 2>&1 | tee "$source_log"
  if [[ ! -f "$prefix_dir/lib/libz.a" ]]; then
    echo "zlib static library missing: $prefix_dir/lib/libz.a" >&2
    exit 1
  fi
}

build_openssl() {
  local source_dir="$work_dir/openssl-src"
  local source_log="$work_dir/build-openssl.log"
  local openssl_target
  case "$target" in
    linux-x64) openssl_target=linux-x86_64 ;;
    linux-arm64) openssl_target=linux-aarch64 ;;
    macos-x64) openssl_target=darwin64-x86_64-cc ;;
    macos-arm64) openssl_target=darwin64-arm64-cc ;;
  esac

  (
    cd "$source_dir"
    ./Configure "$openssl_target" no-shared no-tests no-apps no-docs no-module \
      --prefix="$prefix_dir" --openssldir="$prefix_dir/ssl"
    make -j"$jobs"
    make install_sw
  ) 2>&1 | tee "$source_log"
  mkdir -p "$prefix_dir/lib"
  if [[ -f "$prefix_dir/lib64/libssl.a" && ! -f "$prefix_dir/lib/libssl.a" ]]; then
    ln -sf "$prefix_dir/lib64/libssl.a" "$prefix_dir/lib/libssl.a"
  fi
  if [[ -f "$prefix_dir/lib64/libcrypto.a" && ! -f "$prefix_dir/lib/libcrypto.a" ]]; then
    ln -sf "$prefix_dir/lib64/libcrypto.a" "$prefix_dir/lib/libcrypto.a"
  fi
  if ! [[ -f "$prefix_dir/lib/libssl.a" || -f "$prefix_dir/lib64/libssl.a" ]]; then
    echo "OpenSSL static libssl missing" >&2
    exit 1
  fi
  if ! [[ -f "$prefix_dir/lib/libcrypto.a" || -f "$prefix_dir/lib64/libcrypto.a" ]]; then
    echo "OpenSSL static libcrypto missing" >&2
    exit 1
  fi
}

build_nghttp2() {
  local source_dir="$work_dir/nghttp2-src"
  local source_log="$work_dir/build-nghttp2.log"
  if ! (
    cd "$source_dir"
    ./configure --disable-shared --enable-static --enable-lib-only --prefix="$prefix_dir"
    make -j"$jobs"
    make install
  ) 2>&1 | tee "$source_log"; then
    (
      cd "$source_dir"
      cmake -S . -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$prefix_dir" \
        -DENABLE_LIB_ONLY=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_STATIC_LIBS=ON \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_TESTING=OFF
      cmake --build build --parallel "$jobs"
      cmake --install build
    ) 2>&1 | tee "$source_log.cmake"
  fi
  if [[ ! -f "$prefix_dir/lib/libnghttp2.a" ]]; then
    echo "nghttp2 static library missing: $prefix_dir/lib/libnghttp2.a" >&2
    exit 1
  fi
}

build_libssh2() {
  local source_dir="$work_dir/libssh2-src"
  local source_log="$work_dir/build-libssh2.log"
  if ! (
    cd "$source_dir"
    ./configure --prefix="$prefix_dir" \
      --with-crypto=openssl \
      --with-libssl-prefix="$prefix_dir" \
      --enable-static \
      --disable-shared \
      --disable-examples \
      --disable-tests \
      --with-libz-prefix="$prefix_dir"
    make -j"$jobs"
    make install
  ) 2>&1 | tee "$source_log"; then
    rm -rf "$source_dir/build"
    (
      cd "$source_dir"
      cmake -S . -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$prefix_dir" \
        -DCRYPTO_BACKEND=OpenSSL \
        -DOPENSSL_ROOT_DIR="$prefix_dir" \
        -DCMAKE_POSITION_INDEPENDENT_CODE=OFF \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_TESTING=OFF
      cmake --build build --parallel "$jobs"
      cmake --install build
    ) 2>&1 | tee "$source_log.cmake"
  fi
  if [[ ! -f "$prefix_dir/lib/libssh2.a" ]]; then
    echo "libssh2 static library missing: $prefix_dir/lib/libssh2.a" >&2
    exit 1
  fi
}

build_curl() {
  local source_dir="$work_dir/curl-src"
  local source_log="$work_dir/build-curl.log"
  (
    cd "$source_dir"
    cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$prefix_dir" \
      -DCMAKE_INSTALL_LIBDIR=lib \
      -DCMAKE_PREFIX_PATH="$prefix_dir" \
      -DBUILD_SHARED_LIBS=OFF \
      -DBUILD_STATIC_LIBS=ON \
      -DBUILD_CURL_EXE=OFF \
      -DBUILD_LIBCURL_DOCS=OFF \
      -DBUILD_MISC_DOCS=OFF \
      -DBUILD_TESTING=OFF \
      -DCURL_USE_PKGCONFIG=OFF \
      -DCURL_USE_OPENSSL=ON \
      -DOPENSSL_ROOT_DIR="$prefix_dir" \
      -DCURL_ZLIB=ON \
      -DZLIB_INCLUDE_DIR="$prefix_dir/include" \
      -DZLIB_LIBRARY="$prefix_dir/lib/libz.a" \
      -DUSE_NGHTTP2=ON \
      -DNGHTTP2_USE_STATIC_LIBS=ON \
      -DNGHTTP2_INCLUDE_DIR="$prefix_dir/include" \
      -DNGHTTP2_LIBRARY="$prefix_dir/lib/libnghttp2.a" \
      -DCURL_USE_LIBSSH2=ON \
      -DLIBSSH2_USE_STATIC_LIBS=ON \
      -DLIBSSH2_INCLUDE_DIR="$prefix_dir/include" \
      -DLIBSSH2_LIBRARY="$prefix_dir/lib/libssh2.a" \
      -DCURL_DISABLE_LDAP=ON \
      -DCURL_DISABLE_RTSP=ON \
      -DCURL_DISABLE_DICT=ON \
      -DCURL_DISABLE_TELNET=ON \
      -DCURL_DISABLE_TFTP=ON \
      -DCURL_DISABLE_GOPHER=ON \
      -DCURL_DISABLE_IMAP=ON \
      -DCURL_DISABLE_POP3=ON \
      -DCURL_DISABLE_SMTP=ON \
      -DCURL_ENABLE_SMB=OFF
    cmake --build build --parallel "$jobs"
    cmake --install build
  ) 2>&1 | tee "$source_log"
  if [[ -f "$prefix_dir/lib64/libcurl.a" && ! -f "$prefix_dir/lib/libcurl.a" ]]; then
    ln -sf "$prefix_dir/lib64/libcurl.a" "$prefix_dir/lib/libcurl.a"
  fi
  if [[ ! -f "$prefix_dir/lib/libcurl.a" ]] || [[ ! -f "$prefix_dir/include/curl/curl.h" ]]; then
    echo "curl static SDK missing" >&2
    exit 1
  fi
}

mkdir -p "$work_dir"
work_dir="$(cd "$work_dir" && pwd -P)"
prefix_dir="$work_dir/prefix"
rm -rf "$work_dir"/*
mkdir -p "$work_dir" "$prefix_dir"
mkdir -p "$work_dir/zlib-src" "$work_dir/openssl-src" "$work_dir/nghttp2-src" "$work_dir/libssh2-src" "$work_dir/curl-src"

extract_source "zlib" "$work_dir/zlib-src"
extract_source "openssl" "$work_dir/openssl-src"
extract_source "nghttp2" "$work_dir/nghttp2-src"
extract_source "libssh2" "$work_dir/libssh2-src"
extract_source "curl" "$work_dir/curl-src"

build_zlib
build_openssl
build_nghttp2
build_libssh2
build_curl

echo "FMD_CURL_STATIC_PREFIX=$prefix_dir" | tee -a "$work_dir/build.log"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "FMD_CURL_STATIC_PREFIX=$prefix_dir" >> "$GITHUB_ENV"
fi

echo "$prefix_dir"
