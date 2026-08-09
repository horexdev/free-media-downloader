use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(fmd_native_sftp)");
    println!("cargo:rerun-if-env-changed=FMD_CURL_STATIC_PREFIX");
    println!("cargo:rerun-if-changed=native/ssh_hostkey_shim.c");

    if env::var_os("CARGO_FEATURE_NATIVE_STACK").is_none() {
        return;
    }

    let prefix = env::var_os("FMD_CURL_STATIC_PREFIX").unwrap_or_else(|| {
        panic!("native-stack requires FMD_CURL_STATIC_PREFIX; system libcurl fallback is forbidden")
    });
    let prefix = PathBuf::from(prefix);
    let include = prefix.join("include");
    let library = prefix.join("lib");
    if !include.join("curl/curl.h").is_file() || !library.is_dir() {
        panic!("FMD_CURL_STATIC_PREFIX does not contain the pinned static curl SDK")
    }

    cc::Build::new()
        .file("native/ssh_hostkey_shim.c")
        .include(&include)
        .warnings_into_errors(true)
        .compile("fmd_curl_shim");
    println!("cargo:rustc-link-search=native={}", library.display());
    println!("cargo:rustc-cfg=fmd_native_sftp");
    println!("cargo:rustc-env=FMD_LIBSSH2_VERSION=1.11.1+fmd.2");
    println!("cargo:rustc-env=FMD_OPENSSL_VERSION=3.5.7");
    println!("cargo:rustc-env=FMD_NGHTTP2_VERSION=1.70.0");
    println!("cargo:rustc-env=FMD_ZLIB_VERSION=1.3.2");
}
