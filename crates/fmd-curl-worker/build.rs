use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(fmd_native_sftp)");
    println!("cargo:rerun-if-env-changed=FMD_CURL_STATIC_PREFIX");
    println!("cargo:rerun-if-changed=native/ssh_hostkey_shim.c");

    if env::var_os("CARGO_FEATURE_NATIVE_STACK").is_none() {
        return;
    }
    if env::var_os("CARGO_FEATURE_BUNDLED_CURL").is_some() {
        panic!("native-stack must be built with --no-default-features")
    }

    let prefix = env::var_os("FMD_CURL_STATIC_PREFIX").unwrap_or_else(|| {
        panic!("native-stack requires FMD_CURL_STATIC_PREFIX; system libcurl fallback is forbidden")
    });
    let prefix = PathBuf::from(prefix);
    let include = prefix.join("include");
    let library = prefix.join("lib");
    let target = env::var("TARGET").expect("Cargo must provide TARGET");
    let curl_library = if target.contains("windows-msvc") {
        library.join("libcurl.lib")
    } else {
        library.join("libcurl.a")
    };
    if !include.join("curl/curl.h").is_file() || !curl_library.is_file() {
        panic!("FMD_CURL_STATIC_PREFIX does not contain the pinned static curl SDK")
    }

    let mut shim = cc::Build::new();
    shim.file("native/ssh_hostkey_shim.c")
        .include(&include)
        .warnings_into_errors(true);
    if target.contains("windows-msvc") {
        shim.define("CURL_STATICLIB", None);
    }
    shim.compile("fmd_curl_shim");
    println!("cargo:rustc-link-search=native={}", library.display());
    emit_native_dependencies(&library);
    println!("cargo:rustc-cfg=fmd_native_sftp");
    println!("cargo:rustc-env=FMD_LIBSSH2_VERSION=1.11.1+fmd.2");
    println!("cargo:rustc-env=FMD_OPENSSL_VERSION=3.5.7");
    println!("cargo:rustc-env=FMD_NGHTTP2_VERSION=1.70.0");
    println!("cargo:rustc-env=FMD_ZLIB_VERSION=1.3.2");
}

fn emit_native_dependencies(library: &std::path::Path) {
    let target = env::var("TARGET").expect("Cargo must provide TARGET");
    if target.contains("windows-msvc") {
        for name in ["libssl", "libcrypto", "nghttp2", "zs"] {
            println!("cargo:rustc-link-lib=static={name}");
        }
        for name in [
            "advapi32", "bcrypt", "crypt32", "iphlpapi", "normaliz", "ws2_32",
        ] {
            println!("cargo:rustc-link-lib={name}");
        }
    } else if target.contains("apple-darwin") {
        for name in ["ssh2", "ssl", "crypto", "nghttp2", "z"] {
            println!("cargo:rustc-link-lib=static={name}");
        }
        for framework in ["CoreFoundation", "Security", "SystemConfiguration"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
    } else if target.contains("linux") {
        let pkgconfig = library.join("pkgconfig");
        println!("cargo:rerun-if-changed={}", pkgconfig.display());
    }
}
