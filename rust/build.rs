// SigV4 Rust bindings
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Support both layouts:
    // - Development: C sources are in the parent directory (../source/include, ../source/)
    // - Packaged crate: C sources are copied into the crate (include/, csrc/)
    let (include_dir, c_src_dir);
    if manifest_dir.join("include").is_dir() {
        include_dir = manifest_dir.join("include");
        c_src_dir = manifest_dir.join("csrc");
    } else {
        let project_root = manifest_dir.parent().unwrap().to_path_buf();
        include_dir = project_root.join("source").join("include");
        c_src_dir = project_root.join("source");
    }

    let mut cc_build = cc::Build::new();
    cc_build
        .file(c_src_dir.join("sigv4.c"))
        .file(c_src_dir.join("sigv4_quicksort.c"))
        .include(&include_dir);

    let target = env::var("TARGET").unwrap();
    let mut bindgen_builder = bindgen::Builder::default()
        .header(manifest_dir.join("wrapper.h").to_str().unwrap())
        .clang_arg(format!("--target={target}"))
        .clang_arg(format!("-I{}", include_dir.display()));

    if cfg!(feature = "custom-config") {
        // User provides their own sigv4_config.h via SIGV4_CONFIG_INCLUDE_DIR.
        let config_dir = env::var("SIGV4_CONFIG_INCLUDE_DIR")
            .expect("custom-config feature requires SIGV4_CONFIG_INCLUDE_DIR env var pointing to directory containing sigv4_config.h");
        cc_build.include(&config_dir);
        bindgen_builder = bindgen_builder.clang_arg(format!("-I{config_dir}"));
        println!("cargo::rerun-if-env-changed=SIGV4_CONFIG_INCLUDE_DIR");
        println!("cargo:rerun-if-changed={config_dir}");
    } else {
        // Use library defaults
        cc_build.define("SIGV4_DO_NOT_USE_CUSTOM_CONFIG", None);
        bindgen_builder =
            bindgen_builder.clang_arg("-DSIGV4_DO_NOT_USE_CUSTOM_CONFIG");
    }

    cc_build.compile("sigv4");

    bindgen_builder
        .allowlist_function("SigV4_.*")
        .allowlist_type("SigV4.*")
        .allowlist_var("SIGV4_.*")
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .derive_default(true)
        .use_core()
        .sort_semantically(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_dir.join("bindings.rs"))
        .unwrap();

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed={}", c_src_dir.display());
    println!("cargo:rerun-if-changed={}", include_dir.display());
}
