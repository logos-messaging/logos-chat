use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=LOGOS_DELIVERY_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LOGOS_DELIVERY_RELOCATABLE");

    let Some(lib_dir) = locate_lib_dir() else {
        println!(
            "cargo:warning=liblogosdelivery could not be located; `cargo check`/\
             `clippy` will pass, but building or testing will fail at link. Enter \
             the dev shell with `nix develop` or set LOGOS_DELIVERY_LIB_DIR to \
             the directory containing the library."
        );
        return;
    };

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    match target_os.as_str() {
        "macos" | "linux" | "ios" => {}
        other => panic!("unsupported OS for logos-delivery transport: {other}"),
    }

    compile_shim(&lib_dir);

    // Two linking modes, because dev builds and *distributable* builds want
    // opposite things out of the library's install name / soname.
    if relocatable() || target_os == "ios" {
        // Distribution: link the shipped library in place and leave its
        // relocatable name (@rpath on macOS, $ORIGIN soname on Linux) intact,
        // so the consumer can copy it into its own bundle and resolve it from
        // there. The library's own @loader_path/$ORIGIN rpath then finds
        // librln beside it. This costs the consumer some build-script glue --
        // on macOS it MUST add an rpath, since cargo does not propagate
        // `rustc-link-arg` across crates -- which is exactly what the default
        // mode below exists to avoid. `lib_dir` is published as
        // DEP_LOGOSDELIVERY_LIB_DIR so direct dependents can locate the
        // libraries to bundle.
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    } else {
        // Default (dev): stamp a private copy with an ABSOLUTE install name.
        // The propagating search + lib directives are then sufficient and
        // consumers need zero build-script glue -- but the resulting binary
        // hardcodes a nix store path and only runs on this machine.
        match target_os.as_str() {
            "macos" => stamp_absolute_macos(&lib_dir, &out_dir),
            "linux" => stamp_absolute_linux(&lib_dir, &out_dir),
            _ => unreachable!("target OS validated above"),
        }
        println!("cargo:rustc-link-search=native={out_dir}");
    }

    if target_os == "ios" {
        // iOS apps cannot ship loose dylibs the way an APK can, so the delivery
        // node is linked as a static archive. rln has to be named explicitly:
        // with no shared library there is no rpath to resolve it transitively.
        println!("cargo:rustc-link-lib=static=logosdelivery");
        println!("cargo:rustc-link-lib=static=rln");
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=dylib=logosdelivery");
    }
    println!("cargo:lib_dir={}", lib_dir.display());
}

/// Compile `csrc/shim.c`, which re-exports the library's `static inline` typed
/// helpers as linkable symbols, and link the TinyCBOR they encode with. The
/// headers sit beside the library in the same package (`<lib_dir>/../include`).
fn compile_shim(lib_dir: &Path) {
    let include_dir = lib_dir
        .parent()
        .map(|p| p.join("include"))
        .unwrap_or_default();
    let tinycbor = locate_tinycbor(lib_dir).unwrap_or_else(|| {
        panic!(
            "TinyCBOR not found: set TINYCBOR_DIR, or use a liblogosdelivery package \
             that propagates it (nix-support/propagated-build-inputs)"
        )
    });

    println!("cargo:rerun-if-changed=csrc/shim.c");
    cc::Build::new()
        .file("csrc/shim.c")
        .include(&include_dir)
        .include(tinycbor.join("include"))
        .compile("lcshim");

    println!(
        "cargo:rustc-link-search=native={}",
        tinycbor.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=tinycbor");
}

/// TinyCBOR's install prefix: `TINYCBOR_DIR`, else the copy the nix package
/// propagates to its consumers.
fn locate_tinycbor(lib_dir: &Path) -> Option<PathBuf> {
    println!("cargo:rerun-if-env-changed=TINYCBOR_DIR");
    if let Ok(dir) = std::env::var("TINYCBOR_DIR") {
        return Some(PathBuf::from(dir));
    }
    let propagated = lib_dir
        .parent()?
        .join("nix-support/propagated-build-inputs");
    fs::read_to_string(propagated)
        .ok()?
        .split_whitespace()
        .find(|p| p.contains("-tinycbor-"))
        .map(PathBuf::from)
}

/// Opt-in relocatable linking for builds that get shipped to other machines.
/// Off by default so existing consumers (and this repo's own tests) keep the
/// zero-glue absolute-path behaviour.
fn relocatable() -> bool {
    matches!(
        std::env::var("LOGOS_DELIVERY_RELOCATABLE").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Locate the native library directory as an ABSOLUTE, canonical path. Prefers
/// `LOGOS_DELIVERY_LIB_DIR`, then falls back to building it via nix. Returns
/// `None` when neither is available (e.g. `cargo check` without nix).
fn locate_lib_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("LOGOS_DELIVERY_LIB_DIR") {
        if let Some(resolved) = resolve_lib_dir(&dir) {
            return Some(resolved);
        }
        println!(
            "cargo:warning=LOGOS_DELIVERY_LIB_DIR='{dir}' could not be resolved; \
             falling back to `nix build`"
        );
    }
    resolve_lib_dir(&nix_build_logos_delivery()?)
}

/// Resolve a lib dir to an absolute, canonical path. Cargo runs build scripts
/// with the cwd set to the crate dir, but a relative value (e.g. CI's
/// `./result/lib`) is anchored at the flake/workspace root where `nix build`
/// drops `result`. Canonicalizing also follows the `result` symlink to the
/// immutable store path, so the stamped install name / soname stays stable.
fn resolve_lib_dir(dir: &str) -> Option<PathBuf> {
    let path = Path::new(dir);
    let anchored = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
        Path::new(&find_flake_root(&manifest)?).join(path)
    };
    // Re-run once the lib appears, so build order (nix build vs. cargo) is free.
    println!("cargo:rerun-if-changed={}", anchored.display());
    if let Some(parent) = anchored.parent() {
        println!("cargo:rerun-if-changed={}", parent.display());
    }
    anchored.canonicalize().ok()
}

/// Copy `liblogosdelivery.dylib` into `OUT_DIR` and rewrite its install name to
/// the absolute store path. The consumer records that absolute path, so dyld
/// loads the original file directly — whose own `@loader_path` RPATH resolves
/// `librln.dylib` beside it — with no RPATH needed on the consumer.
fn stamp_absolute_macos(lib_dir: &Path, out_dir: &str) {
    let src = lib_dir.join("liblogosdelivery.dylib");
    let dst = format!("{out_dir}/liblogosdelivery.dylib");
    copy_writable(&src, Path::new(&dst));
    run("install_name_tool", &["-id", path_str(&src), &dst]);
    println!("cargo:rerun-if-changed={}", src.display());
}

/// Linux equivalent: an absolute `DT_SONAME` is recorded verbatim in the
/// consumer's `DT_NEEDED`, so `ld.so` loads it by path with no RPATH. Requires
/// `patchelf` at build time (provided by the nix devshell).
fn stamp_absolute_linux(lib_dir: &Path, out_dir: &str) {
    let src = lib_dir.join("liblogosdelivery.so");
    let dst = format!("{out_dir}/liblogosdelivery.so");
    copy_writable(&src, Path::new(&dst));
    run("patchelf", &["--set-soname", path_str(&src), &dst]);
    println!("cargo:rerun-if-changed={}", src.display());
}

fn path_str(p: &Path) -> &str {
    p.to_str()
        .unwrap_or_else(|| panic!("non-UTF-8 path: {}", p.display()))
}

fn copy_writable(src: &Path, dst: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::copy(src, dst)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", src.display(), dst.display()));
    // Store-sourced files are read-only; restore owner write so the install
    // name / soname can be rewritten.
    fs::set_permissions(dst, fs::Permissions::from_mode(0o644)).unwrap();
}

fn run(cmd: &str, args: &[&str]) {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run `{cmd}`: {e}"));
    assert!(status.success(), "`{cmd} {args:?}` failed with {status}");
}

fn nix_build_logos_delivery() -> Option<String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let flake_root = find_flake_root(&manifest_dir)?;

    println!("cargo:rerun-if-changed={flake_root}/flake.lock");

    // Enable flakes inline so the fallback works without global nix.conf setup.
    let output = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            ".#logos-delivery",
            "--no-link",
            "--print-out-paths",
        ])
        .current_dir(&flake_root)
        .output()
        .ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("cargo:warning=nix build .#logos-delivery failed: {stderr}");
        return None;
    }

    let store_path = String::from_utf8(output.stdout).ok()?;
    let lib_dir = format!("{}/lib", store_path.trim());

    if std::path::Path::new(&lib_dir).exists() {
        Some(lib_dir)
    } else {
        None
    }
}

fn find_flake_root(start: &str) -> Option<String> {
    let mut path = std::path::PathBuf::from(start);
    loop {
        if path.join("flake.nix").exists() {
            return Some(path.to_string_lossy().into_owned());
        }
        if !path.pop() {
            return None;
        }
    }
}
