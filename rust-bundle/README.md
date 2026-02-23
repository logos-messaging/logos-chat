# rust-bundle

A minimal Rust `staticlib` crate that bundles `libchat` and `rln` into a single archive (`liblogoschat_rust_bundle.a`), suitable for static linking into the Nim application.

## Motivation

`libchat` and `rln` are both Rust crates. Linking them as separate static archives (`.a` files) causes duplicate symbol errors at link time, because each archive would embed its own copy of the Rust standard library.

By declaring both as `rlib` dependencies of a single `staticlib` crate, rustc resolves and links everything in one pass. The resulting `liblogoschat_rust_bundle.a` exposes all `#[no_mangle] pub extern "C"` symbols from both crates without any stdlib duplication.

This approach follows the guidance in the official Rust Reference: https://doc.rust-lang.org/reference/linkage.html#mixed-rust-and-foreign-codebases.

## Build

```sh
cargo build --release --manifest-path rust-bundle/Cargo.toml
```

Output: `rust-bundle/target/release/liblogoschat_rust_bundle.a`

From the project root, use the `build-bundle` Makefile target, which handles this after building `librln` from the nwaku vendor tree.

## Dependencies

| Crate | Path |
|-------|------|
| `libchat` | `vendor/libchat/conversations` |
| `rln` | `vendor/nwaku/vendor/zerokit/rln` |
