// Force both rlibs into this staticlib.
// Their #[no_mangle] pub extern "C" symbols are exported from librust_bundle.a.
extern crate libchat;
extern crate rln;
