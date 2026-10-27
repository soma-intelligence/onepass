//! Embeds `Info.plist` in the macOS binary (`__TEXT,__info_plist`): a
//! sandboxed command-line tool needs a bundle identifier for its container,
//! and it names the relay for the app's code-signature check.

fn main() {
    println!("cargo:rerun-if-changed=Info.plist");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        println!(
            "cargo:rustc-link-arg-bin=onepass-relay=-Wl,-sectcreate,__TEXT,__info_plist,{dir}/Info.plist"
        );
    }
}
