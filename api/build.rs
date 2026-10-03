// build.rs
fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let def_file = format!("{}/exports.def", manifest_dir);

    // Pass the module definition file to the MSVC linker
    println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def_file);

    // Link required Windows system libraries
    println!("cargo:rustc-link-lib=cfgmgr32");
    println!("cargo:rustc-link-lib=iphlpapi");
    println!("cargo:rustc-link-lib=setupapi");
    println!("cargo:rustc-link-lib=shlwapi");
    println!("cargo:rustc-link-lib=version");
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=ntdll");
    println!("cargo:rustc-link-lib=ole32");
    println!("cargo:rustc-link-lib=swdevice");
    println!("cargo:rustc-link-lib=onecore");

    // Re-run if exports.def changes
    println!("cargo:rerun-if-changed=exports.def");
}
