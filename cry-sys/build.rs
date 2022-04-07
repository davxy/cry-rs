use std::ffi::OsStr;
use walkdir::WalkDir;

fn collect_sources(root: &str) -> Vec<String> {
    let mut src = vec![];
    for entry in WalkDir::new(root) {
        let file = entry.unwrap();
        let path = file.path();
        if path.extension() == Some(OsStr::new("c")) {
            src.push(path.display().to_string());
        }
    }
    src
}

fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=cry/include/cry/cry.h");
    println!("cargo:rerun-if-changed=cry/libcry.a");

    bindgen::Builder::default()
        .use_core()
        .header("cry/include/cry/cry.h")
        .clang_arg("-Icry/include")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/bindings.rs")
        .expect("Unable to write bindings");

    let src = collect_sources("cry/src");

    cc::Build::new()
        .include("cry/include")
        .include("cry/src")
        .files(src.iter())
        .compile("libcry");
}
