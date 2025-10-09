use std::env;
use std::fmt;
use std::path::PathBuf;

fn main() {
  let ws_dir = std::env::var("WS_DIR").expect("WS_DIR not set");

  println!("cargo:rustc-link-lib=wireshark");
  println!("cargo:rustc-link-lib=wiretap");
  println!("cargo:rustc-link-lib=wsutil");
  println!("cargo:rustc-link-lib=glib-2.0");

  // Tell cargo to look for shared libraries in the specified directory
  // shared library.
  println!("cargo:rustc-link-search={}/build/run/", ws_dir);
  // println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu/");

  let mut clang_args: Vec<String> = vec![
    "-I/usr/lib/x86_64-linux-gnu/glib-2.0/include".into(),
    "-I/usr/include/".into(),
    "-I/usr/include/glib-2.0/".into(),
  ];

  clang_args.extend([
    format!("-I{}/", ws_dir),
    format!("-I{}/include/", ws_dir),
    format!("-I{}/wiretap/", ws_dir),
    format!("-I{}/wsutil/", ws_dir),
    format!("-I{}/build/", ws_dir),
  ]);

  // The bindgen::Builder is the main entry point
  // to bindgen, and lets you build up options for
  // the resulting bindings.
  let bindings = bindgen::Builder::default()
    // The input header we would like to generate
    // bindings for.
    .clang_args(&clang_args)
    .emit_clang_ast()
    .header("wrapper.h")
    // Tell cargo to invalidate the built crate whenever any of the
    // included header files changed.
    .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    // Finish the builder and generate the bindings.
    .generate()
    // Unwrap the Result and panic on failure.
    .expect("Unable to generate bindings");

  // Write the bindings to the $OUT_DIR/bindings.rs file.
  let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
  bindings
    .write_to_file(out_path.join("bindings.rs"))
    .expect("Couldn't write bindings!");
}
