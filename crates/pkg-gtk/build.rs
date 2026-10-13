use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=data/window.blp");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("window.ui");
    let status = Command::new("blueprint-compiler")
        .arg("compile")
        .arg("--output")
        .arg(output)
        .arg("data/window.blp")
        .status()
        .expect("Install blueprint-compiler to build pkg-gtk");
    assert!(status.success(), "Blueprint compilation failed");
}
