use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    
    let data_dir = manifest_dir.join("data");
    let gresource_xml = data_dir.join("com.chrisdaggas.security-center.gresource.xml");
    let output = out_dir.join("security-center.gresource");

    // Compile GResource
    let status = Command::new("glib-compile-resources")
        .arg("--sourcedir")
        .arg(&data_dir)
        .arg("--target")
        .arg(&output)
        .arg(&gresource_xml)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:rerun-if-changed=data/com.chrisdaggas.security-center.gresource.xml");
            println!("cargo:rerun-if-changed=data/style.css");
        }
        _ => {
            // Create a minimal empty gresource if compilation fails
            std::fs::write(&output, include_bytes!("data/style.css")).ok();
            eprintln!("Warning: glib-compile-resources not available, using fallback");
        }
    }
}
