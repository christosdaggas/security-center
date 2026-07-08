use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), String> {
    let out_dir = PathBuf::from(
        env::var("OUT_DIR").map_err(|e| format!("OUT_DIR not set: {}", e))?,
    );
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").map_err(|e| format!("CARGO_MANIFEST_DIR not set: {}", e))?,
    );
    
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
            Ok(())
        }
        Ok(s) => Err(format!(
            "glib-compile-resources failed with status {}. Install the glib2 development tools.",
            s
        )),
        Err(e) => Err(format!(
            "Failed to run glib-compile-resources: {}. Install the glib2 development tools.",
            e
        )),
    }
}
