//! Copy the WinDivert runtime artifacts (WinDivert.dll + WinDivert64.sys) next
//! to the output binary so it runs without manually staging them. Only does
//! anything on Windows.

#[cfg(target_os = "windows")]
fn main() {
    use std::path::PathBuf;

    println!("cargo:rerun-if-changed=../../vendor/windivert/WinDivert-2.2.2-A/x64/WinDivert.dll");
    println!("cargo:rerun-if-changed=../../vendor/windivert/WinDivert-2.2.2-A/x64/WinDivert64.sys");

    // Workspace root → vendor/...
    let manifest_dir: PathBuf = std::env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let src = workspace_root.join("vendor/windivert/WinDivert-2.2.2-A/x64");

    // OUT_DIR is .../target/{profile}/build/gr-capture-{hash}/out
    // We want    .../target/{profile}/  — go up 3 levels.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_profile_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("walk up to target/{profile}/")
        .to_path_buf();
    let example_dir = target_profile_dir.join("examples");
    std::fs::create_dir_all(&example_dir).ok();

    for fname in ["WinDivert.dll", "WinDivert64.sys"] {
        let src_path = src.join(fname);
        if src_path.exists() {
            for dst_dir in [&target_profile_dir, &example_dir] {
                let dst_path = dst_dir.join(fname);
                if let Err(e) = std::fs::copy(&src_path, &dst_path) {
                    println!("cargo:warning=failed to copy {fname} to {}: {e}", dst_dir.display());
                }
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    // No-op on non-Windows.
}
