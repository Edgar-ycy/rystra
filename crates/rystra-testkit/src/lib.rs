use std::path::PathBuf;

/// Returns the workspace Cargo.toml path.
pub fn workspace_manifest_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("Cargo.toml"))
        .expect("rystra-testkit must live under crates/ in the workspace")
}
