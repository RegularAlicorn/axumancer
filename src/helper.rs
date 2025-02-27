use std::path::{Path, PathBuf};

use tracing::error;

pub fn file_exists_safe(base_dir: &Path, file_path: &str) -> bool {
    if let Ok(resolved_path) = resolve_safe_path(base_dir, file_path) {
        resolved_path.try_exists().unwrap_or(false)
    } else {
        false
    }
}

// Securing against path traversal attacks ("../")
fn resolve_safe_path(base_dir: &Path, file_path: &str) -> Result<PathBuf, ()> {
    let base_dir = base_dir.canonicalize().map_err(|_| {
        error!("Invalid base directory {:?}", base_dir);
    })?;

    let full_path = base_dir.join(file_path);
    let full_path_canonical = full_path.canonicalize().map_err(|p| {
        error!("Invalid file path {:?} - {:?}", full_path, p);
    })?;

    if full_path_canonical.starts_with(&base_dir) {
        Ok(full_path_canonical)
    } else {
        error!(
            "Potential directory traversal attack. Path: {}",
            full_path_canonical.to_str().unwrap_or("")
        );
        Err(())
    }
}
