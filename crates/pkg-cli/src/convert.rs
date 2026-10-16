use std::{error::Error, path::Path};

pub use pkg_ops::convert::run_with_progress;

pub fn run(base: &Path, output: &Path, update: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let mut last = 0;
    run_with_progress(
        base,
        output,
        update,
        || false,
        |written, total| {
            if written - last >= 64 * 1024 * 1024 || written == total {
                eprintln!("Archived {written}/{total} bytes");
                last = written;
            }
        },
    )?;
    eprintln!("Archive complete: {}", output.display());
    if update.is_some() {
        eprintln!(
            "Archive complete: {}",
            pkg_ops::convert::update_path(output)?.display()
        );
    }
    Ok(())
}
