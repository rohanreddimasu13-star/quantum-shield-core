use anyhow::{bail, Context, Result};
use std::{
    env, fs,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_TREE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 250_000;

const APPLICATION_MARKERS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "Dockerfile",
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
];

struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    fn create() -> Result<Self> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_nanos();

        for attempt in 0..100u32 {
            let path = env::temp_dir().join(format!(
                "quantum-shield-protect-{}-{stamp}-{attempt}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }

            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "could not create private temporary directory {}",
                            path.display()
                        )
                    })
                }
            }
        }

        bail!("could not allocate a unique private temporary directory")
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn detect_local_kind(path: &Path) -> Result<&'static str> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect target {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing to auto-detect a symlink target: {}",
            path.display()
        );
    }
    if metadata.is_file() {
        return Ok("file");
    }
    if !metadata.is_dir() {
        bail!("target must be a regular file or directory");
    }

    let canonical = path.canonicalize()?;
    ensure_reasonable_directory_scope(&canonical)?;

    if has_git_marker(&canonical) {
        return Ok("repository");
    }
    if has_application_marker(&canonical) {
        return Ok("application");
    }
    bail!(
        "cannot safely classify directory {}; pass --kind repository or --kind application after checking the target",
        canonical.display()
    );
}

pub(crate) fn protect_local(kind: &str, input: &Path, key_id: &str, output: &Path) -> Result<()> {
    let initial_metadata = fs::symlink_metadata(input)
        .with_context(|| format!("cannot inspect target {}", input.display()))?;
    if initial_metadata.file_type().is_symlink() {
        bail!("refusing a symlink as the target root");
    }

    let source = input
        .canonicalize()
        .with_context(|| format!("cannot resolve target {}", input.display()))?;
    let metadata = fs::metadata(&source)?;
    let selected_kind = if kind == "auto" {
        detect_local_kind(&source)?
    } else {
        kind
    };

    match selected_kind {
        "file" if !metadata.is_file() => {
            bail!("--kind file requires a regular file target")
        }
        "repository" | "application" if !metadata.is_dir() => {
            bail!("repository/application protection requires a directory target")
        }
        "repository" if !has_git_marker(&source) => {
            bail!("target has no regular .git directory/file; refusing repository classification")
        }
        "application" if !has_application_marker(&source) => {
            bail!("target has no recognized top-level application manifest; no output was created")
        }
        "file" | "repository" | "application" => {}
        _ => bail!("unsupported local target kind"),
    }

    if metadata.is_dir() {
        ensure_reasonable_directory_scope(&source)?;
    }

    let output = resolve_new_output(output)?;
    if metadata.is_dir() && output.starts_with(&source) {
        bail!("output must be outside the source directory to prevent self-inclusion");
    }

    let temp = PrivateTempDir::create()?;
    let plaintext_to_encrypt = if selected_kind == "file" {
        if metadata.len() > MAX_TREE_BYTES {
            bail!("file exceeds the 256 MiB per-operation encryption limit");
        }
        source.clone()
    } else {
        measure_directory(&source)?;
        let archive = temp.path.join("source.tar.gz");
        let status = Command::new("tar")
            .arg("--create")
            .arg("--gzip")
            .arg("--one-file-system")
            .arg("--file")
            .arg(&archive)
            .arg("--directory")
            .arg(&source)
            .arg(".")
            .status()
            .context("could not start tar; install a compatible tar utility")?;
        if !status.success() {
            bail!("archive creation failed (tar exit status: {status}); no encrypted output was reported");
        }
        let archive_size = fs::metadata(&archive)
            .with_context(|| "tar did not create the expected archive")?
            .len();
        if archive_size > MAX_TREE_BYTES {
            bail!("compressed source archive exceeds the 256 MiB per-operation encryption limit");
        }
        archive
    };

    let verification_path = temp.path.join("verified.plain");
    crate::crypto::encrypt_file(key_id, &plaintext_to_encrypt, &output)
        .context("encryption failed; source was not modified")?;

    let verification = (|| -> Result<bool> {
        crate::crypto::decrypt_file(key_id, &output, &verification_path)
            .context("could not authenticate/decrypt the newly encrypted output")?;
        files_equal(&plaintext_to_encrypt, &verification_path)
    })();

    match verification {
        Ok(true) => {}
        Ok(false) => {
            let _ = fs::remove_file(&output);
            bail!("verification mismatch; the encrypted output was removed, and the source remains unchanged");
        }
        Err(error) => {
            let _ = fs::remove_file(&output);
            return Err(error).context(
                "encrypted output failed its verification step and was removed; source remains unchanged",
            );
        }
    }

    println!("PASS: protection output was decrypted and verified against the source.");
    println!("Target type : {selected_kind}");
    println!("Encrypted   : {}", output.display());
    println!("Source      : retained unchanged");
    if selected_kind != "file" {
        println!("Bundle      : compressed source snapshot; it does not encrypt the live application or repository in place");
    }
    Ok(())
}

fn has_git_marker(root: &Path) -> bool {
    matches!(
        fs::symlink_metadata(root.join(".git")),
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && (metadata.is_file() || metadata.is_dir())
    )
}

fn has_application_marker(root: &Path) -> bool {
    APPLICATION_MARKERS.iter().any(|marker| {
        matches!(
            fs::symlink_metadata(root.join(marker)),
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink()
        )
    })
}

fn ensure_reasonable_directory_scope(path: &Path) -> Result<()> {
    if path == Path::new("/") {
        bail!("refusing to bundle the filesystem root");
    }

    if let Some(home_value) = env::var_os("HOME") {
        if let Ok(home) = PathBuf::from(home_value).canonicalize() {
            if path == home || home.parent().is_some_and(|parent| path == parent) {
                bail!("refusing to bundle the home directory or its parent; select a specific project directory");
            }
        }
    }

    Ok(())
}

fn measure_directory(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0usize;
    let mut total_bytes = 0u64;

    while let Some(path) = pending.pop() {
        entries += 1;
        if entries > MAX_TREE_ENTRIES {
            bail!("source directory exceeds the 250,000-entry safety limit");
        }

        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .with_context(|| format!("cannot read directory {}", path.display()))?
            {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .context("source file-size total overflowed")?;
            if total_bytes > MAX_TREE_BYTES {
                bail!("source tree exceeds the 256 MiB safety budget");
            }
        } else {
            bail!(
                "refusing to bundle special filesystem entry {}",
                path.display()
            );
        }
    }

    Ok(())
}

fn resolve_new_output(path: &Path) -> Result<PathBuf> {
    let filename = path
        .file_name()
        .context("output must include a file name")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .with_context(|| format!("output parent does not exist: {}", path.display()))?;
    let resolved = parent.join(filename);

    match fs::symlink_metadata(&resolved) {
        Ok(_) => bail!(
            "output already exists; refusing to overwrite {}",
            resolved.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("could not inspect output path {}", resolved.display()))
        }
    }

    Ok(resolved)
}

fn files_equal(left: &Path, right: &Path) -> Result<bool> {
    let mut left_file =
        File::open(left).with_context(|| format!("cannot read {}", left.display()))?;
    let mut right_file =
        File::open(right).with_context(|| format!("cannot read {}", right.display()))?;
    let mut left_buf = [0u8; 64 * 1024];
    let mut right_buf = [0u8; 64 * 1024];

    loop {
        let left_len = left_file.read(&mut left_buf)?;
        let right_len = right_file.read(&mut right_buf)?;
        if left_len != right_len || left_buf[..left_len] != right_buf[..right_len] {
            return Ok(false);
        }
        if left_len == 0 {
            return Ok(true);
        }
    }
}

/// Prints an offline OS/cloud protection plan without accessing devices,
/// credentials or provider APIs. It never reports actual encryption success.
pub(crate) fn simulate_protection(target: &str, provider: Option<&str>) -> anyhow::Result<()> {
    match target {
        "os" => {
            println!("=== QUANTUM SHIELD OS-DISK SIMULATION ===");
            println!("Mode: SIMULATION ONLY");
            println!("1. Identify a candidate installation disk.");
            println!("2. Reject mounted disks, existing signatures and the running root disk.");
            println!("3. Require explicit device confirmation and verified recovery material.");
            println!("4. Plan LUKS2 initialization for a separate blank disk.");
            println!("5. Verify the LUKS2 header after initialization.");
            println!("6. Plan OS installation, initramfs, crypttab and bootloader configuration.");
            println!("RESULT: simulation only; no disk was accessed or changed.");
        }
        "cloud-server" => {
            let providers: Vec<&str> = match provider {
                Some("aws") => vec!["aws"],
                Some("gcp") => vec!["gcp"],
                Some("azure") => vec!["azure"],
                Some(_) => anyhow::bail!("provider must be aws, gcp or azure"),
                None => vec!["aws", "gcp", "azure"],
            };
            println!("=== QUANTUM SHIELD CLOUD-DISK SIMULATION ===");
            println!("Mode: SIMULATION ONLY; no network calls, credentials or cloud CLIs.");
            for p in providers {
                println!();
                println!("[{}]", p.to_ascii_uppercase());
                match p {
                    "aws" => {
                        println!("1. Inspect the EC2 root EBS encryption status.");
                        println!(
                            "2. Plan an encrypted snapshot and replacement volume if required."
                        );
                        println!(
                            "3. Verify encryption metadata before separately approved cutover."
                        );
                    }
                    "gcp" => {
                        println!("1. Inspect Compute Engine boot-disk encryption.");
                        println!("2. Plan a CMEK-protected replacement if requested.");
                        println!("3. Verify key metadata before separately approved cutover.");
                    }
                    "azure" => {
                        println!("1. Inspect managed OS-disk encryption and Disk Encryption Set.");
                        println!("2. Plan an encrypted snapshot and replacement disk if required.");
                        println!("3. Verify key metadata before separately approved cutover.");
                    }
                    _ => unreachable!(),
                }
            }
            println!();
            println!("RESULT: simulation only; no VM, disk, snapshot or key was changed.");
            println!("A real migration needs authenticated access, recovery testing and a verified cutover.");
        }
        _ => anyhow::bail!("unsupported simulation target"),
    }
    Ok(())
}
