use anyhow::{bail, Context, Result};
use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAGIC: &[u8; 8] = b"QSEAL001";
const MAX_PLAINTEXT: u64 = 256 * 1024 * 1024;
const FILE_CONTEXT: &[u8] = b"quantum-shield/file/v1";

fn validate_key_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("key ID must be 1-64 ASCII letters, digits, hyphens, or underscores");
    }
    Ok(())
}

fn key_store_dir() -> Result<PathBuf> {
    let home =
        std::env::var_os("HOME").context("HOME is not set; cannot locate the local key store")?;
    let dir = PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("quantum-shield")
        .join("keys");

    fs::create_dir_all(&dir)
        .with_context(|| format!("could not create local key directory {}", dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(&dir)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            bail!("local key directory must be a real directory, not a symlink");
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .context("could not restrict local key directory permissions")?;
        let actual = fs::metadata(&dir)?.permissions().mode();
        if actual & 0o077 != 0 {
            bail!("local key directory is accessible to group/others");
        }
    }

    Ok(dir)
}

fn key_path(id: &str) -> Result<PathBuf> {
    validate_key_id(id)?;
    Ok(key_store_dir()?.join(format!("{id}.key")))
}

pub(crate) fn generate_key(id: &str) -> Result<PathBuf> {
    let path = key_path(id)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    SystemRandom::new()
        .fill(&mut *key)
        .map_err(|_| anyhow::anyhow!("secure random key generation failed"))?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).with_context(|| {
        format!(
            "could not create key {}; refusing to overwrite an existing key",
            path.display()
        )
    })?;

    if let Err(error) = file.write_all(&key[..]).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(error).with_context(|| format!("could not persist key {}", path.display()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("could not restrict key-file permissions")?;
    }
    if let Err(error) = crate::key_management::record_event("created", id) {
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

pub(crate) fn list_keys() -> Result<Vec<String>> {
    let dir = key_store_dir()?;
    let mut ids = Vec::new();

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = name.strip_suffix(".key") else {
            continue;
        };

        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "key store contains an unexpected non-regular entry: {}",
                path.display()
            );
        }
        validate_key_id(id)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!(
                    "key file {} is accessible to group/others; restrict it to mode 600",
                    path.display()
                );
            }
        }

        if metadata.len() != KEY_LEN as u64 {
            bail!("key file {} has an unexpected length", path.display());
        }

        let status = if crate::key_management::is_revoked(id)? {
            " [REVOKED]"
        } else {
            ""
        };
        ids.push(format!("{id}{status}"));
    }

    ids.sort();
    Ok(ids)
}

fn load_key(id: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let path = key_path(id)?;
    let meta = fs::symlink_metadata(&path)
        .with_context(|| format!("could not inspect key file {}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("key path must be a regular file, not a symlink");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!(
                "key file {} is accessible to group/others; restrict it to mode 600",
                path.display()
            );
        }
    }

    let raw = Zeroizing::new(read_bounded(&path, KEY_LEN as u64)?);
    if raw.len() != KEY_LEN {
        bail!(
            "key file {} must contain exactly {KEY_LEN} bytes",
            path.display()
        );
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&raw);
    Ok(key)
}

fn make_aad(id: &str, context: &[u8]) -> Result<Vec<u8>> {
    validate_key_id(id)?;
    if context.len() > 65_536 {
        bail!("encryption context exceeds 64 KiB");
    }
    let id_bytes = id.as_bytes();
    let mut aad = Vec::with_capacity(MAGIC.len() + 2 + id_bytes.len() + 8 + context.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
    aad.extend_from_slice(id_bytes);
    aad.extend_from_slice(&(context.len() as u64).to_be_bytes());
    aad.extend_from_slice(context);
    Ok(aad)
}

fn seal_with_key(key_bytes: &[u8], id: &str, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    if key_bytes.len() != KEY_LEN {
        bail!("invalid AES-256 key length");
    }
    if plaintext.len() as u64 > MAX_PLAINTEXT {
        bail!("payload exceeds the 256 MiB per-operation limit");
    }
    let aad = make_aad(id, context)?;
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
        .map_err(|_| anyhow::anyhow!("could not initialize AES-256-GCM"))?;
    let key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("secure random nonce generation failed"))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad.as_slice()), &mut ciphertext)
        .map_err(|_| anyhow::anyhow!("AES-256-GCM encryption failed"))?;

    let mut envelope = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn open_with_key(key_bytes: &[u8], id: &str, envelope: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    if key_bytes.len() != KEY_LEN {
        bail!("invalid AES-256 key length");
    }
    if envelope.len() < MAGIC.len() + NONCE_LEN + TAG_LEN {
        bail!("encrypted input is truncated");
    }
    if envelope.len() as u64 > MAX_PLAINTEXT + (MAGIC.len() + NONCE_LEN + TAG_LEN) as u64 {
        bail!("encrypted input exceeds the 256 MiB per-operation limit");
    }
    if &envelope[..MAGIC.len()] != MAGIC {
        bail!("input is not a supported Quantum Shield encrypted file");
    }

    let nonce_bytes: [u8; NONCE_LEN] = envelope[MAGIC.len()..MAGIC.len() + NONCE_LEN]
        .try_into()
        .context("invalid encryption nonce")?;
    let aad = make_aad(id, context)?;
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
        .map_err(|_| anyhow::anyhow!("could not initialize AES-256-GCM"))?;
    let key = LessSafeKey::new(unbound);
    let mut plaintext = envelope[MAGIC.len() + NONCE_LEN..].to_vec();

    let plaintext_len = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad.as_slice()),
            &mut plaintext,
        )
        .map_err(|_| {
            anyhow::anyhow!("authentication failed: wrong key/context or modified ciphertext")
        })?
        .len();

    plaintext.truncate(plaintext_len);
    Ok(plaintext)
}

pub(crate) fn encrypt_payload(id: &str, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    crate::key_management::ensure_active(id)?;
    let key = load_key(id)?;
    let envelope = seal_with_key(&key[..], id, plaintext, context)?;
    crate::key_management::record_event("encrypted", id)?;
    Ok(envelope)
}

pub(crate) fn decrypt_payload(id: &str, envelope: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let key = load_key(id)?;
    let plaintext = open_with_key(&key[..], id, envelope, context)?;
    crate::key_management::record_event("decrypted", id)?;
    Ok(plaintext)
}

fn open_regular_input(path: &Path) -> Result<File> {
    // Reject symlinks and special files before opening. O_NOFOLLOW plus O_NONBLOCK closes
    // the symlink race and prevents a swapped FIFO from blocking the CLI indefinitely.
    let link_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect input {}", path.display()))?;
    if !link_metadata.file_type().is_file() {
        bail!(
            "input must be a regular non-symlink file: {}",
            path.display()
        );
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("could not safely open regular input {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!(
            "input changed to a non-regular file while opening: {}",
            path.display()
        );
    }
    Ok(file)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = open_regular_input(path)?;
    if file.metadata()?.len() > limit {
        bail!("{} exceeds the configured size limit", path.display());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() as u64 > limit {
        bail!(
            "{} grew beyond the configured size limit while being read",
            path.display()
        );
    }
    Ok(bytes)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).with_context(|| {
        format!(
            "could not create {}; output must not already exist",
            path.display()
        )
    })?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error).with_context(|| format!("could not write {}", path.display()));
    }
    Ok(())
}

pub(crate) fn encrypt_file(id: &str, input: &Path, output: &Path) -> Result<()> {
    let plaintext = Zeroizing::new(read_bounded(input, MAX_PLAINTEXT)?);
    let envelope = encrypt_payload(id, &plaintext, FILE_CONTEXT)?;
    write_new_private(output, &envelope)?;
    Ok(())
}

pub(crate) fn decrypt_file(id: &str, input: &Path, output: &Path) -> Result<()> {
    let envelope = read_bounded(
        input,
        MAX_PLAINTEXT + (MAGIC.len() + NONCE_LEN + TAG_LEN) as u64,
    )?;
    let plaintext = Zeroizing::new(decrypt_payload(id, &envelope, FILE_CONTEXT)?);
    write_new_private(output, &plaintext)?;
    Ok(())
}

/// Encrypt a bounded payload file with authenticated application context.
pub(crate) fn encrypt_payload_file(
    id: &str,
    input: &Path,
    output: &Path,
    context: &[u8],
) -> Result<()> {
    if context.is_empty() || context.len() > 65_536 {
        bail!("context must be between 1 byte and 64 KiB");
    }
    let plaintext = Zeroizing::new(read_bounded(input, MAX_PLAINTEXT)?);
    let envelope = encrypt_payload(id, &plaintext, context)?;
    write_new_private(output, &envelope)?;
    Ok(())
}

/// Decrypt a payload only with the original authenticated context.
pub(crate) fn decrypt_payload_file(
    id: &str,
    input: &Path,
    output: &Path,
    context: &[u8],
) -> Result<()> {
    if context.is_empty() || context.len() > 65_536 {
        bail!("context must be between 1 byte and 64 KiB");
    }
    let max_envelope = MAX_PLAINTEXT + (MAGIC.len() + NONCE_LEN + TAG_LEN) as u64;
    let envelope = read_bounded(input, max_envelope)?;
    let plaintext = Zeroizing::new(decrypt_payload(id, &envelope, context)?);
    write_new_private(output, &plaintext)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Zeroizing<[u8; KEY_LEN]> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(11);
        }
        key
    }

    #[test]
    fn aes_gcm_round_trip_preserves_binary_payload() {
        let key = test_key();
        let input = b"ordinary website content\0binary\xffpayload";
        let envelope = seal_with_key(&key[..], "test-key", input, b"test-context").unwrap();
        let output = open_with_key(&key[..], "test-key", &envelope, b"test-context").unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn aes_gcm_rejects_wrong_context_and_key_id() {
        let key = test_key();
        let envelope = seal_with_key(&key[..], "key-a", b"secret", b"record-17").unwrap();
        assert!(open_with_key(&key[..], "key-a", &envelope, b"record-18").is_err());
        assert!(open_with_key(&key[..], "key-b", &envelope, b"record-17").is_err());
    }

    #[test]
    fn aes_gcm_rejects_modified_ciphertext() {
        let key = test_key();
        let mut envelope =
            seal_with_key(&key[..], "test-key", b"authenticate me", b"file").unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        assert!(open_with_key(&key[..], "test-key", &envelope, b"file").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_io_rejects_symlink_inputs_directories_and_existing_symlink_outputs() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "qs-crypto-file-guard-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create temporary test directory");
        let target = root.join("target.txt");
        let input_link = root.join("input-link.txt");
        let output_link = root.join("output-link.txt");
        fs::write(&target, b"original-data").expect("write target fixture");
        symlink(&target, &input_link).expect("create input symlink");
        symlink(&target, &output_link).expect("create output symlink");

        assert!(read_bounded(&input_link, 1024).is_err());
        assert!(read_bounded(&root, 1024).is_err());
        assert!(write_new_private(&output_link, b"replacement").is_err());
        assert_eq!(
            fs::read(&target).expect("read original target"),
            b"original-data"
        );
        fs::remove_dir_all(&root).expect("remove temporary test directory");
    }
}
