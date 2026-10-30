use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"QSKW0001";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + SALT_LEN + NONCE_LEN;
const MAX_AUDIT_BYTES: u64 = 4 * 1024 * 1024;

fn validate_id(id: &str) -> Result<()> {
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

fn dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    let path = PathBuf::from(home).join(".local/state/quantum-shield/keys");
    fs::create_dir_all(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            bail!("key directory must be a real directory, not a symlink");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(path)
}

fn key_path(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(dir()?.join(format!("{id}.key")))
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(crate) fn record_event(action: &str, id: &str) -> Result<()> {
    validate_id(id)?;
    if !matches!(
        action,
        "created"
            | "encrypted"
            | "decrypted"
            | "wrapped-export"
            | "wrapped-import"
            | "rotated"
            | "revoked"
    ) {
        bail!("invalid audit event");
    }
    let path = dir()?.join("audit.log");
    if path.exists() {
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            bail!("audit log must be a regular file, not a symlink");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                bail!("audit log permissions are too broad; use mode 600");
            }
        }
    }
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path)?;
    writeln!(file, "{}\t{}\t{}", now()?, action, id)?;
    file.sync_data()?;
    Ok(())
}

pub(crate) fn read_audit_log() -> Result<String> {
    let path = dir()?.join("audit.log");
    if !path.exists() {
        return Ok("No key-management audit events yet.\n".to_owned());
    }
    let meta = fs::symlink_metadata(&path)?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_AUDIT_BYTES {
        bail!("audit log is not a regular bounded file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("audit log permissions are too broad; use mode 600");
        }
    }
    Ok(fs::read_to_string(path)?)
}

fn read_file(path: &Path, max: u64, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > max {
        bail!(
            "{} must be a regular non-symlink file within size limit",
            path.display()
        );
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("private key permissions are too broad; use mode 600");
        }
    }

    // Do not follow symlinks at open time: the path could be swapped between the
    // metadata check above and the open below (TOCTOU), or point at a FIFO/device.
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts
        .open(path)
        .with_context(|| format!("could not safely open {}", path.display()))?;

    // Re-validate the object actually opened so a swap cannot bypass the checks.
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > max {
        bail!(
            "{} changed to a non-regular or oversized file while opening",
            path.display()
        );
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if opened.permissions().mode() & 0o077 != 0 {
            bail!("private key permissions are too broad; use mode 600");
        }
    }

    let mut buf = Zeroizing::new(Vec::new());
    file.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        bail!("file grew beyond its size limit");
    }
    Ok(buf)
}

fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("could not create {}; refusing to overwrite", path.display()))?;
    if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e).with_context(|| format!("could not write {}", path.display()));
    }
    Ok(())
}

fn prompt_new_passphrase() -> Result<Zeroizing<String>> {
    let a = Zeroizing::new(rpassword::prompt_password(
        "Choose wrapping passphrase (12+ characters): ",
    )?);
    if a.len() < 12 {
        bail!("wrapping passphrase must be at least 12 bytes");
    }
    let b = Zeroizing::new(rpassword::prompt_password("Repeat wrapping passphrase: ")?);
    if *a != *b {
        bail!("passphrases did not match");
    }
    Ok(a)
}

fn prompt_passphrase() -> Result<Zeroizing<String>> {
    let p = Zeroizing::new(rpassword::prompt_password("Wrapping passphrase: ")?);
    if p.is_empty() {
        bail!("passphrase cannot be empty");
    }
    Ok(p)
}

fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2id parameters: {e:?}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *output)
        .map_err(|e| anyhow::anyhow!("Argon2id derivation failed: {e}"))?;
    Ok(output)
}

fn aad(id: &str, header: &[u8]) -> Result<Vec<u8>> {
    validate_id(id)?;
    let mut out = Vec::with_capacity(header.len() + id.len());
    out.extend_from_slice(header);
    out.extend_from_slice(id.as_bytes());
    Ok(out)
}

fn wrap_bytes(id: &str, key_bytes: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if key_bytes.len() != KEY_LEN {
        bail!("source key must be exactly 32 bytes");
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| anyhow::anyhow!("salt generation failed"))?;
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("nonce generation failed"))?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);

    let kek = derive_kek(passphrase, &salt)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &kek[..])
        .map_err(|_| anyhow::anyhow!("could not initialize AES-256-GCM"))?;
    let cipher = LessSafeKey::new(unbound);
    let aad = aad(id, &header)?;
    let mut ciphertext = key_bytes.to_vec();
    cipher
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad.as_slice()),
            &mut ciphertext,
        )
        .map_err(|_| anyhow::anyhow!("key wrapping failed"))?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

fn unwrap_bytes(id: &str, wrapped: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    if wrapped.len() != HEADER_LEN + KEY_LEN + TAG_LEN || &wrapped[..8] != MAGIC {
        bail!("unsupported or malformed wrapped-key file");
    }
    let salt = &wrapped[8..8 + SALT_LEN];
    let nonce_start = 8 + SALT_LEN;
    let nonce: [u8; NONCE_LEN] = wrapped[nonce_start..nonce_start + NONCE_LEN]
        .try_into()
        .context("malformed wrapped-key nonce")?;
    let header = &wrapped[..HEADER_LEN];
    let aad = aad(id, header)?;
    let kek = derive_kek(passphrase, salt)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &kek[..])
        .map_err(|_| anyhow::anyhow!("could not initialize AES-256-GCM"))?;
    let cipher = LessSafeKey::new(unbound);
    let mut plaintext = Zeroizing::new(wrapped[HEADER_LEN..].to_vec());
    let len = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad.as_slice()),
            &mut plaintext,
        )
        .map_err(|_| anyhow::anyhow!("unwrap failed: wrong passphrase, key ID, or modified file"))?
        .len();
    plaintext.truncate(len);
    if plaintext.len() != KEY_LEN {
        bail!("unwrapped key has an invalid size");
    }
    Ok(plaintext)
}

pub(crate) fn wrap_key(id: &str, output: &Path) -> Result<()> {
    let src = key_path(id)?;
    let key = read_file(&src, KEY_LEN as u64, true)?;
    if key.len() != KEY_LEN {
        bail!("stored key has unexpected length");
    }
    let pass = prompt_new_passphrase()?;
    let wrapped = wrap_bytes(id, &key, &pass)?;
    write_new(output, &wrapped, true)?;
    if let Err(e) = record_event("wrapped-export", id) {
        let _ = fs::remove_file(output);
        return Err(e);
    }
    Ok(())
}

pub(crate) fn unwrap_key(id: &str, input: &Path) -> Result<()> {
    let wrapped = read_file(input, (HEADER_LEN + KEY_LEN + TAG_LEN) as u64, false)?;
    let pass = prompt_passphrase()?;
    let key = unwrap_bytes(id, &wrapped, &pass)?;
    let target = key_path(id)?;
    write_new(&target, &key, true)?;
    if let Err(e) = record_event("wrapped-import", id) {
        let _ = fs::remove_file(&target);
        return Err(e);
    }
    Ok(())
}

fn revocation_marker_state(marker: &Path) -> Result<bool> {
    let meta = match fs::symlink_metadata(marker) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("could not inspect revocation marker {}", marker.display())
            });
        }
    };

    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("revocation marker must be a regular non-symlink file");
    }

    Ok(true)
}

pub(crate) fn is_revoked(id: &str) -> Result<bool> {
    let id = validate_and_return(id)?;
    let marker = dir()?.join(format!("{id}.revoked"));
    revocation_marker_state(&marker)
}

fn validate_and_return(id: &str) -> Result<&str> {
    validate_id(id)?;
    Ok(id)
}

pub(crate) fn ensure_active(id: &str) -> Result<()> {
    if is_revoked(id)? {
        bail!("key '{id}' is revoked for new encryption; rotate to a successor key");
    }
    Ok(())
}

pub(crate) fn revoke_key(id: &str) -> Result<()> {
    let key = key_path(id)?;
    let key_bytes = read_file(&key, KEY_LEN as u64, true)?;
    if key_bytes.len() != KEY_LEN {
        bail!("key has unexpected length");
    }
    let marker = dir()?.join(format!("{id}.revoked"));
    write_new(&marker, format!("revoked_at={}\n", now()?).as_bytes(), true)?;
    if let Err(e) = record_event("revoked", id) {
        let _ = fs::remove_file(&marker);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_key_round_trip_and_context_binding() {
        let key = [42u8; KEY_LEN];
        let wrapped = wrap_bytes("test-id", &key, "a strong test passphrase").unwrap();
        assert_eq!(
            &unwrap_bytes("test-id", &wrapped, "a strong test passphrase").unwrap()[..],
            &key
        );
        assert!(unwrap_bytes("different-id", &wrapped, "a strong test passphrase").is_err());
        assert!(unwrap_bytes("test-id", &wrapped, "wrong passphrase").is_err());
    }

    #[test]
    fn wrapped_key_rejects_tampering() {
        let wrapped = wrap_bytes("test-id", &[7u8; KEY_LEN], "a strong test passphrase").unwrap();
        let mut tampered = wrapped;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(unwrap_bytes("test-id", &tampered, "a strong test passphrase").is_err());
    }
}

#[cfg(all(test, unix))]
mod revocation_marker_tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn marker_state_distinguishes_missing_regular_and_dangling_symlink() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();

        let directory = std::env::temp_dir().join(format!(
            "qs-revocation-marker-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create isolated test directory");

        let marker = directory.join("test-key.revoked");

        assert!(
            !revocation_marker_state(&marker).expect("inspect missing marker"),
            "a definitely missing marker means not revoked"
        );

        fs::write(&marker, b"revoked_at=1\n").expect("create marker");
        assert!(
            revocation_marker_state(&marker).expect("inspect regular marker"),
            "a regular marker means revoked"
        );

        fs::remove_file(&marker).expect("remove regular marker");
        symlink(directory.join("missing-target"), &marker).expect("create dangling symlink");

        assert!(
            revocation_marker_state(&marker).is_err(),
            "a dangling symlink must fail closed, not mean active"
        );

        fs::remove_dir_all(&directory).expect("clean test directory");
    }

    #[test]
    fn private_key_read_rejects_symlink_even_when_target_is_regular() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "qs-key-read-symlink-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create isolated test directory");

        let target = directory.join("real.key");
        fs::write(&target, [7u8; KEY_LEN]).expect("write key fixture");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .expect("restrict key fixture");
        assert_eq!(
            read_file(&target, KEY_LEN as u64, true)
                .expect("regular private key must be readable")
                .len(),
            KEY_LEN
        );

        let link = directory.join("link.key");
        symlink(&target, &link).expect("create symlink to regular key");
        assert!(
            read_file(&link, KEY_LEN as u64, true).is_err(),
            "a symlink must never be followed for private-key reads"
        );

        fs::remove_dir_all(&directory).expect("clean test directory");
    }
}
