//! Experimental HQC-256 KEM envelope for file encryption.
//! Not independently audited; do not treat as production cryptography.

use anyhow::{bail, Context, Result};
use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    hkdf,
    rand::{SecureRandom, SystemRandom},
};
use hqc_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, Hqc256, Hqc256Params};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"QSHQC001";
const HQC_CT_LEN: usize = 14_421;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = MAGIC.len() + HQC_CT_LEN + SALT_LEN + NONCE_LEN;
const MAX_PLAINTEXT: u64 = 64 * 1024 * 1024;
const KDF_INFO: &[u8] =
    b"Quantum Shield experimental HQC-256 + HKDF-SHA-256 + AES-256-GCM file profile v1";

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

fn key_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    let dir = PathBuf::from(home).join(".local/state/quantum-shield/hqc-keys");
    fs::create_dir_all(&dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(&dir)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            bail!("HQC key directory must be a real directory, not a symlink");
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

fn key_paths(id: &str) -> Result<(PathBuf, PathBuf)> {
    validate_id(id)?;
    let dir = key_dir()?;
    Ok((
        dir.join(format!("{id}.hqc256.sk")),
        dir.join(format!("{id}.hqc256.pk")),
    ))
}

fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("could not create {}; refusing to overwrite", path.display()))?;
    if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e).with_context(|| format!("could not write {}", path.display()));
    }
    Ok(())
}

fn read_limited(path: &Path, limit: u64, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("{} must be a regular, non-symlink file", path.display());
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!(
                "private key {} is accessible to group/others; use mode 600",
                path.display()
            );
        }
    }
    if meta.len() > limit {
        bail!("{} exceeds the configured size limit", path.display());
    }
    let mut data = Zeroizing::new(Vec::new());
    File::open(path)?.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        bail!("{} grew beyond the configured size limit", path.display());
    }
    Ok(data)
}

pub(crate) fn generate_keypair(id: &str) -> Result<(PathBuf, PathBuf)> {
    let (sk_path, pk_path) = key_paths(id)?;
    if sk_path.exists() || pk_path.exists() {
        bail!("HQC key ID already exists; refusing to overwrite a key");
    }
    let mut rng = rand::rng();
    let (ek, dk) = Hqc256::generate_key(&mut rng);
    let public = ek.as_ref().to_vec();
    let private = Zeroizing::new(dk.as_ref().to_vec());

    write_new(&sk_path, &private, true)?;
    if let Err(e) = write_new(&pk_path, &public, false) {
        let _ = fs::remove_file(&sk_path);
        return Err(e);
    }
    Ok((sk_path, pk_path))
}

fn derive_key(shared_secret: &[u8], salt_bytes: &[u8]) -> Result<LessSafeKey> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_bytes);
    let prk = salt.extract(shared_secret);
    let okm = prk
        .expand(&[KDF_INFO], &aead::AES_256_GCM)
        .map_err(|_| anyhow::anyhow!("HKDF-SHA-256 derivation failed"))?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

fn encrypt_bytes(public_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() as u64 > MAX_PLAINTEXT {
        bail!("input exceeds the 64 MiB per-operation limit");
    }
    let ek: EncapsulationKey<Hqc256Params> = public_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid HQC-256 public key"))?;
    let mut rng = rand::rng();
    let (ct, shared_secret) = ek.encapsulate(&mut rng);

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| anyhow::anyhow!("secure random salt generation failed"))?;
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("secure random nonce generation failed"))?;

    let key = derive_key(shared_secret.as_ref(), &salt)?;
    let mut envelope = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(ct.as_ref());
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce_bytes);
    if envelope.len() != HEADER_LEN {
        bail!("unexpected HQC-256 ciphertext length");
    }

    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(envelope.as_slice()),
        &mut ciphertext,
    )
    .map_err(|_| anyhow::anyhow!("AES-256-GCM encryption failed"))?;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn decrypt_bytes(private_bytes: &[u8], envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < HEADER_LEN + TAG_LEN {
        bail!("HQC encrypted file is truncated");
    }
    if &envelope[..MAGIC.len()] != MAGIC {
        bail!("unsupported HQC encrypted-file format");
    }
    if envelope.len() as u64 > MAX_PLAINTEXT + (HEADER_LEN + TAG_LEN) as u64 {
        bail!("encrypted input exceeds the 64 MiB limit");
    }

    let dk: DecapsulationKey<Hqc256Params> = private_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid HQC-256 private key"))?;
    let ct: Ciphertext<Hqc256Params> = envelope[MAGIC.len()..MAGIC.len() + HQC_CT_LEN]
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid HQC ciphertext"))?;

    let salt_start = MAGIC.len() + HQC_CT_LEN;
    let nonce_start = salt_start + SALT_LEN;
    let nonce_end = nonce_start + NONCE_LEN;
    let salt = &envelope[salt_start..nonce_start];
    let nonce_bytes: [u8; NONCE_LEN] = envelope[nonce_start..nonce_end]
        .try_into()
        .context("invalid nonce")?;

    let shared_secret = dk.decapsulate(&ct);
    let key = derive_key(shared_secret.as_ref(), salt)?;
    let mut plaintext = envelope[HEADER_LEN..].to_vec();
    let length = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&envelope[..HEADER_LEN]),
            &mut plaintext,
        )
        .map_err(|_| anyhow::anyhow!("authentication failed: wrong key or modified file"))?
        .len();

    plaintext.truncate(length);
    Ok(plaintext)
}

pub(crate) fn encrypt_file(public_key: &Path, input: &Path, output: &Path) -> Result<()> {
    let pk = read_limited(public_key, 8_000, false)?;
    let plaintext = read_limited(input, MAX_PLAINTEXT, false)?;
    let envelope = encrypt_bytes(&pk, &plaintext)?;
    write_new(output, &envelope, true)
}

pub(crate) fn decrypt_file(id: &str, input: &Path, output: &Path) -> Result<()> {
    let (sk_path, _) = key_paths(id)?;
    let sk = read_limited(&sk_path, 8_000, true)?;
    let envelope = read_limited(input, MAX_PLAINTEXT + (HEADER_LEN + TAG_LEN) as u64, false)?;
    let plaintext = Zeroizing::new(decrypt_bytes(&sk, &envelope)?);
    write_new(output, &plaintext, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hqc256_envelope_round_trips_and_rejects_tampering() {
        let mut rng = rand::rng();
        let (ek, dk) = Hqc256::generate_key(&mut rng);
        let input = b"Quantum Shield HQC profile test\0binary payload";
        let envelope = encrypt_bytes(ek.as_ref(), input).unwrap();
        assert_eq!(decrypt_bytes(dk.as_ref(), &envelope).unwrap(), input);

        let mut modified = envelope;
        let last = modified.len() - 1;
        modified[last] ^= 1;
        assert!(decrypt_bytes(dk.as_ref(), &modified).is_err());
    }
}
