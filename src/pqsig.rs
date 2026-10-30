use anyhow::{bail, Context, Result};
use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa65, Signature, SignatureEncoding, Signer,
    SigningKey, Verifier, VerifyingKey,
};
use slh_dsa::{
    params::SLH_DSA_SHAKE_128F,
    safe_api::{SlhDsaKeyPair, SlhDsaSignature},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_INPUT: u64 = 64 * 1024 * 1024;
const MAX_KEY_OR_SIGNATURE: u64 = 2 * 1024 * 1024;
const DOMAIN: &[u8] = b"Quantum Shield PQ file signature v1\0";

#[derive(Clone, Copy)]
enum Algorithm {
    MlDsa65,
    SlhDsaShake128f,
}

impl Algorithm {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "ml-dsa-65" => Ok(Self::MlDsa65),
            "slh-dsa-shake-128f" => Ok(Self::SlhDsaShake128f),
            _ => bail!(
                "unsupported signature algorithm '{value}'; choose ml-dsa-65 or slh-dsa-shake-128f"
            ),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml-dsa-65",
            Self::SlhDsaShake128f => "slh-dsa-shake-128f",
        }
    }
}

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

fn store_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    let dir = PathBuf::from(home).join(".local/state/quantum-shield/signing-keys");
    fs::create_dir_all(&dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(&dir)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            bail!("signing-key directory must be a real directory");
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

fn paths(id: &str, alg: Algorithm) -> Result<(PathBuf, PathBuf)> {
    validate_id(id)?;
    let dir = store_dir()?;
    let prefix = format!("{id}.{}", alg.name());
    Ok((
        dir.join(format!("{prefix}.sk")),
        dir.join(format!("{prefix}.pk")),
    ))
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("could not create {}; refusing to overwrite", path.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error).with_context(|| format!("could not write {}", path.display()));
    }
    Ok(())
}

fn read_limited(path: &Path, limit: u64, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!(
                "private key {} is accessible to group/others; restrict it to mode 600",
                path.display()
            );
        }
    }
    if meta.len() > limit {
        bail!("{} exceeds the configured size limit", path.display());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("{} grew beyond the configured size limit", path.display());
    }
    Ok(bytes)
}

fn message_to_sign(alg: Algorithm, input: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + alg.name().len() + 1 + input.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(alg.name().as_bytes());
    message.push(0);
    message.extend_from_slice(input);
    message
}

pub(crate) fn generate_keypair(algorithm: &str, id: &str) -> Result<(PathBuf, PathBuf)> {
    let alg = Algorithm::parse(algorithm)?;
    let (private_path, public_path) = paths(id, alg)?;
    if private_path.exists() || public_path.exists() {
        bail!("key ID already exists for this algorithm; refusing to overwrite keys");
    }

    let (private, public) = match alg {
        Algorithm::MlDsa65 => {
            let sk = SigningKey::<MlDsa65>::generate();
            let secret = sk.to_bytes();
            let public = sk.verifying_key().encode();
            (secret.as_slice().to_vec(), public.as_slice().to_vec())
        }
        Algorithm::SlhDsaShake128f => {
            let pair = SlhDsaKeyPair::generate(SLH_DSA_SHAKE_128F)
                .map_err(|e| anyhow::anyhow!("SLH-DSA key generation failed: {e:?}"))?;
            (pair.secret_key().to_vec(), pair.public_key().to_vec())
        }
    };

    let private = Zeroizing::new(private);
    write_private_new(&private_path, &private)?;
    if let Err(error) = write_private_new(&public_path, &public) {
        let _ = fs::remove_file(&private_path);
        return Err(error);
    }
    Ok((private_path, public_path))
}

pub(crate) fn sign_file(
    algorithm: &str,
    id: &str,
    input: &Path,
    signature_path: &Path,
) -> Result<()> {
    let alg = Algorithm::parse(algorithm)?;
    let (private_path, public_path) = paths(id, alg)?;
    let secret = read_limited(&private_path, MAX_KEY_OR_SIGNATURE, true)?;
    let _public = read_limited(&public_path, MAX_KEY_OR_SIGNATURE, true)?;
    let input = read_limited(input, MAX_INPUT, false)?;
    let message = message_to_sign(alg, &input);

    let signature: Vec<u8> = match alg {
        Algorithm::MlDsa65 => {
            let sk = SigningKey::<MlDsa65>::new_from_slice(&secret)
                .map_err(|e| anyhow::anyhow!("invalid ML-DSA private key: {e}"))?;
            sk.sign(&message).to_bytes().as_slice().to_vec()
        }
        Algorithm::SlhDsaShake128f => {
            let pair = SlhDsaKeyPair::from_bytes(SLH_DSA_SHAKE_128F, &_public, &secret)
                .map_err(|e| anyhow::anyhow!("invalid SLH-DSA keypair: {e:?}"))?;
            pair.sign(&message)
                .map_err(|e| anyhow::anyhow!("SLH-DSA signing failed: {e:?}"))?
                .to_bytes()
                .to_vec()
        }
    };

    write_private_new(signature_path, &signature)?;
    Ok(())
}

pub(crate) fn verify_file(
    algorithm: &str,
    public_key_path: &Path,
    input_path: &Path,
    signature_path: &Path,
) -> Result<()> {
    let alg = Algorithm::parse(algorithm)?;
    let public = read_limited(public_key_path, MAX_KEY_OR_SIGNATURE, false)?;
    let input = read_limited(input_path, MAX_INPUT, false)?;
    let signature = read_limited(signature_path, MAX_KEY_OR_SIGNATURE, false)?;
    let message = message_to_sign(alg, &input);

    let valid = match alg {
        Algorithm::MlDsa65 => {
            let vk = VerifyingKey::<MlDsa65>::new_from_slice(&public)
                .map_err(|e| anyhow::anyhow!("invalid ML-DSA public key: {e}"))?;
            let sig = Signature::<MlDsa65>::try_from(signature.as_slice())
                .map_err(|_| anyhow::anyhow!("invalid ML-DSA signature encoding"))?;
            vk.verify(&message, &sig).is_ok()
        }
        Algorithm::SlhDsaShake128f => {
            SlhDsaSignature::verify(&signature, &public, &message, SLH_DSA_SHAKE_128F)
        }
    };

    if !valid {
        bail!("signature verification FAILED: input, signature, key, or algorithm did not match");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_65_signature_verifies_and_detects_modified_message() {
        let sk = SigningKey::<MlDsa65>::generate();
        let vk = sk.verifying_key();
        let message = message_to_sign(Algorithm::MlDsa65, b"Quantum Shield test");
        let signature = sk.sign(&message);
        assert!(vk.verify(&message, &signature).is_ok());

        let tampered = message_to_sign(Algorithm::MlDsa65, b"tampered input");
        assert!(vk.verify(&tampered, &signature).is_err());
    }

    #[test]
    fn slh_dsa_signature_verifies_and_detects_modified_message() {
        let pair = SlhDsaKeyPair::generate(SLH_DSA_SHAKE_128F).unwrap();
        let message = message_to_sign(Algorithm::SlhDsaShake128f, b"Quantum Shield test");
        let signature = pair.sign(&message).unwrap();
        assert!(SlhDsaSignature::verify(
            signature.to_bytes(),
            pair.public_key(),
            &message,
            SLH_DSA_SHAKE_128F
        ));

        let tampered = message_to_sign(Algorithm::SlhDsaShake128f, b"tampered input");
        assert!(!SlhDsaSignature::verify(
            signature.to_bytes(),
            pair.public_key(),
            &tampered,
            SLH_DSA_SHAKE_128F
        ));
    }
}
