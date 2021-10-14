use super::digest::{sha256, SHA256_TYPE};
use super::Rng;
use mbedtls::pk::Pk;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use anyhow::Result;
use crate::error::CryptoError;

pub type Signature = Vec<u8>;

pub struct VerificationKey {
    inner: Pk,
}

impl VerificationKey {
    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    /// When calling on PEM-encoded data, key must be NULL-terminated
    pub fn new(public_key: &[u8]) -> Result<Self> {
        let inner = Pk::from_public_key(public_key)?;
        Ok(Self { inner })
    }

    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    pub fn new_from_file(public_key_path: &Path) -> Result<Self> {
        let mut file = File::open(public_key_path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let ext = match public_key_path.extension() {
            Some(e)     => e,
            None        => return Err(
                CryptoError::GenericError(String::from("key file does not have extension")).into())
        };

        if ext == "pem" {
            buf.push(0);
        }
        Self::new(&buf[..])
    }

    pub fn verify(&mut self, message: &[u8], signature: &[u8]) -> Result<()> {
        let hash = sha256(message)?;
        self.inner.verify(SHA256_TYPE, &hash[..], signature)?;
        Ok(())
    }
}

pub struct SigningKey {
    inner: Pk,
}
impl SigningKey {
    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    /// When calling on PEM-encoded data, key must be NULL-terminated
    pub fn new(private_key: &[u8], password: Option<&[u8]>) -> super::Result<Self> {
        let inner = Pk::from_private_key(private_key, password)?;
        Ok(Self { inner })
    }

    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    pub fn new_from_file(private_key_path: &Path, password: Option<&[u8]>) -> super::Result<Self> {
        let mut file = File::open(private_key_path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let ext = match private_key_path.extension() {
            Some(e)     => e,
            None        => return Err(
                CryptoError::GenericError(String::from("key file does not have extension")).into())
        };

        if ext == "pem" {
            buf.push(0);
        }
        Self::new(&buf[..], password)
    }

    pub fn sign(&mut self, message: &[u8], rng: &mut Rng) -> super::Result<Signature> {
        let hash = sha256(message)?;
        let sig_len = self.inner.rsa_public_modulus()?.byte_length()?;
        let mut signature = vec![0u8; sig_len];
        self.inner
            .sign(SHA256_TYPE, &hash[..], &mut signature[..], rng)?;
        Ok(signature)
    }
}
