use std::io;

#[derive(Debug)]
pub enum CryptoError {
    MbedTls(mbedtls::Error),
    Io(io::Error),
    CmacVerificationError,
    GenericError(String)
}

impl std::convert::From<mbedtls::Error> for CryptoError {
    fn from(e: mbedtls::Error) -> Self {
        Self::MbedTls(e)
    }
}

impl std::convert::From<io::Error> for CryptoError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CryptoError {}
