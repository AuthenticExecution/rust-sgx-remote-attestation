#[derive(Debug)]
pub enum SpRaError {
    Crypto(sgx_crypto::error::CryptoError),
    IO(std::io::Error),
    IAS(IasError),
    Serialization(std::boxed::Box<bincode::ErrorKind>),
    IntegrityError,
    SigstructMismatched,
    EnclaveInDebugMode,
    EnclaveNotTrusted,
    InvalidSpConfig(String),
    GenericError(String)
}

impl std::convert::From<std::io::Error> for SpRaError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl std::convert::From<sgx_crypto::error::CryptoError> for SpRaError {
    fn from(e: sgx_crypto::error::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl std::convert::From<IasError> for SpRaError {
    fn from(e: IasError) -> Self {
        Self::IAS(e)
    }
}

impl std::convert::From<std::boxed::Box<bincode::ErrorKind>> for SpRaError {
    fn from(e: std::boxed::Box<bincode::ErrorKind>) -> Self {
        Self::Serialization(e)
    }
}

impl std::fmt::Display for SpRaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for SpRaError {}

#[derive(Debug)]
pub enum AttestationError {
    Connection(http_bytes::http::StatusCode),
    MismatchedIASRootCertificate,
    InvalidIASCertificate,
    BadSignature,
    BadHeader,
    CertListError,
}

impl std::error::Error for AttestationError {}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub enum IasError {
    IO(std::io::Error),
    Connection(sgx_crypto::mbedtls::Error),
    BufferTooSmall,
    HTTPError(http_bytes::Error),
    SigRLError(http_bytes::http::StatusCode),
    Attestation(AttestationError),
}

impl std::error::Error for IasError {}

impl std::fmt::Display for IasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

impl std::convert::From<std::io::Error> for IasError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl std::convert::From<sgx_crypto::mbedtls::Error> for IasError {
    fn from(e: sgx_crypto::mbedtls::Error) -> Self {
        Self::Connection(e)
    }
}

impl std::convert::From<http_bytes::Error> for IasError {
    fn from(e: http_bytes::Error) -> Self {
        Self::HTTPError(e)
    }
}
