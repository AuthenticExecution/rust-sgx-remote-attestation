#[derive(Debug)]
pub enum EnclaveRaError {
    Crypto(sgx_crypto::error::CryptoError),
    IntegrityError,
    ReportDataLongerThan64Bytes,
    BincodeError(std::boxed::Box<bincode::ErrorKind>),
    LocalAttestation(LocalAttestationError),
    EnclaveNotTrusted,
    PseNotTrusted,
    IoError(std::io::Error),
    TargetinfoError
}

impl std::error::Error for EnclaveRaError {}

impl std::fmt::Display for EnclaveRaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
        -> Result<(), std::fmt::Error> {
            write!(f, "{:?}", self)
        }
}

impl std::convert::From<sgx_crypto::error::CryptoError> for EnclaveRaError {
    fn from(e: sgx_crypto::error::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl std::convert::From<std::boxed::Box<bincode::ErrorKind>> for EnclaveRaError {
    fn from(e: std::boxed::Box<bincode::ErrorKind>) -> Self {
        Self::BincodeError(e)
    }
}

impl std::convert::From<std::io::Error> for EnclaveRaError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

#[derive(Debug)]
pub enum LocalAttestationError {
    Crypto(sgx_crypto::error::CryptoError),
    IncorrectReportLength,
    IntegrityError,
}

impl std::convert::From<sgx_crypto::error::CryptoError> for LocalAttestationError {
    fn from(e: sgx_crypto::error::CryptoError) -> Self {
        Self::Crypto(e)
    }
}
