#[derive(Debug)]
pub enum ClientRaError {
    IO(IOError),
    Aesm(aesm_client::Error),
    EnclaveNotTrusted,
    PseNotTrusted,
    GenericError(String)
}

#[derive(Debug)]
pub enum IOError {
    Bincode(std::boxed::Box<bincode::ErrorKind>),
    StdIo(std::io::Error),
}

impl std::convert::From<aesm_client::Error> for ClientRaError {
    fn from(e: aesm_client::Error) -> Self {
        Self::Aesm(e)
    }
}

impl std::convert::From<std::boxed::Box<bincode::ErrorKind>> for ClientRaError {
    fn from(e: std::boxed::Box<bincode::ErrorKind>) -> Self {
        Self::IO(IOError::Bincode(e))
    }
}

impl std::convert::From<std::io::Error> for ClientRaError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(IOError::StdIo(e))
    }
}

impl std::fmt::Display for ClientRaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
        -> Result<(), std::fmt::Error> {
            write!(f, "{:?}", self)
        }
}

impl std::error::Error for ClientRaError {}
