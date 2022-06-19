use thiserror::Error;

#[derive(Debug, Error)]
pub enum SimpleCAError {
    #[error("{msg}")]
    GenericError { msg: &'static str },
}
