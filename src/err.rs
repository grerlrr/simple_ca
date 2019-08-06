#[derive(Debug, Fail)]
pub enum SimpleCAError {
    #[fail(display = "{}", msg)]
    GenericError { msg: &'static str },
}
