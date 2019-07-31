#[macro_use]
extern crate failure;

#[macro_use]
extern crate serde_derive;

mod cert_params;
mod certs;
mod conf;
mod err;
mod name;

pub use conf::{CertAuthConf, Conf};
pub use name::Name;
pub use cert_params::CertParams;

macro_rules! write_file {
  ($content:expr, $dest:expr, $verbose:expr, $msg_fmt:expr) => ({
    let mut file = File::create($dest).unwrap();
    let _ = file.write_all($content)?;
    if $verbose {
      println!($msg_fmt, $dest);
    }
  });
}

pub fn save_file(content: &Vec<u8>, dest: &std::path::Path) -> Result<(), std::io::Error> {
  use std::io::Write;
  let mut file = std::fs::File::create(dest).unwrap();
  file.write_all(content)?;
  Ok(())
}

mod commands;
pub use commands::{generate_server_cert, load_ca};
