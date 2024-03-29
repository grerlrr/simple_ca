use std::fs::{self, File};
use std::io::{Error as IOError, ErrorKind as IOErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::err::SimpleCAError;
use crate::Name;

const CONFIG_DIR: &'static str = ".simple_ca";
const CONFIG_FILE: &'static str = "config";

fn ensure_dir(dir: &PathBuf) -> Result<(), IOError> {
    if dir.exists() {
        if dir.is_file() {
            return Err(IOError::new(
                IOErrorKind::AlreadyExists,
                format!("Can create dir {}", dir.to_string_lossy()),
            ));
        }
    } else {
        fs::create_dir(&dir)?;
    }
    Ok(())
}

pub fn home_dir() -> Result<PathBuf, SimpleCAError> {
    match dirs::home_dir() {
        Some(dir) => Ok(dir),
        None => Err(SimpleCAError::GenericError {
            msg: "Unable to locate home directory.",
        })?,
    }
}

fn file_in_conf(name: &str) -> Result<PathBuf> {
    let mut path = home_dir()?;
    path.push(CONFIG_DIR);
    path.push(name);
    Ok(path)
}

pub fn with_config_dir<T, RT>(process: T) -> Result<RT>
where
    T: Fn(PathBuf) -> Result<RT>,
{
    let mut home_path = home_dir()?;
    home_path.push(CONFIG_DIR);
    let config_dir_path = home_path;
    ensure_dir(&config_dir_path)?;
    process(config_dir_path)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CertAuthConf {
    country: Option<String>,
    state_or_province: Option<String>,
    locality: Option<String>,
    organization: Option<String>,
    organization_unit: Option<String>,
}

macro_rules! file_name_getter {
    ($fn_name:ident, $f_name:expr) => {
        pub fn $fn_name() -> Result<PathBuf> {
            file_in_conf($f_name)
        }
    };
}

fn reversed_domain(domain: &str) -> String {
    if domain.parse::<std::net::SocketAddr>().is_ok() {
        domain.to_owned()
    } else {
        let port_pos = domain.find(':');
        let port = port_pos.map(|i| (&domain[i..])).unwrap_or("");
        let domain = port_pos.map(|i| &domain[..i]).unwrap_or(domain);

        let mut result = domain
            .split(".")
            .collect::<Vec<&str>>()
            .into_iter()
            .rev()
            .collect::<Vec<&str>>()
            .join(".");

        result.push_str(port);
        result
    }
}

fn opt_value(opt: &Option<String>, default: &str) -> String {
    opt.as_ref()
        .map(|x| x.to_string())
        .unwrap_or_else(|| default.to_string())
}

impl CertAuthConf {
    pub fn default() -> CertAuthConf {
        CertAuthConf {
            country: None,
            state_or_province: None,
            locality: None,
            organization: Some("Simple CA".to_string()),
            organization_unit: None,
        }
    }

    file_name_getter!(ca_key, "ca.key.pem");
    file_name_getter!(ca_cert, "ca.cert.pem");
    file_name_getter!(intermediate_key, "intermediate.key.pem");
    file_name_getter!(intermediate_cert, "intermediate.cert.pem");

    pub fn server_key(domain: &str) -> Result<PathBuf> {
        file_in_conf(&format!("{}.key.pem", reversed_domain(domain)))
    }

    pub fn server_cert(domain: &str) -> Result<PathBuf> {
        file_in_conf(&format!("{}.cert.pem", reversed_domain(domain)))
    }

    pub fn ca_name(&self) -> Name {
        let org = opt_value(&self.organization, "Simple CA");
        Name {
            country: opt_value(&self.country, ""),
            province: opt_value(&self.state_or_province, ""),
            locality: opt_value(&self.locality, ""),
            org: opt_value(&self.organization, ""),
            org_unit: opt_value(&self.organization_unit, ""),
            common_name: format!("{} Root CA", org),
        }
    }

    pub fn intermediate_name(&self) -> Name {
        let ca_name = self.ca_name();
        ca_name.copy(&format!("{} Intermediate CA", ca_name.org))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Conf {
    ca: Option<CertAuthConf>,
}

impl Conf {
    pub fn default() -> Conf {
        Conf {
            ca: Some(CertAuthConf::default()),
        }
    }

    pub fn load() -> Result<Conf> {
        with_config_dir(|mut dir| {
            dir.push(CONFIG_FILE);
            let config_path = dir;
            Conf::load_config(&config_path)
        })
    }

    pub fn ca(&self) -> &CertAuthConf {
        self.ca.as_ref().unwrap()
    }

    pub fn load_config(path: &Path) -> Result<Conf> {
        if path.exists() {
            let mut config_str = String::new();
            let mut f = File::open(path)?;
            f.read_to_string(&mut config_str)?;

            let conf: Conf = toml::from_str(&config_str)?;
            Ok(conf)
        } else {
            let conf = Conf::default();
            conf.save(path)?;
            Ok(conf)
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        let mut f = File::create(path)?;
        f.write_all(content.as_bytes())?;
        Ok(())
    }
}
