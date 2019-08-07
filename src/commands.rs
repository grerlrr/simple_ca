use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::Path;

use failure::Error;

use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Name, X509};

use crate::cert_params::CertParams;
use crate::certs::{create_intermediate_ca, create_root_ca, create_server_cert};
use crate::conf::{CertAuthConf, Conf};
use crate::name::Name;
use crate::save_file;

fn read_file(path: &Path) -> Result<Vec<u8>, io::Error> {
    let mut content = Vec::new();
    let mut f = File::open(path)?;

    f.read_to_end(&mut content)?;
    Ok(content)
}

fn get_pkey(generate: bool, path: &Path, bits: u32) -> Result<PKey<Private>, Error> {
    let pkey = if generate {
        let rsa = Rsa::generate(bits)?;
        PKey::from_rsa(rsa)?
    } else {
        let pem = read_file(path)?;
        PKey::private_key_from_pem(&pem)?
    };
    Ok(pkey)
}

fn get_x509<T>(generate: bool, path: &Path, create: T) -> Result<X509, Error>
where
    T: Fn() -> Result<X509, Error>,
{
    let x509 = if generate {
        let ca = create()?;
        save_file(&ca.to_pem()?, path)?;
        ca
    } else {
        let pem = read_file(path)?;
        X509::from_pem(&pem)?
    };
    Ok(x509)
}

pub fn load_ca(reset: bool, verbose: bool) -> Result<(X509, PKey<Private>, X509Name), Error> {
    let conf = Conf::load()?;

    let ca_key_path = CertAuthConf::ca_key()?;
    let ca_cert_path = CertAuthConf::ca_cert()?;

    let intermediate_key_path = CertAuthConf::intermediate_key()?;
    let intermediate_cert_path = CertAuthConf::intermediate_cert()?;

    let mut ca_create = false;
    let mut intermediate_create = false;

    if reset || !ca_key_path.exists() || !ca_cert_path.exists() {
        ca_create = true;
        intermediate_create = true;
    } else if !intermediate_key_path.exists() || !intermediate_cert_path.exists() {
        intermediate_create = true;
    }

    let ca_pkey = get_pkey(ca_create, &ca_key_path, 4096)?;
    if ca_create {
        write_file!(
            &ca_pkey.private_key_to_pem_pkcs8()?,
            &ca_key_path,
            verbose,
            "Saved CA private key at: {:?}"
        );
    }
    let ca_name = conf.ca().ca_name().to_x509_name()?;
    let ca_params = CertParams::root_ca_params(&ca_name, &ca_pkey, 7200)?;
    let ca = get_x509(ca_create, &ca_cert_path, || create_root_ca(&ca_params))?;
    if ca_create {
        write_file!(
            &ca.to_pem()?,
            &ca_cert_path,
            verbose,
            "Saved CA certificate at: {:?}"
        );
    }

    let intermediate_pkey = get_pkey(intermediate_create, &intermediate_key_path, 4096)?;
    let intermediate_name = conf.ca().intermediate_name().to_x509_name()?;
    let intermediate = {
        if intermediate_create {
            write_file!(
                &intermediate_pkey.private_key_to_pem_pkcs8()?,
                &intermediate_key_path,
                verbose,
                "Saved Intermediate private key at: {:?}"
            );
        }
        let intermediate_params = CertParams::intermediate_ca_params(
            &intermediate_name,
            &intermediate_pkey,
            &ca_name,
            &ca_pkey,
            3600,
        )?;
        let intermediate = get_x509(intermediate_create, &intermediate_cert_path, || {
            create_intermediate_ca(&intermediate_params, &ca)
        })?;
        if intermediate_create {
            write_file!(
                &intermediate.to_pem()?,
                &intermediate_cert_path,
                verbose,
                "Saved intermediate certicate at: {:?}"
            );
        }
        intermediate
    };

    Ok((intermediate, intermediate_pkey, intermediate_name))
}

pub fn generate_server_cert(
    name: &Name,
    alt_names: &Vec<&str>,
    verbose: bool,
) -> Result<(), Error> {
    let domain = &name.common_name;
    let name = name.to_x509_name()?;
    let server_key_path = CertAuthConf::server_key(domain)?;
    let pkey = get_pkey(true, &server_key_path, 2048)?;
    write_file!(
        &pkey.private_key_to_pem_pkcs8()?,
        &server_key_path,
        verbose,
        "Saved server key at: {:?}"
    );
    let (ca, ca_pkey, ca_name) = load_ca(false, verbose)?;

    let params = CertParams::server_cert_params(&name, &pkey, &ca_name, &ca_pkey, 370, alt_names)?;
    let cert = create_server_cert(&params, &ca)?;
    let cert_path = CertAuthConf::server_cert(domain)?;
    write_file!(
        &cert.to_pem()?,
        &cert_path,
        verbose,
        "Saved server certificate at: {:?}"
    );

    Ok(())
}
