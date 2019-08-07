use failure::Error;

use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::x509::extension;
use openssl::x509::{X509Builder, X509Extension, X509Ref, X509};

use crate::cert_params::CertParams;

pub fn create_cert<EXT>(params: &CertParams, ext: EXT) -> Result<X509, Error>
where
    EXT: Fn(&X509Builder) -> Result<Vec<X509Extension>, Error>,
{
    let mut builder = X509Builder::new()?;

    builder.set_version(2)?;

    let serial = params.serial();
    builder.set_serial_number(&serial)?;

    builder.set_not_before(&params.valid_from())?;
    builder.set_not_after(&params.valid_to())?;

    let subject = params.subject();
    builder.set_subject_name(&subject.name)?;
    builder.set_pubkey(&subject.pkey)?;

    let issuer = params.issuer();
    builder.set_issuer_name(&issuer.name)?;

    let mut extensions = ext(&builder)?;
    for extension in extensions.drain(..) {
        builder.append_extension(extension)?;
    }

    builder.sign(&issuer.pkey, MessageDigest::sha256())?;

    Ok(builder.build())
}

pub fn create_root_ca(params: &CertParams) -> Result<X509, Error> {
    let cert = create_cert(params, |builder| {
        let ctx = builder.x509v3_context(None, None);
        let sub_key_id = extension::SubjectKeyIdentifier::new().build(&ctx)?;
        Ok(vec![sub_key_id])
    })?; // Create a temp cert so we can use it later to generate auth_key_id

    create_cert(params, |builder| {
        let ctx = builder.x509v3_context(Some(&cert), None);
        let sub_key_id = extension::SubjectKeyIdentifier::new().build(&ctx)?;
        let auth_key_id = extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&ctx)?;
        let bc = extension::BasicConstraints::new().critical().ca().build()?;
        let key_usage = extension::KeyUsage::new()
            .digital_signature()
            .key_cert_sign()
            .crl_sign()
            .build()?;
        Ok(vec![sub_key_id, auth_key_id, bc, key_usage])
    })
}

pub fn create_intermediate_ca(params: &CertParams, root_ca_cert: &X509Ref) -> Result<X509, Error> {
    create_cert(params, |builder| {
        let ctx = builder.x509v3_context(Some(root_ca_cert), None);
        let sub_key_id = extension::SubjectKeyIdentifier::new().build(&ctx)?;
        let auth_key_id = extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(true)
            .build(&ctx)?;
        let bc = extension::BasicConstraints::new()
            //.critical()
            .ca()
            //.pathlen(0)
            .build()?;
        let key_usage = extension::KeyUsage::new()
            .digital_signature()
            .key_cert_sign()
            .crl_sign()
            .build()?;
        Ok(vec![sub_key_id, auth_key_id, bc, key_usage])
    })
}

pub fn create_server_cert(params: &CertParams, intermediate_cert: &X509Ref) -> Result<X509, Error> {
    create_cert(params, |builder| {
        let ctx = builder.x509v3_context(Some(intermediate_cert), None);

        let sub_key_id = extension::SubjectKeyIdentifier::new().build(&ctx)?;

        let auth_key_id = extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(true)
            .build(&ctx)?;

        let bc = extension::BasicConstraints::new().build()?;

        let key_usage = extension::KeyUsage::new()
            // .critical()
            .digital_signature()
            .non_repudiation()
            .key_encipherment()
            .build()?;

        let extended_key_usage = extension::ExtendedKeyUsage::new().server_auth().build()?;

        let netscape_cert_type =
            X509Extension::new_nid(None, None, Nid::NETSCAPE_CERT_TYPE, "SSL Server")?;

        let netscape_comment = X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_COMMENT,
            "Simple CA Generated Server Certificate",
        )?;

        let mut v3_extensions = vec![
            sub_key_id,
            auth_key_id,
            bc,
            netscape_cert_type,
            netscape_comment,
            key_usage,
            extended_key_usage,
        ];

        if params.sub_alt_names.len() > 0 {
            let mut sub_alt_name = extension::SubjectAlternativeName::new();
            params.sub_alt_names.iter().for_each(|name| {
                sub_alt_name.dns(name);
            });
            v3_extensions.push(sub_alt_name.build(&ctx)?);
        }

        Ok(v3_extensions)
    })
}

#[cfg(test)]
mod tests {

    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use std::fs::File;
    use std::io::Write;

    use super::*;
    use crate::CertParams;
    use crate::Name;
    use openssl::x509::X509;

    macro_rules! write_file_unwrapped {
        ($content:expr, $dest:expr) => {{
            let mut file = File::create($dest).unwrap();
            file.write_all($content).unwrap();
        }};
    }

    #[test]
    fn test_create_cert_authorities() {
        let name = Name {
            country: "AU".to_string(),
            province: "TAS".to_string(),
            locality: "Hobart".to_string(),
            org: "".to_string(),
            org_unit: "".to_string(),
            common_name: "ROOT CA".to_string(),
        };

        let root_rsa = Rsa::generate(4096).unwrap();
        let root_key = PKey::from_rsa(root_rsa).unwrap();
        let root_name = name.to_x509_name().unwrap();
        let ca_params = CertParams::root_ca_params(&root_name, &root_key, 7200).unwrap();
        let root_ca: X509 = create_root_ca(&ca_params).unwrap();

        write_file_unwrapped!(
            &root_key.private_key_to_pem_pkcs8().unwrap(),
            "target/ca.key.pem"
        );
        write_file_unwrapped!(&root_ca.to_pem().unwrap(), "target/ca.cert.pem");

        let intermediate_rsa = Rsa::generate(4096).unwrap();
        let intermediate_key = PKey::from_rsa(intermediate_rsa).unwrap();
        let intermediate_name = name.copy("Intermediate CA").to_x509_name().unwrap();
        let intermediate_params = CertParams::intermediate_ca_params(
            &intermediate_name,
            &intermediate_key,
            &root_name,
            &root_key,
            2500,
        )
        .unwrap();
        let intermediate_ca = create_intermediate_ca(&intermediate_params, &root_ca).unwrap();

        write_file_unwrapped!(
            &intermediate_key.private_key_to_pem_pkcs8().unwrap(),
            "target/intermediate.key.pem"
        );
        write_file_unwrapped!(
            &intermediate_ca.to_pem().unwrap(),
            "target/intermediate.cert.pem"
        );

        let server_rsa = Rsa::generate(2048).unwrap();
        let server_key = PKey::from_rsa(server_rsa).unwrap();
        let server_name = name.copy("*.example.com").to_x509_name().unwrap();
        let server_params = CertParams::server_cert_params(
            &server_name,
            &server_key,
            &intermediate_name,
            &intermediate_key,
            // &root_name,
            // &root_key,
            370,
            &vec!["*.another.com"],
        )
        .unwrap();
        let server_cert = create_server_cert(&server_params, &intermediate_ca).unwrap();
        // let server_cert = create_server_cert(&server_params, &root_ca).unwrap();

        write_file_unwrapped!(
            &server_key.private_key_to_pem_pkcs8().unwrap(),
            "target/server.key.pem"
        );
        write_file_unwrapped!(&server_cert.to_pem().unwrap(), "target/server.cert.pem");
    }

}
