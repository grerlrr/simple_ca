use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509Name;
use std::time::{SystemTime, UNIX_EPOCH};

fn create_serial_number() -> BigNum {
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let time = since_epoch.as_secs() * 1_000_000_000 as u64 + since_epoch.subsec_nanos() as u64;
    let time = format!("{}", time);
    BigNum::from_dec_str(&time).unwrap()
}

pub struct Entity<'a> {
    pub name: &'a X509Name,
    pub pkey: &'a PKey<Private>,
}

pub struct CertParams<'a> {
    subject: Entity<'a>,
    issuer: Option<Entity<'a>>,
    pub valid: u32,
    serial: BigNum,
    pub sub_alt_names: Vec<String>,
}

impl<'a> CertParams<'a> {
    pub fn valid_from(&self) -> Asn1Time {
        Asn1Time::days_from_now(0).unwrap()
    }

    pub fn valid_to(&self) -> Asn1Time {
        Asn1Time::days_from_now(self.valid).unwrap()
    }

    pub fn subject(&self) -> &Entity {
        &self.subject
    }

    pub fn issuer(&self) -> &Entity {
        self.issuer.as_ref().unwrap_or(self.subject())
    }

    pub fn serial(&self) -> Asn1Integer {
        self.serial.to_asn1_integer().unwrap()
    }

    pub fn root_ca_params(
        name: &'a X509Name,
        pkey: &'a PKey<Private>,
        valid: u32,
    ) -> Result<CertParams<'a>, ErrorStack> {
        let subject = Entity { name, pkey };
        Ok(CertParams {
            subject,
            issuer: None,
            valid,
            serial: BigNum::from_u32(1000)?,
            sub_alt_names: Vec::with_capacity(0),
        })
    }

    pub fn intermediate_ca_params(
        name: &'a X509Name,
        pkey: &'a PKey<Private>,
        root_name: &'a X509Name,
        root_pkey: &'a PKey<Private>,
        valid: u32,
    ) -> Result<CertParams<'a>, ErrorStack> {
        let subject = Entity { name, pkey };
        let issuer = Entity {
            name: root_name,
            pkey: root_pkey,
        };
        Ok(CertParams {
            subject,
            issuer: Some(issuer),
            valid,
            serial: BigNum::from_u32(10000)?,
            sub_alt_names: Vec::with_capacity(0),
        })
    }

    pub fn server_cert_params(
        name: &'a X509Name,
        pkey: &'a PKey<Private>,
        issuer_name: &'a X509Name,
        issuer_pkey: &'a PKey<Private>,
        valid: u32,
        sub_alt_names: &Vec<&'a str>,
    ) -> Result<CertParams<'a>, ErrorStack> {
        let common_name = format!(
            "{}",
            name.entries_by_nid(Nid::COMMONNAME)
                .next()
                .unwrap()
                .data()
                .as_utf8()?
        );
        let subject = Entity { name, pkey };
        let issuer = Entity {
            name: issuer_name,
            pkey: issuer_pkey,
        };
        let mut sub_alt_names: Vec<String> = sub_alt_names.iter().map(|x| x.to_string()).collect();
        sub_alt_names.insert(0, common_name);
        Ok(CertParams {
            subject,
            issuer: Some(issuer),
            valid,
            serial: create_serial_number(),
            sub_alt_names,
        })
    }
}
