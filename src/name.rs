extern crate openssl;

use openssl::nid::Nid;
use openssl::error::ErrorStack;
use openssl::x509::{X509Name, X509NameBuilder};

#[derive(Debug)]
pub struct Name {
  pub country: String,
  pub province: String,
  pub locality: String,
  pub org: String,
  pub org_unit: String,
  pub common_name: String,
}

macro_rules! append {
    ($b:expr, $n:expr, $v:expr) => ({
      if !$v.is_empty() {
        $b.append_entry_by_nid($n, $v)?;
      }
    })
}

impl Name {
  pub fn copy(&self, common_name: &str) -> Self {
    let mut new = self.clone();
    new.country = self.country.clone();
    new.province = self.province.clone();
    new.locality = self.locality.clone();
    new.org = self.org.clone();
    new.org_unit = self.org_unit.clone();
    new.common_name = common_name.to_string();
    new
  }

  pub fn to_x509_name(&self) -> Result<X509Name, ErrorStack> {
    let mut builder = X509NameBuilder::new()?;
    append!(builder, Nid::COUNTRYNAME, &self.country);
    append!(builder, Nid::STATEORPROVINCENAME, &self.country);
    append!(builder, Nid::LOCALITYNAME, &self.locality);
    append!(builder, Nid::ORGANIZATIONNAME, &self.org);
    append!(builder, Nid::ORGANIZATIONALUNITNAME, &self.org_unit);
    append!(builder, Nid::COMMONNAME, &self.common_name);
    Ok(builder.build())
  }
}

impl Clone for Name {
  fn clone(&self) -> Self {
    Name {
      common_name: self.common_name.clone(),
      country: self.common_name.clone(),
      province: self.common_name.clone(),
      locality: self.common_name.clone(),
      org: self.common_name.clone(),
      org_unit: self.common_name.clone(),
    }
  }
}
