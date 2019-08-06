extern crate clap;
extern crate simple_ca;

use clap::{App, Arg, SubCommand};
use simple_ca::{generate_server_cert, load_ca, Name};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let matches = App::new("Simple CA")
        .version(VERSION)
        .about("Create certificates for dev environment easiliy.")
        .subcommand(
            SubCommand::with_name("ca")
                .about("Regenerate CA certificates")
                .arg(Arg::with_name("v").short("v").help("Sets verbose mode")),
        )
        .subcommand(
            SubCommand::with_name("server")
                .about("Create server certificate")
                .arg(
                    Arg::with_name("COMMON_NAME")
                        .help("Common name field of the certificate")
                        .required(true),
                )
                .arg(
                    Arg::with_name("subjectAltName")
                        .help("DNS entry in the SubjectAltName extension of the certificate")
                        .required(true)
                        .multiple(true)
                        .takes_value(true),
                )
                .args_from_usage(
                    "--country=[NAME] 'Country field of the certificate'
          --state=[NAME] 'State or province field of the certificate'
          --locality=[NAME] 'Locality field of the certificate'
          --org=[NAME] 'Orgnaization field of the certificate'
          --org-unit=[NAME] 'Organization unit field of the certificate'
          ",
                )
                .arg(Arg::with_name("v").short("v").help("Sets verbose put mode")),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("ca") {
        let verbose = matches.is_present("v");
        load_ca(true, verbose).unwrap();
    }

    if let Some(matches) = matches.subcommand_matches("server") {
        let verbose = matches.is_present("v");
        let sans = matches
            .values_of("subjectAltName")
            .map(|values| values.collect::<Vec<&str>>())
            .unwrap_or_else(|| Vec::with_capacity(0));

        if let Some(common_name) = matches.value_of("COMMON_NAME") {
            let name = Name {
                country: matches.value_of("country").unwrap_or("").to_string(),
                province: matches.value_of("state").unwrap_or("").to_string(),
                locality: matches.value_of("locality").unwrap_or("").to_string(),
                org: matches.value_of("org").unwrap_or("").to_string(),
                org_unit: matches.value_of("org-unit").unwrap_or("").to_string(),
                common_name: common_name.to_string(),
            };
            generate_server_cert(&name, &sans, verbose).unwrap();
        }
    }
}
