//! Utility for exercising Pkcs12Builder structure

#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use log::{error, LevelFilter};
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
    Config,
};
use rand_core::OsRng;

use der::{asn1::SetOfVec, Decode};
use pkcs12::pfx::Pfx;

use crate::{
    args::Pkcs12UtilArgs,
    asn1_utils::*,
    file_utils::*,
    pkcs12_builder::{add_key_id_attr, MacDataBuilder, Pkcs12Builder},
};

mod args;
mod asn1_utils;
mod file_utils;
pub mod pkcs12_builder;

/// Error type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),
    /// PKCS5-related errors
    Pkcs5(pkcs5::Error),
    /// General errors
    Pkcs12Util(String),
}
impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}
impl From<pkcs5::Error> for Error {
    fn from(err: pkcs5::Error) -> Error {
        Error::Pkcs5(err)
    }
}

type Result<T> = core::result::Result<T, Error>;

fn main() {
    let args = Pkcs12UtilArgs::parse();

    let mut logging_configured = false;

    if let Some(logging_config) = &args.logging_config {
        if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
            println!(
                "ERROR: failed to configure logging using {} with {:?}. Continuing without logging.",
                logging_config, e
            );
        } else {
            logging_configured = true;
        }
    }

    if !logging_configured {
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{m}{n}")))
            .build();
        match Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        {
            Ok(config) => {
                let handle = log4rs::init_config(config);
                if let Err(e) = handle {
                    println!(
                        "ERROR: failed to configure logging for stdout with {:?}. Continuing without logging.",
                        e
                    );
                }
            }
            Err(e) => {
                println!("ERROR: failed to prepare default logging configuration with {:?}. Continuing without logging", e);
            }
        }
    }

    let output_folder = match &args.output_folder {
        Some(of) => {
            if of.exists() {
                of.clone()
            } else {
                error!("Specified output_folder does not exist. Using current directory.");
                PathBuf::from(".")
            }
        }
        None => PathBuf::from("."),
    };

    if args.pkcs12.is_none() && args.cert.is_none() && args.key.is_none() {
        println!("ERROR: Either pkcs12 or cert and key must be specified");
        return;
    }

    let password = if let Some(password) = args.password {
        password
    } else {
        // todo! prompt
        String::from("")
    };

    if args.pkcs12.is_some() {
        // Parsing
        let base_file_name = get_base_file_name(&args.pkcs12);

        let pfx_bytes = match get_buffer_from_file_arg(&args.pkcs12) {
            Ok(pfx_bytes) => pfx_bytes,
            Err(e) => {
                println!("ERROR: failed to read PKCS #12 file: {e:?}");
                return;
            }
        };
        let pfx = match Pfx::from_der(&pfx_bytes) {
            Ok(pfx) => pfx,
            Err(e) => {
                println!("ERROR: failed to parse PKCS #12 file: {e:?}");
                return;
            }
        };

        if ID_DATA != pfx.auth_safe.content_type {
            println!("ERROR: PKCS #12 file contained unexpected content");
            return;
        }

        let auth_safes = match get_auth_safes(&pfx.auth_safe.content) {
            Ok(auth_safes) => auth_safes,
            Err(e) => {
                println!("ERROR: failed to read AuthenticatedSafes: {e:?}");
                return;
            }
        };

        for auth_safe in auth_safes {
            if ID_ENCRYPTED_DATA == auth_safe.content_type {
                // certificate
                match get_cert(&auth_safe.content, &password) {
                    Ok(cert) => {
                        let mut ed_file =
                            match File::create(output_folder.join(format!("{base_file_name}.der")))
                            {
                                Ok(f) => f,
                                Err(e) => {
                                    println!("ERROR: failed to create output file: {e:?}");
                                    return;
                                }
                            };
                        let _ = ed_file.write_all(&cert);
                    }
                    Err(e) => {
                        println!("ERROR: failed to parse EncryptedData and generate decryption scheme: {e:?}");
                        return;
                    }
                };
            } else if ID_DATA == auth_safe.content_type {
                // key
                match get_key(&auth_safe.content, &password) {
                    Ok(key) => {
                        let mut ed_file =
                            match File::create(output_folder.join(format!("{base_file_name}.key")))
                            {
                                Ok(f) => f,
                                Err(e) => {
                                    println!("ERROR: failed to create output file: {e:?}");
                                    return;
                                }
                            };
                        let _ = ed_file.write_all(&key);
                    }
                    Err(e) => {
                        println!("ERROR: failed to parse EncryptedData and generate decryption scheme: {e:?}");
                        return;
                    }
                };
            } else {
                println!("ERROR: unexpected content type");
            }
        }
    } else {
        // Generation
        if args.cert.is_none() || args.key.is_none() {
            println!("ERROR: Both cert and key must be specified to generate a PKCS #12 object");
            return;
        }
        let key = match get_buffer_from_file_arg(&args.key) {
            Ok(private_key_bytes) => private_key_bytes,
            Err(e) => {
                println!("ee_key_file must be provided and exist: {e:?}");
                return;
            }
        };
        let cert = match get_cert_from_file_arg(&args.cert) {
            Ok(cert) => cert,
            Err(e) => {
                println!("ERROR: failed to read certificate file: {e:?}");
                return;
            }
        };

        let enc = args.enc.get_enc_alg();
        let kdf = args.kdf.get_prf();
        let mac = args.mac.get_mac_alg();

        let (key_attrs, cert_attrs) = if let Some(id) = args.id {
            let mut cert_attrs = SetOfVec::new();
            if let Err(e) = add_key_id_attr(&mut cert_attrs, id.as_bytes()) {
                println!("Failed to add key identifier to attribute set for certificate: {e:?}. Ignoring and continuing...");
            }

            let mut key_attrs = SetOfVec::new();
            if let Err(e) = add_key_id_attr(&mut key_attrs, id.as_bytes()) {
                println!("Failed to add key identifier to attribute set for key: {e:?}. Ignoring and continuing...");
            }

            (Some(key_attrs), Some(cert_attrs))
        } else {
            (None, None)
        };

        let output_file_name = if let Some(filename) = args.generated_filename {
            filename
        } else {
            String::from("pkcs12_util.p12")
        };

        let der_pfx = match Pkcs12Builder::new()
            .cert_enc_algorithm(Some(enc.clone()))
            .key_enc_algorithm(Some(enc))
            .cert_kdf_algorithm(Some(kdf))
            .key_kdf_algorithm(Some(kdf))
            .mac_data_builder(Some(MacDataBuilder::new(mac)))
            .key_attributes(key_attrs)
            .cert_attributes(cert_attrs)
            .build_with_rng(cert.clone(), &key, &password, &mut OsRng)
        {
            Ok(der_pfx) => der_pfx,
            Err(e) => {
                println!("ERROR: failed to generate PKCS #12: {e:?}");
                return;
            }
        };
        if let Err(e) = write_file(&output_folder.join(&output_file_name), &der_pfx) {
            println!("ERROR: {e:?}");
            return;
        }
        println!("PKCS #12 object written to: {output_file_name}");
    }
}
