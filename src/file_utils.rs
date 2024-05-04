//! Utility functions for interacting with ASN.1 structures associated with PKCS #12 objects

use std::io::Write;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use der::Decode;
use x509_cert::Certificate;

use crate::{Error, Result};

/// Get contents of given file as a vector of bytes
pub(crate) fn get_file_as_byte_vec(filename: &Path) -> Result<Vec<u8>> {
    match File::open(filename) {
        Ok(mut f) => match std::fs::metadata(filename) {
            Ok(metadata) => {
                let mut buffer = vec![0; metadata.len() as usize];
                match f.read_exact(&mut buffer) {
                    Ok(_) => Ok(buffer),
                    Err(e) => Err(Error::Pkcs12Util(format!(
                        "Failed to read {filename:?}: {e:?}"
                    ))),
                }
            }
            Err(e) => Err(Error::Pkcs12Util(format!(
                "Failed to read metadata for {filename:?}: {e:?}"
            ))),
        },
        Err(e) => Err(Error::Pkcs12Util(format!(
            "Failed to open {filename:?}: {e:?}"
        ))),
    }
}

/// Read buffer from file identified in file_name param, if present
pub(crate) fn get_buffer_from_file_arg(file_name: &Option<PathBuf>) -> Result<Vec<u8>> {
    match file_name {
        Some(file_name) => {
            if !file_name.exists() {
                Err(Error::Pkcs12Util(format!(
                    "{} does not exist",
                    file_name.to_str().unwrap_or_default()
                )))
            } else {
                get_file_as_byte_vec(file_name)
            }
        }
        None => Err(Error::Pkcs12Util(String::from("File not specified"))),
    }
}

/// Read certificate from file identified in file_name param, if present
pub(crate) fn get_cert_from_file_arg(file_name: &Option<PathBuf>) -> Result<Certificate> {
    let der = get_buffer_from_file_arg(file_name)?;
    Ok(Certificate::from_der(&der)?)
}

pub(crate) fn write_file(filename: &PathBuf, content: &[u8]) -> Result<()> {
    let mut ed_file = match File::create(filename) {
        Ok(f) => f,
        Err(e) => {
            return Err(Error::Pkcs12Util(format!(
                "Failed to create output file {filename:?}: {e:?}"
            )));
        }
    };
    if let Err(e) = ed_file.write_all(content) {
        return Err(Error::Pkcs12Util(format!(
            "Failed to write data to output file {filename:?}: {e:?}"
        )));
    }
    Ok(())
}

pub(crate) fn get_base_file_name(arg: &Option<PathBuf>) -> String {
    if let Some(pb) = arg {
        if let Some(f) = pb.file_name() {
            if let Some(s) = f.to_str() {
                return s.to_string();
            }
        }
    }
    String::from("pkcs12_util")
}
