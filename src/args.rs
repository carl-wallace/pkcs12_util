use crate::pkcs12_builder::{EncryptionAlgorithm, MacAlgorithm};
use clap::Parser;
use core::fmt;
use pkcs5::pbes2::Pbkdf2Prf;
use pkcs5::pbes2::Pbkdf2Prf::{HmacWithSha256, HmacWithSha384, HmacWithSha512};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize, Debug, Default, clap::ValueEnum)]
pub enum MacAlgorithms {
    #[default]
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl MacAlgorithms {
    pub fn get_mac_alg(&self) -> MacAlgorithm {
        match self {
            MacAlgorithms::HmacSha256 => MacAlgorithm::HmacSha256,
            MacAlgorithms::HmacSha384 => MacAlgorithm::HmacSha384,
            MacAlgorithms::HmacSha512 => MacAlgorithm::HmacSha512,
        }
    }
}

impl fmt::Display for MacAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacAlgorithms::HmacSha256 => write!(f, "hmac-sha256"),
            MacAlgorithms::HmacSha384 => write!(f, "hmac-sha384"),
            MacAlgorithms::HmacSha512 => write!(f, "hmac-sha512"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, clap::ValueEnum)]
pub enum KdfAlgorithms {
    #[default]
    Pbkdf2WithHmacWithSha256,
    Pbkdf2WithHmacWithSha384,
    Pbkdf2WithHmacWithSha512,
}

impl KdfAlgorithms {
    pub fn get_prf(&self) -> Pbkdf2Prf {
        match self {
            KdfAlgorithms::Pbkdf2WithHmacWithSha256 => HmacWithSha256,
            KdfAlgorithms::Pbkdf2WithHmacWithSha384 => HmacWithSha384,
            KdfAlgorithms::Pbkdf2WithHmacWithSha512 => HmacWithSha512,
        }
    }
}

impl fmt::Display for KdfAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfAlgorithms::Pbkdf2WithHmacWithSha256 => write!(f, "pbkdf2-with-hmac-with-sha256"),
            KdfAlgorithms::Pbkdf2WithHmacWithSha384 => write!(f, "pbkdf2-with-hmac-with-sha384"),
            KdfAlgorithms::Pbkdf2WithHmacWithSha512 => write!(f, "pbkdf2-with-hmac-with-sha512"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, clap::ValueEnum)]
#[allow(clippy::enum_variant_names)]
pub enum EncryptionAlgorithms {
    #[default]
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
}

impl EncryptionAlgorithms {
    pub fn get_enc_alg(&self) -> EncryptionAlgorithm {
        match self {
            EncryptionAlgorithms::Aes128Cbc => EncryptionAlgorithm::Aes128Cbc,
            EncryptionAlgorithms::Aes192Cbc => EncryptionAlgorithm::Aes192Cbc,
            EncryptionAlgorithms::Aes256Cbc => EncryptionAlgorithm::Aes256Cbc,
        }
    }
}

impl fmt::Display for EncryptionAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionAlgorithms::Aes128Cbc => write!(f, "aes128-cbc"),
            EncryptionAlgorithms::Aes192Cbc => write!(f, "aes192-cbc"),
            EncryptionAlgorithms::Aes256Cbc => write!(f, "aes256-cbc"),
        }
    }
}

#[allow(rustdoc::bare_urls)]
#[derive(Parser, Debug, Default)]
#[command(
    author,
    version,
    about = "",
    long_about = "",
    arg_required_else_help = true
)]
pub struct Pkcs12UtilArgs {
    /// Folder to which generated or recovered artifacts should be written
    #[clap(long, short, help_heading = "Common")]
    pub output_folder: Option<PathBuf>,
    /// Full path and filename of YAML-formatted configuration file for log4rs logging mechanism.
    /// See https://docs.rs/log4rs/latest/log4rs/ for details.
    #[clap(short, long, help_heading = "Common")]
    pub logging_config: Option<String>,
    /// Certificate to include in PKCS #12 object
    #[clap(long, short, help_heading = "Generator")]
    pub cert: Option<PathBuf>,
    /// Key to include in PKCS #12 object
    #[clap(long, short, help_heading = "Generator")]
    pub key: Option<PathBuf>,
    /// Mac algorithm to use
    #[clap(long, default_value_t, help_heading = "Generator")]
    pub mac: MacAlgorithms,
    /// Kdf algorithm to use
    #[clap(long, default_value_t, help_heading = "Generator")]
    pub kdf: KdfAlgorithms,
    /// Encryption algorithm to use
    #[clap(long, default_value_t, help_heading = "Generator")]
    pub enc: EncryptionAlgorithms,
    /// Key ID
    #[clap(long, help_heading = "Generator")]
    pub id: Option<String>,
    /// Password
    #[clap(long, help_heading = "Generator")]
    pub password: Option<String>,
    /// Output file name
    #[clap(long, help_heading = "Generator")]
    pub generated_filename: Option<String>,
    /// PKCS #12 object to parse
    #[clap(long, short, help_heading = "Parser")]
    pub pkcs12: Option<PathBuf>,
}
